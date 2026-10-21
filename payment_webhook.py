#!/usr/bin/env python3
"""Loopback webhook receiver with an idempotent SQLite fulfillment ledger."""

import argparse
import hashlib
import hmac
import json
import os
import sqlite3
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from stripe_adapter import (
    StripeSignatureError,
    map_stripe_event,
    verify_stripe_signature,
)

SUCCESS_EVENT = "payment.succeeded"
REVERSAL_EVENT = "payment.reversed"
MAX_BODY_BYTES = 1024 * 1024


class EventConflict(Exception):
    """An event ID was reused for a different payment event."""


def signature_for(body, secret):
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return "sha256=" + digest


class PaymentLedger:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = self._connect()
        try:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS payment_events (
                    event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL,
                    order_id TEXT NOT NULL, payload TEXT NOT NULL,
                    received_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS fulfillments (
                    order_id TEXT PRIMARY KEY, event_id TEXT NOT NULL,
                    fulfilled_at TEXT NOT NULL, revoked_at TEXT
                );
            """)
        finally:
            db.close()

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        return db

    def accept(self, event):
        event_id, event_type = event["id"], event["type"]
        order_id = event["data"]["order_id"]
        payload = json.dumps(event, sort_keys=True, separators=(",", ":"))
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute(
                "SELECT event_type, order_id FROM payment_events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
            if old:
                if old["event_type"] != event_type or old["order_id"] != order_id:
                    raise EventConflict
                db.commit()
                return "duplicate"
            now = datetime.now(timezone.utc).isoformat()
            db.execute("INSERT INTO payment_events VALUES (?, ?, ?, ?, ?)",
                       (event_id, event_type, order_id, payload, now))
            # One order, one fulfillment. A second distinct payment event for a
            # payment we already fulfilled (e.g. checkout.session.completed
            # arriving after payment_intent.succeeded) must NOT ship twice.
            # An order whose fulfillment was revoked can be fulfilled again
            # (a retry after a refund), which is why this is not a plain skip.
            existing = db.execute(
                "SELECT event_id, revoked_at FROM fulfillments WHERE order_id = ?",
                (order_id,),
            ).fetchone()
            if existing and existing["revoked_at"] is None:
                db.commit()
                return "already_fulfilled"
            db.execute(
                "INSERT INTO fulfillments (order_id, event_id, fulfilled_at, revoked_at) "
                "VALUES (?, ?, ?, NULL) "
                "ON CONFLICT(order_id) DO UPDATE SET event_id=excluded.event_id, "
                "fulfilled_at=excluded.fulfilled_at, revoked_at=NULL",
                (order_id, event_id, now),
            )
            db.commit()
            return "fulfilled"
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def revoke(self, event):
        """Retract fulfillment for an order after a refund/cancel/dispute.

        Returns "revoked" when at least one live fulfillment was retracted,
        "unknown_order" when there was nothing to retract (reversal arriving
        before its payment, or for an order this ledger never saw).
        """
        event_id, event_type = event["id"], event["type"]
        order_id = event["data"]["order_id"]
        payload = json.dumps(event, sort_keys=True, separators=(",", ":"))
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute(
                "SELECT event_type, order_id FROM payment_events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
            if old:
                if old["event_type"] != event_type or old["order_id"] != order_id:
                    raise EventConflict
                db.commit()
                return "duplicate"
            now = datetime.now(timezone.utc).isoformat()
            db.execute("INSERT INTO payment_events VALUES (?, ?, ?, ?, ?)",
                       (event_id, event_type, order_id, payload, now))
            cursor = db.execute(
                "UPDATE fulfillments SET revoked_at = ? "
                "WHERE order_id = ? AND revoked_at IS NULL",
                (now, order_id),
            )
            changed = cursor.rowcount
            db.commit()
            return "revoked" if changed else "unknown_order"
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()


class WebhookHandler(BaseHTTPRequestHandler):
    ledger = None
    secret = ""
    # "stripe" verifies a real Stripe-Signature (t=..,v1=..) header and maps
    # Stripe event types. "generic" is the original simple HMAC scheme.
    signature_scheme = "stripe"

    def do_POST(self):
        if urlsplit(self.path).path != "/webhook":
            return self.reply(404, {"error": "not_found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self.reply(400, {"error": "invalid_content_length"})
        if length <= 0:
            return self.reply(400, {"error": "empty_body"})
        if length > MAX_BODY_BYTES:
            return self.reply(413, {"error": "body_too_large"})
        body = self.rfile.read(length)
        if self.signature_scheme == "stripe":
            try:
                verify_stripe_signature(
                    self.headers.get("Stripe-Signature", ""), body, self.secret
                )
            except StripeSignatureError:
                return self.reply(401, {"error": "invalid_signature"})
        else:
            expected = signature_for(body, self.secret)
            supplied = self.headers.get("X-Webhook-Signature", "")
            if not hmac.compare_digest(supplied, expected):
                return self.reply(401, {"error": "invalid_signature"})
        try:
            raw_event = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self.reply(400, {"error": "invalid_json"})
        if not isinstance(raw_event, dict) or not isinstance(raw_event.get("id"), str) or not raw_event["id"].strip():
            return self.reply(400, {"error": "invalid_event"})
        if self.signature_scheme == "stripe":
            event = map_stripe_event(raw_event)
            if event is None:
                # Signed, real Stripe delivery, but not about money moving.
                return self.reply(202, {"status": "ignored"})
        else:
            event = raw_event
        event_type = event.get("type")
        if event_type not in (SUCCESS_EVENT, REVERSAL_EVENT):
            return self.reply(202, {"status": "ignored"})
        data = event.get("data")
        if not isinstance(data, dict) or not isinstance(data.get("order_id"), str) or not data["order_id"].strip():
            return self.reply(400, {"error": "invalid_order"})
        try:
            if event_type == SUCCESS_EVENT:
                status = self.ledger.accept(event)
            else:
                status = self.ledger.revoke(event)
        except EventConflict:
            return self.reply(409, {"error": "event_id_conflict"})
        except sqlite3.Error:
            return self.reply(500, {"error": "ledger_error"})
        return self.reply(200, {"status": status})

    def reply(self, status, body):
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format, *args):
        return


def make_server(host, port, ledger, secret, signature_scheme="stripe"):
    handler = type("ConfiguredWebhookHandler", (WebhookHandler,),
                   {"ledger": ledger, "secret": secret,
                    "signature_scheme": signature_scheme})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="payment-events.sqlite3")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--scheme", choices=("stripe", "generic"), default="stripe",
                        help="stripe = verify Stripe-Signature (t=..,v1=..); "
                             "generic = verify X-Webhook-Signature")
    args = parser.parse_args()
    secret = os.environ.get("PAYMENT_WEBHOOK_SECRET", "")
    if not secret:
        parser.error("set PAYMENT_WEBHOOK_SECRET to a non-empty development secret")
    server = make_server(args.host, args.port, PaymentLedger(args.db), secret,
                         signature_scheme=args.scheme)
    print("Payment webhook listening on http://%s:%s/webhook" % (args.host, args.port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
