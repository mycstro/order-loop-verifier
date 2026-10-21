"""Proves the Stripe-shaped path: real header format, replay defence, reversal.

Runs entirely offline. No Stripe account, network or API key is involved, so
every assertion here is reproducible before a live key exists.
"""

import json
import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from payment_webhook import PaymentLedger, make_server
from stripe_adapter import (
    StripeSignatureError,
    expected_digest,
    loads_event,
    map_stripe_event,
    verify_stripe_signature,
)

SECRET = "whsec_unit_test_secret"


def stripe_header(body, secret=SECRET, timestamp=None):
    """Build a header exactly as Stripe does: t=<ts>,v1=<hmac>"""
    ts = int(time.time()) if timestamp is None else timestamp
    return "t=%d,v1=%s" % (ts, expected_digest(secret, ts, body))


def pi_event(event_id="evt_1", pi="pi_ABC123", event_type="payment_intent.succeeded"):
    return {
        "id": event_id,
        "object": "event",
        "type": event_type,
        "data": {"object": {"id": pi, "object": "payment_intent", "amount": 4200}},
    }


class SignatureTests(unittest.TestCase):
    def test_real_stripe_header_verifies(self):
        body = json.dumps(pi_event()).encode()
        header = stripe_header(body)
        ts = verify_stripe_signature(header, body, SECRET)
        self.assertIsInstance(ts, int)

    def test_tampered_body_is_rejected(self):
        body = json.dumps(pi_event()).encode()
        header = stripe_header(body)
        tampered = body.replace(b"pi_ABC123", b"pi_ATTACKER")
        with self.assertRaises(StripeSignatureError):
            verify_stripe_signature(header, tampered, SECRET)

    def test_wrong_secret_is_rejected(self):
        body = json.dumps(pi_event()).encode()
        header = stripe_header(body, secret="whsec_wrong")
        with self.assertRaises(StripeSignatureError):
            verify_stripe_signature(header, body, SECRET)

    def test_missing_header_is_rejected(self):
        with self.assertRaises(StripeSignatureError):
            verify_stripe_signature("", b"{}", SECRET)

    def test_header_without_v1_is_rejected(self):
        with self.assertRaises(StripeSignatureError):
            verify_stripe_signature("t=%d" % int(time.time()), b"{}", SECRET)

    def test_replayed_old_delivery_is_rejected(self):
        body = json.dumps(pi_event()).encode()
        stale = int(time.time()) - 3600
        header = stripe_header(body, timestamp=stale)
        with self.assertRaises(StripeSignatureError):
            verify_stripe_signature(header, body, SECRET)

    def test_multiple_v1_accepts_any_match(self):
        """Secrets rotate; Stripe sends one v1 per active secret."""
        body = json.dumps(pi_event()).encode()
        ts = int(time.time())
        good = expected_digest(SECRET, ts, body)
        header = "t=%d,v1=%s,v1=%s" % (ts, "0" * 64, good)
        self.assertEqual(verify_stripe_signature(header, body, SECRET), ts)

    def test_tolerance_boundary(self):
        body = b'{"id":"evt_x","type":"payment_intent.succeeded","data":{"object":{"id":"pi_1"}}}'
        now = int(time.time())
        header = stripe_header(body, timestamp=now)
        self.assertEqual(verify_stripe_signature(header, body, SECRET, tolerance=300, now=now + 300), now)
        with self.assertRaises(StripeSignatureError):
            verify_stripe_signature(header, body, SECRET, tolerance=300, now=now + 301)


class MappingTests(unittest.TestCase):
    def test_payment_intent_maps_to_paid(self):
        mapped = map_stripe_event(pi_event())
        self.assertEqual(mapped["type"], "payment.succeeded")
        self.assertEqual(mapped["data"]["order_id"], "pi_ABC123")

    def test_checkout_session_uses_payment_intent_not_session_id(self):
        event = {"id": "evt_cs", "type": "checkout.session.completed",
                 "data": {"object": {"id": "cs_test_1", "object": "checkout.session",
                                     "payment_intent": "pi_XYZ"}}}
        self.assertEqual(map_stripe_event(event)["data"]["order_id"], "pi_XYZ")

    def test_refund_maps_to_reversal(self):
        self.assertEqual(map_stripe_event(pi_event(event_type="charge.refunded"))["type"],
                         "payment.reversed")

    def test_unrelated_event_is_ignored(self):
        self.assertIsNone(map_stripe_event(pi_event(event_type="customer.created")))

    def test_event_without_ids_is_ignored(self):
        self.assertIsNone(map_stripe_event({"type": "payment_intent.succeeded", "data": {}}))
        self.assertIsNone(map_stripe_event({"id": "evt_1", "type": "payment_intent.succeeded", "data": {}}))


class EndToEndTests(unittest.TestCase):
    """Drives the real HTTP server with real Stripe-shaped deliveries."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp.name) / "events.sqlite3"
        self.ledger = PaymentLedger(self.db_path)
        self.server = make_server("127.0.0.1", 0, self.ledger, SECRET)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = "http://127.0.0.1:%s/webhook" % self.server.server_port

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def deliver(self, stripe_event, header=None, raw=None):
        body = raw if raw is not None else json.dumps(stripe_event, separators=(",", ":")).encode()
        headers = {"Stripe-Signature": header if header is not None else stripe_header(body),
                   "Content-Type": "application/json"}
        request = Request(self.url, data=body, headers=headers, method="POST")
        try:
            response = urlopen(request, timeout=5)
        except HTTPError as error:
            response = error
        with response:
            return response.code, json.loads(response.read())

    def counts(self):
        with sqlite3.connect(self.db_path) as db:
            events = db.execute("SELECT count(*) FROM payment_events").fetchone()[0]
            live = db.execute("SELECT count(*) FROM fulfillments WHERE revoked_at IS NULL").fetchone()[0]
            total = db.execute("SELECT count(*) FROM fulfillments").fetchone()[0]
        return events, live, total

    def test_one_payment_fulfills_exactly_one_order(self):
        code, body = self.deliver(pi_event())
        self.assertEqual((code, body), (200, {"status": "fulfilled"}))
        self.assertEqual(self.counts(), (1, 1, 1))

    def test_duplicate_deliveries_of_same_event_fulfill_once(self):
        event = pi_event()
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _n: self.deliver(event), range(6)))
        self.assertEqual([c for c, _b in results], [200] * 6)
        self.assertEqual(sorted(b["status"] for _c, b in results),
                         ["duplicate"] * 5 + ["fulfilled"])
        self.assertEqual(self.counts(), (1, 1, 1))

    def test_two_distinct_events_same_payment_intent_fulfill_once(self):
        """payment_intent.succeeded then checkout.session.completed, same payment."""
        first = pi_event(event_id="evt_A")
        second = {"id": "evt_B", "type": "checkout.session.completed",
                  "data": {"object": {"id": "cs_1", "payment_intent": "pi_ABC123"}}}
        self.assertEqual(self.deliver(first)[1], {"status": "fulfilled"})
        # second event is recorded but must NOT ship a second time
        self.assertEqual(self.deliver(second)[1], {"status": "already_fulfilled"})
        # two distinct payment events recorded in the audit log, but exactly
        # ONE fulfillment row for the order (fulfillments is keyed by order)
        self.assertEqual(self.counts(), (2, 1, 1))

    def test_forged_signature_writes_nothing(self):
        body = json.dumps(pi_event()).encode()
        code, payload = self.deliver(None, header="t=%d,v1=%s" % (int(time.time()), "a" * 64), raw=body)
        self.assertEqual((code, payload), (401, {"error": "invalid_signature"}))
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_replayed_delivery_writes_nothing_new(self):
        body = json.dumps(pi_event()).encode()
        old = int(time.time()) - 7200
        code, payload = self.deliver(None, header=stripe_header(body, timestamp=old), raw=body)
        self.assertEqual((code, payload), (401, {"error": "invalid_signature"}))
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_refund_retracts_fulfillment_but_keeps_audit_trail(self):
        self.assertEqual(self.deliver(pi_event())[1], {"status": "fulfilled"})
        refund = {"id": "evt_refund", "type": "charge.refunded",
                  "data": {"object": {"id": "ch_1", "payment_intent": "pi_ABC123"}}}
        self.assertEqual(self.deliver(refund)[1], {"status": "revoked"})
        # event log keeps both, fulfillment row survives but is revoked
        self.assertEqual(self.counts(), (2, 0, 1))

    def test_refund_before_payment_reports_unknown_order(self):
        refund = {"id": "evt_r2", "type": "payment_intent.canceled",
                  "data": {"object": {"id": "pi_NEVER"}}}
        self.assertEqual(self.deliver(refund)[1], {"status": "unknown_order"})

    def test_unknown_event_type_is_acknowledged_not_fulfilled(self):
        code, payload = self.deliver(pi_event(event_type="customer.created"))
        self.assertEqual((code, payload), (202, {"status": "ignored"}))
        self.assertEqual(self.counts(), (0, 0, 0))


if __name__ == "__main__":
    unittest.main()
