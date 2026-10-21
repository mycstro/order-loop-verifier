import json
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from payment_webhook import PaymentLedger, make_server, signature_for


class WebhookTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp.name) / "events.sqlite3"
        self.ledger = PaymentLedger(self.db_path)
        self.secret = "unit-test-secret"
        # These tests exercise the original generic HMAC scheme and its exact
        # response bodies; the Stripe header path has its own suite.
        self.server = make_server("127.0.0.1", 0, self.ledger, self.secret,
                                  signature_scheme="generic")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = "http://127.0.0.1:%s/webhook" % self.server.server_port

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def post(self, event, signature=None):
        body = json.dumps(event, separators=(",", ":")).encode("utf-8")
        headers = {"X-Webhook-Signature": signature or signature_for(body, self.secret)}
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
            fulfilled = db.execute("SELECT count(*) FROM fulfillments").fetchone()[0]
        return events, fulfilled

    def test_concurrent_duplicate_webhooks_fulfill_once(self):
        event = {"id": "evt_1", "type": "payment.succeeded",
                 "data": {"order_id": "order_1"}}
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _n: self.post(event), range(8)))
        self.assertEqual([status for status, _body in results], [200] * 8)
        self.assertEqual(sorted(body["status"] for _status, body in results),
                         ["duplicate"] * 7 + ["fulfilled"])
        self.assertEqual(self.counts(), (1, 1))

    def test_invalid_signature_does_not_write(self):
        event = {"id": "evt_bad", "type": "payment.succeeded",
                 "data": {"order_id": "order_1"}}
        self.assertEqual(self.post(event, "sha256=bad"),
                         (401, {"error": "invalid_signature"}))
        self.assertEqual(self.counts(), (0, 0))

    def test_conflicting_order_for_same_event_id_is_rejected(self):
        first = {"id": "evt_same", "type": "payment.succeeded",
                 "data": {"order_id": "order_1"}}
        other = {"id": "evt_same", "type": "payment.succeeded",
                 "data": {"order_id": "order_2"}}
        self.assertEqual(self.post(first), (200, {"status": "fulfilled"}))
        self.assertEqual(self.post(other), (409, {"error": "event_id_conflict"}))
        self.assertEqual(self.counts(), (1, 1))


if __name__ == "__main__":
    unittest.main()
