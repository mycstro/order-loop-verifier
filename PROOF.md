# Proof — executed 2026-10-21 18:34 UTC

Not a description of what the code does. The actual captured output, against the code in this
repository, cloned fresh from GitHub.

## 1. A stranger can clone it and run it

```sh
git clone https://github.com/mycstro/order-loop-verifier.git
cd order-loop-verifier
python3 -m unittest discover
```

```
........................
----------------------------------------------------------------------
Ran 24 tests in 5.586s

OK
```

No dependency install, no API key, no network call inside any test.

## 2. Live HTTP round trip

Server: `PAYMENT_WEBHOOK_SECRET=whsec_demo_scan21 python3 payment_webhook.py --db /tmp/e2e.db --port 8901`
(). Every request below was signed exactly as Stripe signs a real delivery
(`t=<unix_ts>,v1=HMAC-SHA256(secret, "<t>.<raw body>")`).

```
-- 1st delivery:           (200, {'status': 'fulfilled'})
-- identical replay:       (200, {'status': 'duplicate'})
-- same order, NEW event:  (200, {'status': 'already_fulfilled'})
-- replayed 2h old:        (401, {'error': 'invalid_signature'})
-- forged signature:       (401, {'error': 'invalid_signature'})
-- refund:                 (200, {'status': 'revoked'})
```

**Three differently-shaped deliveries for one payment produced one fulfillment row.**

```sql
payment_events:      3
live fulfillments:   0
fulfillment rows:    1

[{'order_id': 'pi_LIVE001',
  'event_id':  'evt_1',
  'fulfilled_at': '2026-10-21T18:34:22.666075+00:00',
  'revoked_at':   '2026-10-21T18:34:22.675638+00:00'}]
```

Three events recorded in the audit log, one order fulfilled, then revoked by the refund — the row
survives with `revoked_at` set, so the history of what happened is never destroyed.

## 3. It shut down cleanly

```
port 8901 after shutdown: REFUSED
```

## What this proof covers, and what it does not

**Covers:** signature verification against the real Stripe header format (including the 300-second
replay window and secret rollover), idempotency under concurrent duplicate delivery, the
double-ship bug where two distinct valid events belong to one payment, reversal on refund, and the
rejection of forged and stale deliveries without writing anything.

**Does not cover:** a live Stripe account. Signature verification is offline and complete — it will
correctly accept or reject a real delivery — but no request in this repo was ever made to Stripe's
API, and no real event payload from a live account appears above. The synthetic events use Stripe's
documented event shape (`data.object.payment_intent`, falling back to `data.object.id`), which is
what the mapper keys on.

**Also not covered:** fulfillment itself. The ledger writes a SQLite receipt; wiring that receipt to
Printful, Printify or the Shopify fulfillment API is the integration step, and it is the part that
differs per store.
