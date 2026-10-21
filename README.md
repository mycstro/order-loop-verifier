# Order loop verifier

A payment-to-fulfillment webhook ledger that **will not silently lose or duplicate an order**.

Standard library only. No dependencies, no Stripe account, no network needed to prove it works —
that is deliberate, so the loop is verified in test mode before a live key is ever connected.

## The failure this closes

Your store takes the payment and the order doesn't come out the other end — or it comes out twice.
The usual causes, all silent:

- two valid events for one payment (`payment_intent.succeeded` **and** `checkout.session.completed`)
  each look new, so the order ships twice
- a retried delivery is treated as a new payment
- a refund never pulls the order back, so it ships anyway
- a malformed or forged request gets fulfilled because the handler only checked it was a POST
- a fulfillment fails and nothing anywhere records that it was owed

## What this does

1. **Verifies a real `Stripe-Signature`** — `t=<unix_ts>,v1=<hex>[,v1=<hex>]`, digest =
   `HMAC-SHA256(secret, "<t>.<raw body>")`. Accepted if **any** `v1` matches (secret rollover), and
   rejected if the timestamp is outside a **300-second** tolerance (replay defence).
2. **Maps the event to an order action**, including the events that must **retract** a fulfillment
   already written (refund, dispute, cancellation, expired session).
3. **Writes exactly one durable receipt per payment, keyed by order** — repeat and concurrent
   deliveries never create a second one.
4. **Holds what it cannot deliver** instead of dropping it, so the failure is visible.

## Prove it

```sh
python3 -m unittest discover -v
```

**24 tests, all offline, no fixtures to download.** The names are the specification:

```
test_real_stripe_header_verifies              a genuine t=..,v1=.. header is accepted
test_tampered_body_is_rejected                a body edited after signing fails
test_wrong_secret_is_rejected
test_replayed_old_delivery_is_rejected        an old capture cannot be replayed
test_tolerance_boundary                       the 300s window edge
test_multiple_v1_accepts_any_match            secret rollover
test_missing_header_is_rejected
test_header_without_v1_is_rejected
test_two_distinct_events_same_payment_intent_fulfill_once   <- ships the order ONCE
test_duplicate_deliveries_of_same_event_fulfill_once
test_concurrent_duplicate_webhooks_fulfill_once
test_refund_retracts_fulfillment_but_keeps_audit_trail
test_refund_before_payment_reports_unknown_order
test_unknown_event_type_is_acknowledged_not_fulfilled
test_checkout_session_uses_payment_intent_not_session_id
test_event_without_ids_is_ignored
test_conflicting_order_for_same_event_id_is_rejected
test_unrelated_event_is_ignored
test_payment_intent_maps_to_paid
test_refund_maps_to_reversal
test_invalid_signature_does_not_write
test_forged_signature_writes_nothing
test_one_payment_fulfills_exactly_one_order
test_replayed_delivery_writes_nothing_new
```

## Run it

```sh
PAYMENT_WEBHOOK_SECRET=whsec_test python3 payment_webhook.py --db events.sqlite3
```

Listens on `127.0.0.1:8787`, `POST /webhook`.

The order key comes from `data.object.payment_intent`, falling back to `data.object.id`. The
PaymentIntent id is preferred because it is **constant across a payment's life**, while a Checkout
Session id changes per attempt — keying on the session id is how the double-ship bug gets in.

```json
{"id":"evt_123","type":"payment_intent.succeeded","data":{"object":{"id":"pi_123"}}}
```

Paid types: `payment_intent.succeeded`, `checkout.session.completed`, `charge.succeeded`.
Reversal types (these **revoke** a fulfillment): `payment_intent.canceled`, `charge.refunded`,
`charge.dispute.created`, `checkout.session.expired`.
Anything else is acknowledged and ignored — not an error.

`--scheme generic` switches to `X-Webhook-Signature: sha256=<hex>` over the raw body, for non-Stripe
providers (PayPal-style gateways).

## What this is not

- Fulfillment here is a **local SQLite receipt**, not a shipment. Wire the receipt to your provider
  (Printful, Printify, Shopify fulfillment API) for the real action.
- It binds to **loopback by default**. Public exposure, TLS and production secret management are out
  of scope for this package.
- It verifies signatures offline and does not call Stripe's API — right for auditing, a gap if you
  want to fetch the full event object server-side.

## Who this is for

Store operators already taking money whose fulfillment is manual, custom, or fragile — Shopify /
Etsy / POD stores wiring Printful, Printify or CJ Dropshipping to checkout, or anyone whose "order"
lives in a webhook they wrote themselves or had written cheaply.

Licence: MIT.
