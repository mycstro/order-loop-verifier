"""Stripe-shaped signature verification and event mapping.

Stripe signs webhook deliveries with a ``Stripe-Signature`` header of the form::

    t=<unix_ts>,v1=<hex hmac>,v1=<another hex hmac>

Each v1 digest is HMAC-SHA256(secret, "<t>.<raw body>"). Multiple v1 values
appear during a secret rollover, so a delivery is valid if ANY v1 matches. The
timestamp must be inside a tolerance window (Stripe's default is 300 seconds)
to stop replay of an old captured delivery.

This module is deliberately dependency-free and offline: it needs no Stripe
account, no network and no API key, so the loop can be proven in test mode
before a live key is ever connected.
"""

import hashlib
import hmac
import json
import time

DEFAULT_TOLERANCE_SECONDS = 300

# Stripe event types that mean "money actually moved for this order".
PAID_EVENT_TYPES = frozenset({
    "payment_intent.succeeded",
    "checkout.session.completed",
    "charge.succeeded",
})

# Stripe event types that must RETRACT a fulfillment already written.
REVERSAL_EVENT_TYPES = frozenset({
    "payment_intent.canceled",
    "charge.refunded",
    "charge.dispute.created",
    "checkout.session.expired",
})


class StripeSignatureError(Exception):
    """The delivery is not provably from Stripe. Never fulfill on this."""


def _parse_header(header):
    """Return (timestamp_int, [v1 digests]). Raises StripeSignatureError."""
    if not header or not isinstance(header, str):
        raise StripeSignatureError("missing Stripe-Signature header")
    timestamp = None
    digests = []
    for part in header.split(","):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, _, value = part.partition("=")
        key, value = key.strip(), value.strip()
        if key == "t":
            try:
                timestamp = int(value)
            except ValueError:
                raise StripeSignatureError("non-integer timestamp")
        elif key == "v1" and value:
            digests.append(value)
    if timestamp is None:
        raise StripeSignatureError("no timestamp in header")
    if not digests:
        raise StripeSignatureError("no v1 signature in header")
    return timestamp, digests


def expected_digest(secret, timestamp, body):
    """HMAC-SHA256 over b"<timestamp>.<raw body>", lowercase hex."""
    if isinstance(body, str):
        body = body.encode("utf-8")
    payload = str(timestamp).encode("utf-8") + b"." + body
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def verify_stripe_signature(header, body, secret, tolerance=DEFAULT_TOLERANCE_SECONDS, now=None):
    """Raise StripeSignatureError unless this delivery is authentic and fresh.

    Returns the timestamp that was verified so callers can log it.
    """
    if not secret:
        raise StripeSignatureError("no signing secret configured")
    timestamp, digests = _parse_header(header)
    current = int(time.time()) if now is None else int(now)
    if tolerance is not None and abs(current - timestamp) > tolerance:
        raise StripeSignatureError("timestamp outside tolerance")

    expected = expected_digest(secret, timestamp, body)
    matched = False
    for digest in digests:
        if hmac.compare_digest(digest, expected):
            matched = True
    if not matched:
        raise StripeSignatureError("no matching v1 signature")
    return timestamp


def order_key_for(stripe_event):
    """The stable key one order is fulfilled against, derived from Stripe data.

    PaymentIntent id is preferred because it is constant across every event in
    one payment's life; a Checkout Session id changes per attempt.
    """
    obj = (stripe_event.get("data") or {}).get("object") or {}
    for field in ("payment_intent", "id"):
        value = obj.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def map_stripe_event(stripe_event):
    """Convert a Stripe event into this project's canonical event shape.

    Canonical shape: ``{"id": <stripe event id>, "type": "payment.succeeded" |
    "payment.reversed", "data": {"order_id": <payment intent id>}}``

    Returns None when the event is not about money moving (Stripe sends dozens
    of other types; they are acknowledged and ignored, not errors).
    """
    if not isinstance(stripe_event, dict):
        return None
    event_id = stripe_event.get("id")
    event_type = stripe_event.get("type")
    if not isinstance(event_id, str) or not event_id.strip():
        return None
    if not isinstance(event_type, str):
        return None

    if event_type in PAID_EVENT_TYPES:
        canonical_type = "payment.succeeded"
    elif event_type in REVERSAL_EVENT_TYPES:
        canonical_type = "payment.reversed"
    else:
        return None

    order_id = order_key_for(stripe_event)
    if not order_id:
        return None
    return {
        "id": event_id.strip(),
        "type": canonical_type,
        "data": {"order_id": order_id, "stripe_type": event_type},
    }


def loads_event(body):
    """Parse a raw webhook body into a dict, or None if it is not a JSON object."""
    try:
        if isinstance(body, bytes):
            body = body.decode("utf-8")
        parsed = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None
