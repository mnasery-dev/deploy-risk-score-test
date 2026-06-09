"""Sample application for testing deploy risk scoring."""

import os
import time
import logging

logger = logging.getLogger(__name__)

# Payment configuration
STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY", "")
PAYMENT_TIMEOUT_SEC = 30
MAX_RETRIES = 3


def checkout(cart_items, user_id):
    """Process a checkout with payment."""
    total = sum(item["price"] * item["quantity"] for item in cart_items)
    discount = calculate_loyalty_discount(user_id, total)
    final_total = total - discount

    payment_result = process_payment(user_id, final_total, method="stripe")
    if payment_result["status"] != "success":
        logger.error(f"Payment failed for user {user_id}: {payment_result['error']}")
        return {"user_id": user_id, "total": final_total, "status": "payment_failed"}

    order_id = create_order(user_id, cart_items, final_total, payment_result["charge_id"])
    notify_fulfillment(order_id)
    return {"user_id": user_id, "total": final_total, "status": "completed", "order_id": order_id}


def apply_discount(total, discount_code):
    """Apply a discount code."""
    discounts = {"SAVE10": 0.10, "SAVE20": 0.20, "LOYALTY30": 0.30}
    rate = discounts.get(discount_code, 0)
    return total * (1 - rate)


def calculate_loyalty_discount(user_id, total):
    """Calculate loyalty tier discount based on user history."""
    from db import get_user_order_count
    order_count = get_user_order_count(user_id)
    if order_count > 50:
        return total * 0.15
    elif order_count > 20:
        return total * 0.10
    elif order_count > 5:
        return total * 0.05
    return 0


def process_payment(user_id, amount, method="stripe"):
    """Process payment with retry logic and circuit breaker."""
    import stripe
    stripe.api_key = STRIPE_API_KEY

    for attempt in range(MAX_RETRIES):
        try:
            charge = stripe.Charge.create(
                amount=int(amount * 100),
                currency="usd",
                customer=get_stripe_customer_id(user_id),
                metadata={"user_id": str(user_id), "attempt": str(attempt + 1)},
                idempotency_key=f"checkout-{user_id}-{int(time.time())}",
            )
            logger.info(f"Payment successful: {charge.id}")
            return {"status": "success", "charge_id": charge.id}
        except stripe.error.RateLimitError:
            logger.warning(f"Stripe rate limited, attempt {attempt + 1}/{MAX_RETRIES}")
            time.sleep(2 ** attempt)
        except stripe.error.CardError as e:
            return {"status": "failed", "error": f"Card declined: {e.user_message}"}
        except stripe.error.StripeError as e:
            logger.error(f"Stripe error: {e}")
            if attempt == MAX_RETRIES - 1:
                return {"status": "failed", "error": str(e)}
            time.sleep(1)

    return {"status": "failed", "error": "max retries exceeded"}


def get_stripe_customer_id(user_id):
    """Look up or create Stripe customer for user."""
    from db import get_user_stripe_id, save_user_stripe_id
    import stripe

    existing = get_user_stripe_id(user_id)
    if existing:
        return existing

    customer = stripe.Customer.create(metadata={"user_id": str(user_id)})
    save_user_stripe_id(user_id, customer.id)
    return customer.id


def create_order(user_id, items, total, charge_id):
    """Create order record in database."""
    from db import insert_order
    return insert_order(user_id=user_id, items=items, total=total,
                        payment_charge_id=charge_id, status="confirmed")


def notify_fulfillment(order_id):
    """Send order to fulfillment service."""
    import requests
    try:
        requests.post(
            os.environ.get("FULFILLMENT_URL", "http://fulfillment-service/api/orders"),
            json={"order_id": order_id},
            timeout=5,
        )
    except requests.RequestException as e:
        logger.warning(f"Fulfillment notification failed: {e}")
