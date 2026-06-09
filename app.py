"""Sample application for testing deploy risk scoring."""


def checkout(cart_items, user_id):
    """Process a checkout."""
    total = sum(item["price"] * item["quantity"] for item in cart_items)
    return {"user_id": user_id, "total": total, "status": "completed"}


def apply_discount(total, discount_code):
    """Apply a discount code."""
    discounts = {"SAVE10": 0.10, "SAVE20": 0.20}
    rate = discounts.get(discount_code, 0)
    return total * (1 - rate)
