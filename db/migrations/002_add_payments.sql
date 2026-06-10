-- Migration: Add payments table and link to orders
CREATE TABLE payments (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    currency VARCHAR(3) DEFAULT 'usd',
    stripe_charge_id VARCHAR(255) UNIQUE,
    stripe_customer_id VARCHAR(255),
    status VARCHAR(20) DEFAULT 'pending',
    failure_reason TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_payments_user_id ON payments(user_id);
CREATE INDEX idx_payments_stripe_charge_id ON payments(stripe_charge_id);

ALTER TABLE orders ADD COLUMN payment_id INTEGER REFERENCES payments(id);
ALTER TABLE orders ADD COLUMN discount_amount DECIMAL(10,2) DEFAULT 0;

-- Add loyalty tracking
CREATE TABLE user_loyalty (
    user_id INTEGER PRIMARY KEY,
    total_orders INTEGER DEFAULT 0,
    total_spent DECIMAL(12,2) DEFAULT 0,
    tier VARCHAR(20) DEFAULT 'bronze',
    stripe_customer_id VARCHAR(255),
    updated_at TIMESTAMP DEFAULT NOW()
);
