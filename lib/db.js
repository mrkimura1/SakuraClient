
  user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  product_name TEXT NOT NULL,
  amount NUMERIC(10, 2) NOT NULL,
  discount_percent INTEGER NOT NULL DEFAULT 0,
  discount_code TEXT,
  created_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS orders_user_id_idx ON orders (user_id);
CREATE INDEX IF NOT EXISTS license_keys_redeemed_by_idx ON license_keys (redeemed_by_user_id);

ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS grants_owner BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS custom_days INTEGER;
`;

const SEED_PRODUCTS = [
  ["SakuraClient 26.2 — 30 дней", 30, 299, "sub", 1],
  ["SakuraClient 26.2 — Полгода", 180, 399, "sub", 2],
  ["SakuraClient 26.2 — Навсегда", null, 499, "sub", 3],
  ["Сброс HWID", null, 149, "hwid", 4]
];

async function ensureSchema() {
  if (!hasDatabase()) {
    throw new Error("DATABASE_URL не задан");
