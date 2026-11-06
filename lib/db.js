"use strict";

const { Pool } = require("pg");
const { hashPassword } = require("./crypto");
const { newKey } = require("./keys");

const databaseUrl =
  process.env.DATABASE_URL ||
  process.env.POSTGRES_URL ||
  process.env.POSTGRES_PRISMA_URL ||
  process.env.POSTGRES_URL_NON_POOLING ||
  "";

let pool = null;
let schemaReady = null;

function hasDatabase() {
  return databaseUrl.length > 0;
}

function getPool() {
  if (!pool) {
    const isLocal = /(^|@)(localhost|127\.0\.0\.1)(:|\/)/i.test(databaseUrl);
    pool = new Pool({
      connectionString: databaseUrl,
      max: 3,
      idleTimeoutMillis: 10_000,
      connectionTimeoutMillis: 15_000,
      ssl: isLocal ? false : { rejectUnauthorized: false }
    });
    pool.on("error", (error) => {
      console.error("Postgres pool error:", error.message);
    });
  }
  return pool;
}

function query(text, params) {
  return getPool().query(text, params);
}

async function withTransaction(fn) {
  const client = await getPool().connect();
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch {
      /* пул мог уже закрыть соединение */
    }
    throw error;
  } finally {
    client.release();
  }
}

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username TEXT NOT NULL,
  username_lower TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'Player',
  uid TEXT,
  subscription_ends_utc TIMESTAMPTZ,
  has_lifetime BOOLEAN NOT NULL DEFAULT FALSE,
  hwid_hash TEXT,
  created_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS users_single_owner
  ON users (role) WHERE role = 'Owner';

CREATE TABLE IF NOT EXISTS products (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  days INTEGER,
  price NUMERIC(10, 2) NOT NULL,
  kind TEXT NOT NULL DEFAULT 'sub',
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS license_keys (
  id SERIAL PRIMARY KEY,
  value TEXT NOT NULL UNIQUE,
  product_id INTEGER NOT NULL REFERENCES products (id),
  created_by_user_id INTEGER,
  created_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  redeemed_by_user_id INTEGER REFERENCES users (id) ON DELETE SET NULL,
  redeemed_at_utc TIMESTAMPTZ,
  note TEXT
);

CREATE TABLE IF NOT EXISTS discounts (
  id SERIAL PRIMARY KEY,
  code TEXT NOT NULL UNIQUE,
  percent INTEGER NOT NULL,
  max_uses INTEGER NOT NULL DEFAULT 1,
  uses INTEGER NOT NULL DEFAULT 0,
  expires_at_utc TIMESTAMPTZ,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS orders (
  id SERIAL PRIMARY KEY,
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
  }

  if (!schemaReady) {
    schemaReady = (async () => {
      const client = await getPool().connect();
      try {
        await client.query("BEGIN");
        await client.query("SELECT pg_advisory_xact_lock(20261103)");
        await client.query(SCHEMA_SQL);

        // Товары в коде — единственный источник цен (админ-редактора товаров нет),
        // поэтому синхронизируем и вставку, и уже существующие строки.
        for (const [name, days, price, kind, sortOrder] of SEED_PRODUCTS) {
          const updated = await client.query(
            `UPDATE products
                SET name = $1, price = $2, is_active = TRUE, sort_order = $3
              WHERE days IS NOT DISTINCT FROM $4 AND kind = $5`,
            [name, price, sortOrder, days, kind]
          );

          if (updated.rowCount === 0) {
            await client.query(
              `INSERT INTO products (name, days, price, kind, is_active, sort_order)
               VALUES ($1, $2, $3, $4, TRUE, $5)`,
              [name, days, price, kind, sortOrder]
            );
          }
        }

        await client.query("COMMIT");
      } catch (error) {
        try {
          await client.query("ROLLBACK");
        } catch {
          /* ignore */
        }
        schemaReady = null;
        throw error;
      } finally {
        client.release();
      }

      try {
        await ensureOwner();
      } catch (error) {
        console.error("Не удалось создать владельца:", error.message);
      }

      try {
        await ensureOwnerKey();
      } catch (error) {
        console.error("Не удалось подготовить owner-ключ:", error.message);
      }
    })();
  }

  return schemaReady;
}

// Одноразовый бутстрап владельца из переменных окружения.
// Если владелец уже есть — ничего не делает.
async function ensureOwner() {
  const username = String(process.env.OWNER_USERNAME || "").trim();
  const password = String(process.env.OWNER_PASSWORD || "");
  if (!username) return;

  const owners = await query("SELECT id FROM users WHERE role = 'Owner' LIMIT 1");
  if (owners.rows.length > 0) return;

  const lower = username.toLowerCase();
  const existing = await query("SELECT * FROM users WHERE username_lower = $1", [lower]);

  if (existing.rows.length > 0) {
    await query("UPDATE users SET role = 'Owner' WHERE id = $1", [existing.rows[0].id]);
    console.log(`[sakura] Пользователь ${existing.rows[0].username} назначен владельцем.`);
    return;
  }

  if (password.length < 6) {
    console.warn("[sakura] OWNER_PASSWORD не задан (минимум 6 символов) — владелец не создан.");
    return;
  }

  const next = await query(
    "SELECT COALESCE(MAX(uid::int), 0) + 1 AS next FROM users WHERE uid ~ '^[0-9]+$'"
  );

  await query(
    `INSERT INTO users (username, username_lower, password_hash, role, uid)
     VALUES ($1, $2, $3, 'Owner', $4)`,
    [username, lower, hashPassword(password), String(next.rows[0].next)]
  );
  console.log(`[sakura] Создан владелец ${username}.`);
}

// Один ключ, который при активации даёт подписку навсегда и роль Owner.
// Товар для него не создаётся — ключ привязан к существующему «Навсегда».
// OWNER_KEY важнее сгенерированного ключа: если ключ появился раньше, чем
// переменная окружения попала в Vercel, невостребованный ключ переименовывается.
async function ensureOwnerKey() {
  const product = (
    await query("SELECT id FROM products WHERE kind = 'sub' AND days IS NULL ORDER BY id LIMIT 1")
  ).rows[0];
  if (!product) return;

  const fromEnv = String(process.env.OWNER_KEY || "").trim().toUpperCase();

  if (fromEnv.length > 0) {
    const mine = (
      await query("SELECT id, grants_owner, redeemed_by_user_id FROM license_keys WHERE value = $1", [
        fromEnv
      ])
    ).rows[0];

    if (mine) {
      if (!mine.grants_owner && mine.redeemed_by_user_id == null) {
        await query("UPDATE license_keys SET grants_owner = TRUE, product_id = $2 WHERE id = $1", [
          mine.id,
          product.id
        ]);
        console.log(`[sakura] Ключ ${fromEnv} помечен как owner-ключ.`);
      }
      return;
    }

    const earlier = (
      await query(
        `SELECT id FROM license_keys
          WHERE grants_owner = TRUE AND redeemed_by_user_id IS NULL
          ORDER BY id LIMIT 1`
      )
    ).rows[0];

    if (earlier) {
      await query("UPDATE license_keys SET value = $2, product_id = $3 WHERE id = $1", [
        earlier.id,
        fromEnv,
        product.id
      ]);
    } else {
      await query(
        `INSERT INTO license_keys (value, product_id, note, grants_owner)
         VALUES ($1, $2, 'owner', TRUE)`,
        [fromEnv, product.id]
      );
    }

    console.log(`[sakura] Owner-ключ готов к активации: ${fromEnv}`);
    return;
  }

  const already = await query("SELECT 1 FROM license_keys WHERE grants_owner = TRUE LIMIT 1");
  if (already.rows.length > 0) return;

  const value = newKey();

  await query(
    `INSERT INTO license_keys (value, product_id, note, grants_owner)
     VALUES ($1, $2, 'owner', TRUE)
     ON CONFLICT (value) DO NOTHING`,
    [value, product.id]
  );
  console.log(`[sakura] Owner-ключ готов к активации: ${value}`);
}

module.exports = {
  databaseUrl,
  hasDatabase,
  ensureSchema,
  query,
  withTransaction
};
