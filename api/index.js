"use strict";

const { ensureSchema, hasDatabase, query, withTransaction } = require("../lib/db");
const {
  createToken,
  readToken,
  hashPassword,
  verifyPassword
} = require("../lib/auth");
const {
  toUserDto,
  toProductDto,
  toOrderDto,
  toKeyDto,
  toDiscountDto,
  formatRuDate
} = require("../lib/dto");
const { newKey } = require("../lib/keys");

const DAY_MS = 24 * 60 * 60 * 1000;
const ROLES = new Set(["Player", "User", "Developer", "Owner"]);
const DB_ERROR_CODES = new Set([
  "ECONNREFUSED",
  "ENOTFOUND",
  "ETIMEDOUT",
  "EHOSTUNREACH",
  "28P01",
  "3D000",
  "57P01"
]);

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function send(res, status, data) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(data));
}

function applyCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
}

function readBody(request) {
  const raw = request.body;
  if (raw == null) return {};
  if (typeof raw === "string") {
    try {
      return JSON.parse(raw);
    } catch {
      return {};
    }
  }
  if (Buffer.isBuffer(raw)) {
    try {
      return JSON.parse(raw.toString("utf8"));
    } catch {
      return {};
    }
  }
  return typeof raw === "object" ? raw : {};
}

function getSegments(request) {
  const query = request.query || {};

  // Vercel перенаправляет /api/* на /api?route=* (см. vercel.json),
  // потому что catch-all-роутинг в обычных функциях Vercel не работает.
  const route = query.route;
  if (Array.isArray(route)) return route.filter(Boolean);
  if (typeof route === "string" && route.length > 0) return route.split("/").filter(Boolean);

  const raw = query.path;
  if (Array.isArray(raw)) return raw.filter(Boolean);
  if (typeof raw === "string" && raw.length > 0) return raw.split("/").filter(Boolean);

  try {
    const url = new URL(request.url || "/", "http://localhost");
    return url.pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean);
  } catch {
    return [];
  }
}

function normalizeHwid(value) {
  return String(value || "").trim().toUpperCase();
}

function usernameError(username) {
  if (!/^[\p{L}\p{N}_]{3,20}$/u.test(username)) {
    return "Логин: 3–20 символов, буквы, цифры и _";
  }
  return null;
}

function passwordError(password) {
  if (password.length < 6) return "Пароль должен быть не короче 6 символов";
  if (password.length > 200) return "Пароль слишком длинный";
  return null;
}

async function nextUid(client) {
  await client.query("SELECT pg_advisory_xact_lock(20261104)");
  const { rows } = await client.query(
    "SELECT COALESCE(MAX(uid::int), 0) + 1 AS next FROM users WHERE uid ~ '^[0-9]+$'"
  );
  return String(rows[0].next);
}

function applySubscription(user, product) {
  if (product.days == null) {
    user.has_lifetime = true;
    user.subscription_ends_utc = null;
    return;
  }

  if (user.has_lifetime) return;

  const now = Date.now();
  const end = user.subscription_ends_utc
    ? new Date(user.subscription_ends_utc).getTime()
    : 0;
  const start = end > now ? end : now;
  user.subscription_ends_utc = new Date(start + Number(product.days) * DAY_MS);
}

async function currentUser(request) {
  const payload = readToken(request);
  if (!payload) throw new HttpError(401, "Требуется авторизация");

  const { rows } = await query("SELECT * FROM users WHERE id = $1", [payload.id]);
  if (!rows[0]) throw new HttpError(401, "Требуется авторизация");
  return rows[0];
}

async function currentAdmin(request) {
  const user = await currentUser(request);
  if (user.role !== "Owner" && user.role !== "Developer") {
    throw new HttpError(403, "Недостаточно прав");
  }
  return user;
}

// ---------------------------------------------------------------- публичные

async function status(res) {
  let database = hasDatabase() ? "unknown" : "missing";

  if (hasDatabase()) {
    try {
      await query("SELECT 1");
      database = "ok";
    } catch {
      database = "error";
    }
  }

  send(res, 200, {
    name: "SakuraClient API",
    version: "26.2",
    status: "online",
    database
  });
}

async function register(req, res, requireHwid) {
  const body = readBody(req);
  const username = String(body.username ?? "").trim();
  const password = String(body.password ?? "");
  const hwid = requireHwid ? normalizeHwid(body.hwid) : "";

  const badUsername = usernameError(username);
  if (badUsername) throw new HttpError(400, badUsername);

  const badPassword = passwordError(password);
  if (badPassword) throw new HttpError(400, badPassword);

  if (requireHwid && !hwid) throw new HttpError(400, "Не удалось определить HWID");

  try {
    const user = await withTransaction(async (client) => {
      const uid = await nextUid(client);
      const { rows } = await client.query(
        `INSERT INTO users (username, username_lower, password_hash, role, uid, hwid_hash)
         VALUES ($1, $2, $3, 'Player', $4, $5)
         RETURNING *`,
        [username, username.toLowerCase(), hashPassword(password), uid, hwid || null]
      );
      return rows[0];
    });

    send(res, 200, { token: createToken(user), user: toUserDto(user) });
  } catch (error) {
    if (error && error.code === "23505") {
      throw new HttpError(409, "Этот логин уже занят");
    }
    throw error;
  }
}

async function login(req, res, requireHwid) {
  const body = readBody(req);
  const username = String(body.username ?? "").trim().toLowerCase();
  const password = String(body.password ?? "");
  const hwid = requireHwid ? normalizeHwid(body.hwid) : "";

  if (requireHwid && !hwid) throw new HttpError(400, "Не удалось определить HWID");

  const { rows } = await query("SELECT * FROM users WHERE username_lower = $1", [username]);
  const user = rows[0];

  if (!user || !verifyPassword(password, user.password_hash)) {
    throw new HttpError(401, "Неверный логин или пароль");
  }

  if (requireHwid) {
    if (!user.hwid_hash) {
      await query("UPDATE users SET hwid_hash = $2 WHERE id = $1", [user.id, hwid]);
      user.hwid_hash = hwid;
    } else if (String(user.hwid_hash) !== hwid) {
      throw new HttpError(403, "HWID не совпадает с привязанным. Нужен сброс HWID.");
    }
  }

  send(res, 200, { token: createToken(user), user: toUserDto(user) });
}

async function clientAuth(req, res) {
  const body = readBody(req);
  const uid = String(body.uid ?? "").trim().toUpperCase();
  const hwid = normalizeHwid(body.hwid);

  if (!uid || !hwid) throw new HttpError(400, "Нужны UID и HWID");

  const { rows } = await query("SELECT * FROM users WHERE uid = $1", [uid]);
  const user = rows[0];

  if (!user) throw new HttpError(403, "UID не найден");
  if (!user.hwid_hash) throw new HttpError(403, "HWID не привязан. Зайди в лоадер SakuraClient.");
  if (String(user.hwid_hash) !== hwid) {
    throw new HttpError(403, "HWID не совпадает с аккаунтом. Нужен сброс HWID.");
  }

  const dto = toUserDto(user);
  if (!dto.activeSubscription) throw new HttpError(403, "Подписка не активна");

  send(res, 200, {
    valid: true,
    username: user.username,
    uid: user.uid,
    role: user.role,
    lifetime: dto.lifetime,
    subscriptionEndsUtc: dto.subscriptionEndsUtc
  });
}

async function me(req, res) {
  const user = await currentUser(req);
  send(res, 200, toUserDto(user));
}

async function products(res) {
  const { rows } = await query(
    "SELECT * FROM products WHERE is_active = TRUE ORDER BY sort_order, id"
  );
  send(res, 200, rows.map(toProductDto));
}

async function activateKey(req, res) {
  const body = readBody(req);
  const keyValue = String(body.key ?? "").trim().toUpperCase();
  if (!keyValue) throw new HttpError(400, "Введи ключ");

  const user = await currentUser(req);

  const result = await withTransaction(async (client) => {
    const lockedUser = (
      await client.query("SELECT * FROM users WHERE id = $1 FOR UPDATE", [user.id])
    ).rows[0];
    if (!lockedUser) throw new HttpError(401, "Требуется авторизация");

    const key = (
      await client.query("SELECT * FROM license_keys WHERE value = $1 FOR UPDATE", [keyValue])
    ).rows[0];

    if (!key) throw new HttpError(404, "Ключ не найден");
    if (key.redeemed_by_user_id != null) throw new HttpError(400, "Этот ключ уже активирован");

    const product = (
      await client.query("SELECT * FROM products WHERE id = $1", [key.product_id])
    ).rows[0];
    if (!product || !product.is_active) {
      throw new HttpError(400, "Товар по этому ключу недоступен");
    }

    let message;

    if (key.grants_owner) {
      const taken = (
        await client.query("SELECT username FROM users WHERE role = 'Owner' AND id <> $1", [
          lockedUser.id
        ])
      ).rows[0];
      if (taken) throw new HttpError(409, `Владелец уже назначен на ${taken.username}`);

      lockedUser.has_lifetime = true;
      lockedUser.subscription_ends_utc = null;
      lockedUser.role = "Owner";

      await client.query(
        `UPDATE users
            SET has_lifetime = TRUE, subscription_ends_utc = NULL, role = 'Owner'
          WHERE id = $1`,
        [lockedUser.id]
      );

      message = "Навсегда и права владельца";
    } else if (product.kind === "hwid") {
      await client.query("UPDATE users SET hwid_hash = NULL WHERE id = $1", [lockedUser.id]);
      lockedUser.hwid_hash = null;
      message = "HWID сброшен — перезайди в аккаунт";
    } else {
      applySubscription(lockedUser, product);
      if (lockedUser.role === "Player") lockedUser.role = "User";

      await client.query(
        `UPDATE users
            SET has_lifetime = $2, subscription_ends_utc = $3, role = $4
          WHERE id = $1`,
        [
          lockedUser.id,
          Boolean(lockedUser.has_lifetime),
          lockedUser.subscription_ends_utc,
          lockedUser.role
        ]
      );

      message = product.days == null
        ? "Активирована подписка навсегда"
        : `Подписка активна до ${formatRuDate(lockedUser.subscription_ends_utc)}`;
    }

    await client.query(
      `UPDATE license_keys
          SET redeemed_by_user_id = $2, redeemed_at_utc = NOW()
        WHERE id = $1`,
      [key.id, lockedUser.id]
    );

    return { user: lockedUser, message };
  });

  send(res, 200, { user: toUserDto(result.user), message: result.message });
}

async function purchase(req, res) {
  const body = readBody(req);
  const productId = Number.parseInt(body.productId, 10);
  const discountCode = String(body.discountCode ?? "").trim().toUpperCase();

  const user = await currentUser(req);

  const result = await withTransaction(async (client) => {
    const lockedUser = (
      await client.query("SELECT * FROM users WHERE id = $1 FOR UPDATE", [user.id])
    ).rows[0];
    if (!lockedUser) throw new HttpError(401, "Требуется авторизация");

    const product = (
      await client.query(
        "SELECT * FROM products WHERE id = $1 AND is_active = TRUE",
        [productId]
      )
    ).rows[0];
    if (!product) throw new HttpError(400, "Товар не найден");

    let discount = null;
    let percent = 0;

    if (discountCode.length > 0) {
      discount = (
        await client.query("SELECT * FROM discounts WHERE code = $1 FOR UPDATE", [discountCode])
      ).rows[0];

      if (!discount || !discount.is_active) throw new HttpError(400, "Код скидки не найден");
      if (discount.expires_at_utc && new Date(discount.expires_at_utc).getTime() < Date.now()) {
        throw new HttpError(400, "Срок действия кода истёк");
      }
      if (Number(discount.uses) >= Number(discount.max_uses)) {
        throw new HttpError(400, "Лимит использований кода исчерпан");
      }

      percent = Number(discount.percent);
      await client.query("UPDATE discounts SET uses = uses + 1 WHERE id = $1", [discount.id]);
    }

    const amount = Math.round(Number(product.price) * (100 - percent)) / 100;

    if (product.kind === "hwid") {
      await client.query("UPDATE users SET hwid_hash = NULL WHERE id = $1", [lockedUser.id]);
      lockedUser.hwid_hash = null;
    } else {
      applySubscription(lockedUser, product);
      if (lockedUser.role === "Player") lockedUser.role = "User";

      await client.query(
        `UPDATE users
            SET has_lifetime = $2, subscription_ends_utc = $3, role = $4
          WHERE id = $1`,
        [
          lockedUser.id,
          Boolean(lockedUser.has_lifetime),
          lockedUser.subscription_ends_utc,
          lockedUser.role
        ]
      );
    }

    const order = (
      await client.query(
        `INSERT INTO orders (user_id, product_name, amount, discount_percent, discount_code)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING *`,
        [
          lockedUser.id,
          product.name,
          amount,
          percent,
          percent > 0 ? discountCode : null
        ]
      )
    ).rows[0];

    const message = product.kind === "hwid"
      ? "HWID сброшен — перезайди в аккаунт"
      : product.days == null
        ? "Подписка оформлена навсегда"
        : `Подписка активна до ${formatRuDate(lockedUser.subscription_ends_utc)}`;

    return { user: lockedUser, order, message };
  });

  send(res, 200, {
    user: toUserDto(result.user),
    order: toOrderDto(result.order, result.user.username),
    message: result.message
  });
}

async function myOrders(req, res) {
  const user = await currentUser(req);
  const { rows } = await query(
    "SELECT * FROM orders WHERE user_id = $1 ORDER BY id DESC",
    [user.id]
  );
  send(res, 200, rows.map((order) => toOrderDto(order, user.username)));
}

// ---------------------------------------------------------------- админка

async function adminUsers(req, res) {
  await currentAdmin(req);
  const { rows } = await query("SELECT * FROM users ORDER BY id");
  send(res, 200, rows.map(toUserDto));
}

async function adminSetRole(req, res, userId) {
  const admin = await currentAdmin(req);
  const body = readBody(req);
  const role = String(body.role ?? "").trim();

  if (userId === admin.id) throw new HttpError(400, "Нельзя изменить свою роль");
  if (!ROLES.has(role)) throw new HttpError(400, "Неизвестная роль");
  if (role === "Owner") throw new HttpError(400, "Владельца нельзя назначить через панель");

  const target = (
    await query("SELECT role FROM users WHERE id = $1", [userId])
  ).rows[0];
  if (!target) throw new HttpError(404, "Пользователь не найден");
  if (target.role === "Owner" && admin.role !== "Owner") {
    throw new HttpError(403, "Роль владельца меняет только владелец");
  }

  const { rows } = await query(
    "UPDATE users SET role = $2 WHERE id = $1 RETURNING *",
    [userId, role]
  );
  if (!rows[0]) throw new HttpError(404, "Пользователь не найден");

  send(res, 200, toUserDto(rows[0]));
}

async function adminResetHwid(req, res, userId) {
  await currentAdmin(req);
  const { rows } = await query(
    "UPDATE users SET hwid_hash = NULL WHERE id = $1 RETURNING *",
    [userId]
  );
  if (!rows[0]) throw new HttpError(404, "Пользователь не найден");
  send(res, 200, toUserDto(rows[0]));
}

async function adminKeys(req, res) {
  await currentAdmin(req);
  const { rows } = await query(
    `SELECT k.*, p.name AS product_name, u.username AS redeemed_by_username
       FROM license_keys k
       LEFT JOIN products p ON p.id = k.product_id
       LEFT JOIN users u ON u.id = k.redeemed_by_user_id
      ORDER BY k.id DESC
      LIMIT 200`
  );
  send(res, 200, rows.map(toKeyDto));
}

async function adminCreateKeys(req, res) {
  const admin = await currentAdmin(req);
  const body = readBody(req);
  const productId = Number.parseInt(body.productId, 10);
  const count = Math.min(Math.max(Number.parseInt(body.count, 10) || 1, 1), 50);
  let note = String(body.note ?? "").trim();
  if (note.length > 60) note = note.slice(0, 60);

  const product = (
    await query("SELECT * FROM products WHERE id = $1 AND is_active = TRUE", [productId])
  ).rows[0];
  if (!product) throw new HttpError(400, "Товар не найден");

  const created = await withTransaction(async (client) => {
    const result = [];

    for (let i = 0; i < count; i++) {
      let value = null;

      for (let attempt = 0; attempt < 10 && !value; attempt++) {
        const candidate = newKey();
        const exists = await client.query("SELECT 1 FROM license_keys WHERE value = $1", [candidate]);
        if (exists.rowCount === 0) value = candidate;
      }

      if (!value) throw new HttpError(500, "Не удалось сгенерировать ключ");

      const inserted = (
        await client.query(
          `INSERT INTO license_keys (value, product_id, created_by_user_id, note)
           VALUES ($1, $2, $3, $4)
           RETURNING *`,
          [value, product.id, admin.id, note.length > 0 ? note : null]
        )
      ).rows[0];

      result.push({ ...inserted, product_name: product.name });
    }

    return result;
  });

  send(res, 200, created.map(toKeyDto));
}

async function adminRevokeKey(req, res, keyId) {
  await currentAdmin(req);
  const key = (await query("SELECT * FROM license_keys WHERE id = $1", [keyId])).rows[0];
  if (!key) throw new HttpError(404, "Ключ не найден");
  if (key.redeemed_by_user_id != null) {
    throw new HttpError(400, "Ключ уже активирован — удалить нельзя");
  }

  await query("DELETE FROM license_keys WHERE id = $1", [keyId]);
  send(res, 200, { message: "Ключ удалён" });
}

async function adminDiscounts(req, res) {
  await currentAdmin(req);
  const { rows } = await query("SELECT * FROM discounts ORDER BY id DESC");
  send(res, 200, rows.map(toDiscountDto));
}

async function adminCreateDiscount(req, res) {
  await currentAdmin(req);
  const body = readBody(req);
  const code = String(body.code ?? "").trim().toUpperCase();
  const percent = Number.parseInt(body.percent, 10);
  const maxUses = Number.parseInt(body.maxUses, 10);

  if (!/^[\p{L}\p{N}_-]{3,20}$/u.test(code)) {
    throw new HttpError(400, "Код: 3–20 символов, буквы, цифры, - и _");
  }
  if (!Number.isFinite(percent) || percent < 5 || percent > 90) {
    throw new HttpError(400, "Скидка должна быть от 5% до 90%");
  }
  if (!Number.isFinite(maxUses) || maxUses < 1) {
    throw new HttpError(400, "Количество использований должно быть больше нуля");
  }

  try {
    const expires = body.expiresAtUtc ? new Date(body.expiresAtUtc) : null;
    const { rows } = await query(
      `INSERT INTO discounts (code, percent, max_uses, expires_at_utc)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [
        code,
        percent,
        Math.min(maxUses, 10_000),
        expires && !Number.isNaN(expires.getTime()) ? expires : null
      ]
    );
    send(res, 200, toDiscountDto(rows[0]));
  } catch (error) {
    if (error && error.code === "23505") {
      throw new HttpError(409, "Такой код уже существует");
    }
    throw error;
  }
}

async function adminToggleDiscount(req, res, discountId) {
  await currentAdmin(req);
  const { rows } = await query(
    "UPDATE discounts SET is_active = NOT is_active WHERE id = $1 RETURNING *",
    [discountId]
  );
  if (!rows[0]) throw new HttpError(404, "Скидка не найдена");
  send(res, 200, toDiscountDto(rows[0]));
}

async function adminOrders(req, res) {
  await currentAdmin(req);
  const { rows } = await query(
    `SELECT o.*, u.username
       FROM orders o
       JOIN users u ON u.id = o.user_id
      ORDER BY o.id DESC
      LIMIT 200`
  );
  send(res, 200, rows.map((order) => toOrderDto(order, order.username)));
}

// ---------------------------------------------------------------- маршруты

async function route(req, res, segments) {
  const method = String(req.method || "GET").toUpperCase();
  const path = segments.join("/");

  if (method === "GET" && path === "site/products") return products(res);
  if (method === "GET" && path === "products") return products(res);

  if (method === "POST" && path === "auth/register") return register(req, res, true);
  if (method === "POST" && path === "auth/login") return login(req, res, true);
  if (method === "POST" && path === "site/register") return register(req, res, false);
  if (method === "POST" && path === "site/login") return login(req, res, false);
  if (method === "POST" && path === "client/auth") return clientAuth(req, res);

  if (method === "GET" && path === "me") return me(req, res);
  if (method === "POST" && path === "keys/activate") return activateKey(req, res);
  if (method === "POST" && path === "shop/purchase") return purchase(req, res);
  if (method === "GET" && path === "shop/orders") return myOrders(req, res);

  if (method === "GET" && path === "admin/users") return adminUsers(req, res);
  if (method === "GET" && path === "admin/keys") return adminKeys(req, res);
  if (method === "POST" && path === "admin/keys") return adminCreateKeys(req, res);
  if (method === "GET" && path === "admin/discounts") return adminDiscounts(req, res);
  if (method === "POST" && path === "admin/discounts") return adminCreateDiscount(req, res);
  if (method === "GET" && path === "admin/orders") return adminOrders(req, res);

  if (segments[0] === "admin" && segments[1] === "users" && segments[3] === "role") {
    if (method === "POST") return adminSetRole(req, res, Number.parseInt(segments[2], 10));
  }

  if (segments[0] === "admin" && segments[1] === "users" && segments[3] === "reset-hwid") {
    if (method === "POST") return adminResetHwid(req, res, Number.parseInt(segments[2], 10));
  }

  if (segments[0] === "admin" && segments[1] === "keys" && segments[3] === "revoke") {
    if (method === "POST") return adminRevokeKey(req, res, Number.parseInt(segments[2], 10));
  }

  if (segments[0] === "admin" && segments[1] === "discounts" && segments[3] === "toggle") {
    if (method === "POST") return adminToggleDiscount(req, res, Number.parseInt(segments[2], 10));
  }

  throw new HttpError(404, "Не найдено");
}

module.exports = async function handler(req, res) {
  applyCors(res);

  if (String(req.method || "").toUpperCase() === "OPTIONS") {
    res.statusCode = 204;
    res.end();
    return;
  }

  const segments = getSegments(req);
  const path = segments.join("/");

  try {
    if (String(req.method || "").toUpperCase() === "GET" && (path === "" || path === "status")) {
      return await status(res);
    }

    if (!hasDatabase()) {
      throw new HttpError(
        503,
        "База данных не настроена. В Vercel открой Storage → Create Database → Postgres, подключи её к проекту и сделай Redeploy."
      );
    }

    await ensureSchema();
    await route(req, res, segments);
  } catch (error) {
    if (res.writableEnded) return;

    if (error instanceof HttpError) {
      send(res, error.status, { error: error.message });
      return;
    }

    if (error && DB_ERROR_CODES.has(error.code)) {
      console.error("Database connection error:", error.message);
      send(res, 503, {
        error: "Не удалось подключиться к базе данных. Проверь DATABASE_URL в настройках Vercel."
      });
      return;
    }

    console.error("API error:", error);
    send(res, 500, { error: "Внутренняя ошибка сервера" });
  }
};
