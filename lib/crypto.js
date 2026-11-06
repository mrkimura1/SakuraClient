"use strict";

const {
  createHmac,
  pbkdf2Sync,
  randomBytes,
  timingSafeEqual
} = require("crypto");

// Совместимо с PasswordHasher.cs из SakuraLoader.Server:
// PBKDF2-SHA256, 100000 итераций, 32 байта, формат "base64(salt).base64(hash)".
const ITERATIONS = 100_000;
const KEY_LENGTH = 32;
const DIGEST = "sha256";

function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = pbkdf2Sync(String(password), salt, ITERATIONS, KEY_LENGTH, DIGEST);
  return `${salt.toString("base64")}.${hash.toString("base64")}`;
}

function verifyPassword(password, stored) {
  const parts = String(stored || "").split(".");
  if (parts.length !== 2) return false;

  try {
    const salt = Buffer.from(parts[0], "base64");
    const expected = Buffer.from(parts[1], "base64");
    if (salt.length === 0 || expected.length === 0) return false;

    const actual = pbkdf2Sync(String(password), salt, ITERATIONS, expected.length, DIGEST);
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function signToken(user, secret) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = base64url(JSON.stringify({
    id: user.id,
    username: user.username,
    role: user.role,
    iat: now,
    exp: now + 12 * 60 * 60
  }));
  const signature = createHmac("sha256", secret)
    .update(`${header}.${payload}`)
    .digest("base64url");
  return `${header}.${payload}.${signature}`;
}

function verifyToken(token, secret) {
  if (typeof token !== "string") return null;

  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const [header, payload, signature] = parts;
  const expected = createHmac("sha256", secret)
    .update(`${header}.${payload}`)
    .digest("base64url");

  const actualBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);
  if (actualBuffer.length !== expectedBuffer.length) return null;
  if (!timingSafeEqual(actualBuffer, expectedBuffer)) return null;

  let data;
  try {
    data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    return null;
  }

  if (!data || typeof data.exp !== "number" || data.exp * 1000 < Date.now()) return null;
  if (typeof data.id !== "number") return null;

  return data;
}

module.exports = { hashPassword, verifyPassword, signToken, verifyToken };
