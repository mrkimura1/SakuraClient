"use strict";

const { createHash } = require("crypto");
const { databaseUrl } = require("./db");
const {
  hashPassword,
  verifyPassword,
  signToken,
  verifyToken
} = require("./crypto");

// Ключ подписи нельзя держать в публичном репозитории, поэтому если JWT_SECRET
// не задан, он детерминированно выводится из секретной строки подключения к БД.
const secret =
  process.env.JWT_SECRET ||
  createHash("sha256").update(`sakura-jwt:${databaseUrl}`).digest("hex");

function createToken(user) {
  return signToken(user, secret);
}

function readToken(request) {
  const headers = request.headers || {};
  const header = headers.authorization || headers.Authorization || "";
  const match = /^Bearer\s+(.+)$/i.exec(String(header));
  if (!match) return null;
  return verifyToken(match[1], secret);
}

module.exports = { createToken, readToken, hashPassword, verifyPassword };
