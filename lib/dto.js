"use strict";

const DAY_MS = 24 * 60 * 60 * 1000;

function iso(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}

function toUserDto(user) {
  const now = Date.now();
  const end = user.subscription_ends_utc
    ? new Date(user.subscription_ends_utc).getTime()
    : null;
  const lifetime = Boolean(user.has_lifetime);
  const activeSubscription = lifetime || (end !== null && end > now);
  const daysLeft = lifetime
    ? 0
    : end !== null
      ? Math.max(0, Math.ceil((end - now) / DAY_MS))
      : 0;

  return {
    id: user.id,
    username: user.username,
    uid: user.uid || "",
    role: user.role,
    subscriptionEndsUtc: iso(user.subscription_ends_utc),
    lifetime,
    daysLeft,
    activeSubscription,
    hasHwid: Boolean(user.hwid_hash),
    createdAtUtc: iso(user.created_at_utc)
  };
}

function periodText(product) {
  if (product.kind === "hwid") return "Разовая услуга";
  if (product.days == null) return "Навсегда";
  return `${product.days} дней`;
}

function toProductDto(product) {
  return {
    id: product.id,
    name: product.name,
    days: product.days == null ? null : Number(product.days),
    price: Number(product.price),
    kind: product.kind,
    periodText: periodText(product)
  };
}

function toOrderDto(order, username) {
  return {
    id: order.id,
    username,
    productName: order.product_name,
    amount: Number(order.amount),
    discountPercent: Number(order.discount_percent) || 0,
    discountCode: order.discount_code || null,
    createdAtUtc: iso(order.created_at_utc)
  };
}

function toKeyDto(key) {
  const used = key.redeemed_by_user_id != null;
  const username = key.redeemed_by_username || null;
  const customDays = key.custom_days == null ? null : Number(key.custom_days);

  return {
    id: key.id,
    value: key.value,
    productName: customDays == null
      ? key.product_name || "—"
      : `Свой срок — ${customDays} дн.`,
    used,
    usedBy: username,
    createdAtUtc: iso(key.created_at_utc),
    note: key.note || null,
    customDays,
    statusText: used ? `Активирован · ${username || "—"}` : "Свободен",
    statusColor: used ? "#C7A2B7" : "#7CF0C0"
  };
}

function toDiscountDto(discount) {
  return {
    id: discount.id,
    code: discount.code,
    percent: Number(discount.percent),
    uses: Number(discount.uses),
    maxUses: Number(discount.max_uses),
    expiresAtUtc: iso(discount.expires_at_utc),
    isActive: Boolean(discount.is_active)
  };
}

function formatRuDate(value) {
  const date = value instanceof Date ? value : new Date(value);
  const day = String(date.getUTCDate()).padStart(2, "0");
  const month = String(date.getUTCMonth() + 1).padStart(2, "0");
  return `${day}.${month}.${date.getUTCFullYear()}`;
}

module.exports = {
  toUserDto,
  toProductDto,
  toOrderDto,
  toKeyDto,
  toDiscountDto,
  formatRuDate,
  iso
};
