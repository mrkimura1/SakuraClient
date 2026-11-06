"use strict";

const { randomInt } = require("crypto");

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const GROUP_LENGTH = 4;
const GROUPS = 4;

function newKey() {
  let value = "";
  for (let i = 0; i < GROUP_LENGTH * GROUPS; i++) {
    value += ALPHABET[randomInt(ALPHABET.length)];
  }

  const groups = [];
  for (let i = 0; i < GROUPS; i++) {
    groups.push(value.slice(i * GROUP_LENGTH, (i + 1) * GROUP_LENGTH));
  }

  return `SAKURA-${groups.join("-")}`;
}

module.exports = { newKey };
