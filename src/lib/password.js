'use strict';

const argon2 = require('argon2');
const crypto = require('node:crypto');

const config = require('../config');
const { COMMON_PASSWORDS } = require('./common-passwords');

const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: config.password.memoryCost,
  timeCost: config.password.timeCost,
  parallelism: config.password.parallelism,
  // Pepper: an attacker with only the database cannot verify guesses.
  secret: config.secret,
};

/**
 * A hash of a value nobody knows. Verified against whenever a login names an
 * account that does not exist, so that "no such user" and "wrong password"
 * take the same amount of time.
 */
let dummyHashPromise = null;
function dummyHash() {
  if (!dummyHashPromise) {
    dummyHashPromise = argon2.hash(crypto.randomBytes(32).toString('hex'), ARGON2_OPTIONS);
  }
  return dummyHashPromise;
}

async function hashPassword(password) {
  return argon2.hash(password, ARGON2_OPTIONS);
}

/**
 * @returns {Promise<{ valid: boolean, needsRehash: boolean }>}
 */
async function verifyPassword(hash, password) {
  if (!hash) {
    // Account has no password set yet (invite not redeemed). Still burn the
    // same amount of time as a real verification.
    await argon2.verify(await dummyHash(), password, { secret: config.secret }).catch(() => false);
    return { valid: false, needsRehash: false };
  }
  let valid = false;
  try {
    valid = await argon2.verify(hash, password, { secret: config.secret });
  } catch {
    valid = false;
  }
  let needsRehash = false;
  if (valid) {
    try {
      needsRehash = argon2.needsRehash(hash, ARGON2_OPTIONS);
    } catch {
      needsRehash = false;
    }
  }
  return { valid, needsRehash };
}

/** Equalise timing for logins that name a non-existent account. */
async function burnVerifyTime(password) {
  try {
    await argon2.verify(await dummyHash(), password, { secret: config.secret });
  } catch {
    /* expected: the password never matches */
  }
}

function hasSequentialRun(password, minRun = 4) {
  const lower = password.toLowerCase();
  let ascending = 1;
  let descending = 1;
  for (let i = 1; i < lower.length; i += 1) {
    const delta = lower.charCodeAt(i) - lower.charCodeAt(i - 1);
    ascending = delta === 1 ? ascending + 1 : 1;
    descending = delta === -1 ? descending + 1 : 1;
    if (ascending >= minRun || descending >= minRun) return true;
  }
  return false;
}

function hasRepeatedRun(password, minRun = 4) {
  let run = 1;
  for (let i = 1; i < password.length; i += 1) {
    run = password[i] === password[i - 1] ? run + 1 : 1;
    if (run >= minRun) return true;
  }
  return false;
}

function normaliseForComparison(value) {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/**
 * Policy follows NIST SP 800-63B: length is what matters, plus a blocklist of
 * known-bad choices. No forced composition rules, no forced expiry.
 *
 * @returns {string[]} human-readable problems; empty means acceptable.
 */
function checkPasswordStrength(password, { email = '', name = '' } = {}) {
  const problems = [];

  if (typeof password !== 'string' || password.length === 0) {
    return ['Enter a password.'];
  }
  if (password.length < config.password.minLength) {
    problems.push(`Use at least ${config.password.minLength} characters.`);
  }
  if (password.length > config.password.maxLength) {
    problems.push(`Use at most ${config.password.maxLength} characters.`);
  }
  if (password.trim().length === 0) {
    problems.push('A password cannot be only whitespace.');
  }

  const normalised = normaliseForComparison(password);
  if (COMMON_PASSWORDS.has(password.toLowerCase()) || COMMON_PASSWORDS.has(normalised)) {
    problems.push('This password appears in lists of commonly used passwords.');
  }

  const identifiers = [email, email.split('@')[0] || '', name, 'umole']
    .map(normaliseForComparison)
    .filter((value) => value.length >= 3);
  if (identifiers.some((value) => normalised.includes(value))) {
    problems.push('Do not include your name, email address, or the site name.');
  }

  if (hasRepeatedRun(password)) {
    problems.push('Avoid runs of the same character (for example "aaaa").');
  }
  if (hasSequentialRun(password)) {
    problems.push('Avoid sequential runs (for example "abcd" or "4321").');
  }

  const uniqueChars = new Set(password).size;
  if (uniqueChars < 6) {
    problems.push('Use a greater variety of characters.');
  }

  return problems;
}

module.exports = {
  hashPassword,
  verifyPassword,
  burnVerifyTime,
  checkPasswordStrength,
};
