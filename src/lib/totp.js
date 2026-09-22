'use strict';

const crypto = require('node:crypto');

const config = require('../config');

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

function base32Decode(input) {
  const cleaned = String(input).toUpperCase().replace(/[=\s]/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const char of cleaned) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) throw new Error('Invalid base32 character in TOTP secret');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/** 160-bit shared secret, the size RFC 4226 recommends for HMAC-SHA1. */
function generateSecret() {
  return base32Encode(crypto.randomBytes(20));
}

function counterBuffer(counter) {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter));
  return buffer;
}

function hotp(secretBuffer, counter, digits) {
  const digest = crypto.createHmac('sha1', secretBuffer).update(counterBuffer(counter)).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(binary % 10 ** digits).padStart(digits, '0');
}

function currentStep(now = Date.now()) {
  return Math.floor(now / 1000 / config.totp.stepSeconds);
}

/**
 * Verify a submitted code.
 *
 * Returns the time step the code belongs to, or `null` if it does not match.
 * The caller MUST persist the returned step and refuse anything less than or
 * equal to it, otherwise an intercepted code can be replayed for the rest of
 * its validity window.
 *
 * @param {string} secret base32 shared secret
 * @param {string} token  code submitted by the user
 * @param {{ now?: number, lastUsedStep?: number }} [options]
 * @returns {number|null}
 */
function verifyTotp(secret, token, { now = Date.now(), lastUsedStep = 0 } = {}) {
  const digits = config.totp.digits;
  const candidate = String(token || '').replace(/\D/g, '');
  if (candidate.length !== digits) return null;

  let secretBuffer;
  try {
    secretBuffer = base32Decode(secret);
  } catch {
    return null;
  }
  if (secretBuffer.length === 0) return null;

  const step = currentStep(now);
  const candidateBuffer = Buffer.from(candidate, 'utf8');

  let matchedStep = null;
  // Walk the whole window regardless of an early match: constant work, no
  // timing signal about which step matched.
  for (let offset = -config.totp.window; offset <= config.totp.window; offset += 1) {
    const testStep = step + offset;
    if (testStep < 0) continue;
    const expected = Buffer.from(hotp(secretBuffer, testStep, digits), 'utf8');
    if (crypto.timingSafeEqual(expected, candidateBuffer) && matchedStep === null) {
      matchedStep = testStep;
    }
  }

  if (matchedStep === null) return null;
  // Replay protection: this code, or an older one, has already been spent.
  if (matchedStep <= lastUsedStep) return null;
  return matchedStep;
}

/** otpauth:// URI consumed by Google Authenticator, Aegis, 1Password, etc. */
function otpauthUri(secret, accountName) {
  const issuer = config.totp.issuer;
  const label = `${issuer}:${accountName}`;
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: String(config.totp.digits),
    period: String(config.totp.stepSeconds),
  });
  return `otpauth://totp/${encodeURIComponent(label)}?${params.toString()}`;
}

module.exports = {
  generateSecret,
  verifyTotp,
  otpauthUri,
  currentStep,
  base32Encode,
  base32Decode,
  hotp,
};
