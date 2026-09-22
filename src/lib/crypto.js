'use strict';

const crypto = require('node:crypto');

const config = require('../config');

/**
 * Sub-keys are derived from the single SECRET_KEY with HKDF so that the key
 * used to encrypt TOTP secrets is unrelated to the one used to index tokens.
 */
function deriveKey(label, length = 32) {
  return Buffer.from(
    crypto.hkdfSync('sha256', config.secret, Buffer.alloc(0), Buffer.from(label, 'utf8'), length)
  );
}

const TOKEN_INDEX_KEY = deriveKey('umole:token-index:v1');
const TOTP_ENCRYPTION_KEY = deriveKey('umole:totp-secret:v1');

/** URL-safe random token. 32 bytes = 256 bits of entropy. */
function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

/**
 * Keyed hash used to store session/invite/reset tokens and recovery codes.
 *
 * These values are high-entropy random strings, not user-chosen passwords, so
 * a single HMAC pass is sufficient — there is nothing to brute force. The key
 * means that a stolen database alone does not let an attacker look up a token
 * they have intercepted elsewhere.
 */
function hashToken(token) {
  return crypto.createHmac('sha256', TOKEN_INDEX_KEY).update(token, 'utf8').digest('hex');
}

/** Length-safe constant-time string comparison. */
function timingSafeEqualStrings(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  // Compare fixed-size digests so that differing lengths do not leak via an
  // early return, and are still reported as unequal.
  const digestA = crypto.createHash('sha256').update(bufA).digest();
  const digestB = crypto.createHash('sha256').update(bufB).digest();
  return crypto.timingSafeEqual(digestA, digestB) && bufA.length === bufB.length;
}

/** AES-256-GCM. Used for TOTP shared secrets, which must be recoverable. */
function encryptSecret(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', TOTP_ENCRYPTION_KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1.${iv.toString('base64url')}.${tag.toString('base64url')}.${ciphertext.toString('base64url')}`;
}

function decryptSecret(encoded) {
  if (typeof encoded !== 'string') return null;
  const parts = encoded.split('.');
  if (parts.length !== 4 || parts[0] !== 'v1') return null;
  try {
    const iv = Buffer.from(parts[1], 'base64url');
    const tag = Buffer.from(parts[2], 'base64url');
    const ciphertext = Buffer.from(parts[3], 'base64url');
    const decipher = crypto.createDecipheriv('aes-256-gcm', TOTP_ENCRYPTION_KEY, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  } catch {
    // Wrong key or tampered ciphertext.
    return null;
  }
}

module.exports = {
  randomToken,
  hashToken,
  timingSafeEqualStrings,
  encryptSecret,
  decryptSecret,
};
