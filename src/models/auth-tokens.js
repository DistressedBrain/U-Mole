'use strict';

const config = require('../config');
const { getDb } = require('../db');
const { randomToken, hashToken } = require('../lib/crypto');

/**
 * Single-use invite and password-reset tokens.
 *
 * Only the HMAC of a token is stored, so the database never contains anything
 * that can be replayed as a link. Issuing a new token for a purpose
 * invalidates any outstanding ones for that user, so a forwarded or leaked
 * old link stops working.
 */
function issue({ userId, purpose, createdBy = null, ttlMs = config.invites.ttlMs, now = Date.now() }) {
  const token = randomToken(32);
  const db = getDb();

  const write = db.transaction(() => {
    db.prepare('DELETE FROM auth_tokens WHERE user_id = ? AND purpose = ?').run(userId, purpose);
    db.prepare(
      `INSERT INTO auth_tokens (token_hash, user_id, purpose, expires_at, created_at, created_by)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(hashToken(token), userId, purpose, now + ttlMs, now, createdBy);
  });
  write();

  return { token, expiresAt: now + ttlMs };
}

/** Look a token up without spending it (to render the "choose a password" form). */
function peek(token, purpose, now = Date.now()) {
  if (!token || typeof token !== 'string') return null;
  const row = getDb()
    .prepare('SELECT * FROM auth_tokens WHERE token_hash = ? AND purpose = ?')
    .get(hashToken(token), purpose);
  if (!row) return null;
  if (row.used_at) return null;
  if (row.expires_at <= now) return null;
  return row;
}

/**
 * Spend a token. The read and the mark-as-used happen in one transaction, so
 * two simultaneous submissions cannot both succeed.
 */
function redeem(token, purpose, now = Date.now()) {
  if (!token || typeof token !== 'string') return null;
  const db = getDb();

  const spend = db.transaction(() => {
    const row = db
      .prepare('SELECT * FROM auth_tokens WHERE token_hash = ? AND purpose = ?')
      .get(hashToken(token), purpose);
    if (!row || row.used_at || row.expires_at <= now) return null;
    db.prepare('UPDATE auth_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL').run(
      now,
      row.id
    );
    return row;
  });

  return spend();
}

function revokeAllForUser(userId) {
  return getDb().prepare('DELETE FROM auth_tokens WHERE user_id = ?').run(userId).changes;
}

function hasPending(userId, purpose, now = Date.now()) {
  return Boolean(
    getDb()
      .prepare(
        'SELECT 1 FROM auth_tokens WHERE user_id = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?'
      )
      .get(userId, purpose, now)
  );
}

function purgeExpired(now = Date.now()) {
  return getDb().prepare('DELETE FROM auth_tokens WHERE expires_at <= ?').run(now).changes;
}

module.exports = { issue, peek, redeem, revokeAllForUser, hasPending, purgeExpired };
