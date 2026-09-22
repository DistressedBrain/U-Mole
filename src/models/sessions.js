'use strict';

const config = require('../config');
const { getDb } = require('../db');
const { randomToken, hashToken } = require('../lib/crypto');

/**
 * Sessions live in the database, not in a signed cookie. The cookie carries
 * only a random 256-bit identifier, and the database stores its HMAC — so a
 * stolen database cannot be turned into a valid cookie, and revocation is
 * immediate rather than "whenever the JWT expires".
 */
function create({ userId, ip = '', userAgent = '', mfaPending = false, now = Date.now() }) {
  const token = randomToken(32);
  const csrfToken = randomToken(32);
  const info = getDb()
    .prepare(
      `INSERT INTO sessions
         (token_hash, user_id, csrf_token, mfa_pending, created_at, last_seen_at,
          absolute_expires_at, ip, user_agent)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      hashToken(token),
      userId,
      csrfToken,
      mfaPending ? 1 : 0,
      now,
      now,
      now + config.session.absoluteTimeoutMs,
      ip,
      String(userAgent).slice(0, 255)
    );

  return { token, session: findById(info.lastInsertRowid) };
}

function findById(id) {
  return getDb().prepare('SELECT * FROM sessions WHERE id = ?').get(id) || null;
}

/**
 * Resolve a cookie value to a live session, enforcing both the idle and the
 * absolute timeout. Returns null for anything expired, revoked, or unknown.
 */
function resolve(token, now = Date.now()) {
  if (!token || typeof token !== 'string') return null;

  const session = getDb().prepare('SELECT * FROM sessions WHERE token_hash = ?').get(hashToken(token));
  if (!session) return null;
  if (session.revoked_at) return null;
  if (session.absolute_expires_at <= now) return null;
  if (now - session.last_seen_at > config.session.idleTimeoutMs) return null;

  return session;
}

function touch(id, { ip, userAgent } = {}, now = Date.now()) {
  const db = getDb();
  if (ip !== undefined || userAgent !== undefined) {
    db.prepare('UPDATE sessions SET last_seen_at = ?, ip = ?, user_agent = ? WHERE id = ?').run(
      now,
      ip || '',
      String(userAgent || '').slice(0, 255),
      id
    );
  } else {
    db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id = ?').run(now, id);
  }
}

/**
 * Issue a fresh identifier for an existing session and invalidate the old one.
 *
 * Called on every privilege change — password accepted, second factor
 * accepted, password changed, sudo granted — so that a session identifier an
 * attacker managed to plant or observe before the change is worthless after
 * it. This is the standard defence against session fixation.
 */
function rotate(sessionId, { now = Date.now(), resetCreatedAt = false } = {}) {
  const token = randomToken(32);
  // `resetCreatedAt` marks the session as having re-confirmed the account's
  // credentials. Needed when this very session changes the password, since
  // sessions older than the password are otherwise dropped on sight. The
  // absolute expiry is deliberately left alone: re-authenticating must not be
  // a way to stay signed in forever.
  if (resetCreatedAt) {
    getDb()
      .prepare(
        'UPDATE sessions SET token_hash = ?, csrf_token = ?, last_seen_at = ?, created_at = ? WHERE id = ?'
      )
      .run(hashToken(token), randomToken(32), now, now, sessionId);
  } else {
    getDb()
      .prepare('UPDATE sessions SET token_hash = ?, csrf_token = ?, last_seen_at = ? WHERE id = ?')
      .run(hashToken(token), randomToken(32), now, sessionId);
  }
  return { token, session: findById(sessionId) };
}

function completeMfa(sessionId) {
  getDb().prepare('UPDATE sessions SET mfa_pending = 0 WHERE id = ?').run(sessionId);
}

function grantSudo(sessionId, now = Date.now()) {
  getDb()
    .prepare('UPDATE sessions SET sudo_until = ? WHERE id = ?')
    .run(now + config.session.sudoTimeoutMs, sessionId);
}

function revokeSudo(sessionId) {
  getDb().prepare('UPDATE sessions SET sudo_until = 0 WHERE id = ?').run(sessionId);
}

function revoke(sessionId, now = Date.now()) {
  getDb().prepare('UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL').run(
    now,
    sessionId
  );
}

/** Used when a password changes, an account is disabled, or an admin cuts a
 * user off. `exceptSessionId` keeps the actor's own session alive. */
function revokeAllForUser(userId, { exceptSessionId = null, now = Date.now() } = {}) {
  return getDb()
    .prepare(
      `UPDATE sessions SET revoked_at = ?
        WHERE user_id = ? AND revoked_at IS NULL AND (? IS NULL OR id != ?)`
    )
    .run(now, userId, exceptSessionId, exceptSessionId).changes;
}

function listActiveForUser(userId, now = Date.now()) {
  return getDb()
    .prepare(
      `SELECT * FROM sessions
        WHERE user_id = ? AND revoked_at IS NULL AND absolute_expires_at > ?
          AND last_seen_at > ?
        ORDER BY last_seen_at DESC`
    )
    .all(userId, now, now - config.session.idleTimeoutMs);
}

/** Housekeeping: drop rows that can no longer authenticate anyone. */
function purgeExpired(now = Date.now()) {
  return getDb()
    .prepare(
      `DELETE FROM sessions
        WHERE absolute_expires_at <= ?
           OR (revoked_at IS NOT NULL AND revoked_at < ?)`
    )
    .run(now, now - 7 * 24 * 60 * 60 * 1000).changes;
}

module.exports = {
  create,
  findById,
  resolve,
  touch,
  rotate,
  completeMfa,
  grantSudo,
  revokeSudo,
  revoke,
  revokeAllForUser,
  listActiveForUser,
  purgeExpired,
};
