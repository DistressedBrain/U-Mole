'use strict';

const crypto = require('node:crypto');

const config = require('../config');
const { getDb } = require('../db');
const { randomToken, hashToken, encryptSecret, decryptSecret } = require('../lib/crypto');

const USER_COLUMNS = `
  id, public_id, email, name, password_hash, role, status,
  totp_secret, totp_enabled, totp_last_step, must_change_password,
  failed_login_count, locked_until, password_changed_at, last_login_at,
  created_at, updated_at, created_by
`;

function normaliseEmail(email) {
  return String(email || '')
    .trim()
    .toLowerCase();
}

function create({ email, name = '', role = 'user', createdBy = null }) {
  const now = Date.now();
  const db = getDb();
  const info = db
    .prepare(
      `INSERT INTO users (public_id, email, name, role, status, created_at, updated_at, created_by)
       VALUES (?, ?, ?, ?, 'active', ?, ?, ?)`
    )
    .run(randomToken(16), normaliseEmail(email), String(name).trim(), role, now, now, createdBy);
  return findById(info.lastInsertRowid);
}

function findById(id) {
  return getDb().prepare(`SELECT ${USER_COLUMNS} FROM users WHERE id = ?`).get(id) || null;
}

function findByPublicId(publicId) {
  return (
    getDb().prepare(`SELECT ${USER_COLUMNS} FROM users WHERE public_id = ?`).get(String(publicId)) ||
    null
  );
}

function findByEmail(email) {
  return (
    getDb().prepare(`SELECT ${USER_COLUMNS} FROM users WHERE email = ?`).get(normaliseEmail(email)) ||
    null
  );
}

function list({ search = '', limit = 25, offset = 0 } = {}) {
  const db = getDb();
  const where = search ? 'WHERE email LIKE ? OR name LIKE ?' : '';
  const params = search ? [`%${search}%`, `%${search}%`] : [];
  const rows = db
    .prepare(`SELECT ${USER_COLUMNS} FROM users ${where} ORDER BY email LIMIT ? OFFSET ?`)
    .all(...params, limit, offset);
  const total = db.prepare(`SELECT COUNT(*) AS n FROM users ${where}`).get(...params).n;
  return { rows, total };
}

/** Admins who could actually log in right now. */
function countUsableAdmins(excludeUserId = null) {
  return getDb()
    .prepare(
      `SELECT COUNT(*) AS n FROM users
        WHERE role = 'admin' AND status = 'active' AND password_hash IS NOT NULL
          AND (? IS NULL OR id != ?)`
    )
    .get(excludeUserId, excludeUserId).n;
}

function touch(id, fields) {
  const keys = Object.keys(fields);
  if (keys.length === 0) return findById(id);
  const assignments = keys.map((key) => `${key} = ?`).join(', ');
  getDb()
    .prepare(`UPDATE users SET ${assignments}, updated_at = ? WHERE id = ?`)
    .run(...keys.map((key) => fields[key]), Date.now(), id);
  return findById(id);
}

function setPassword(id, passwordHash, { mustChangePassword = 0 } = {}) {
  return touch(id, {
    password_hash: passwordHash,
    password_changed_at: Date.now(),
    must_change_password: mustChangePassword ? 1 : 0,
    failed_login_count: 0,
    locked_until: 0,
  });
}

function setProfile(id, { name, email }) {
  const fields = {};
  if (name !== undefined) fields.name = String(name).trim();
  if (email !== undefined) fields.email = normaliseEmail(email);
  return touch(id, fields);
}

function setRole(id, role) {
  return touch(id, { role });
}

function setStatus(id, status) {
  return touch(id, { status });
}

function remove(id) {
  getDb().prepare('DELETE FROM users WHERE id = ?').run(id);
}

/* ------------------------------------------------------------------ */
/* Lockout                                                             */
/* ------------------------------------------------------------------ */

function isLocked(user, now = Date.now()) {
  return Boolean(user) && user.locked_until > now;
}

/**
 * Record a failed password attempt. Lock duration doubles for each failure
 * past the threshold, capped, so an automated guesser is slowed to a crawl
 * while a genuine user who mistypes twice is unaffected.
 */
function recordLoginFailure(id, now = Date.now()) {
  const user = findById(id);
  if (!user) return null;

  const failures = user.failed_login_count + 1;
  let lockedUntil = user.locked_until;

  if (failures >= config.lockout.threshold) {
    const overshoot = failures - config.lockout.threshold;
    const duration = Math.min(
      config.lockout.baseLockMs * 2 ** overshoot,
      config.lockout.maxLockMs
    );
    lockedUntil = now + duration;
  }

  return touch(id, { failed_login_count: failures, locked_until: lockedUntil });
}

function recordLoginSuccess(id, now = Date.now()) {
  return touch(id, { failed_login_count: 0, locked_until: 0, last_login_at: now });
}

function clearLockout(id) {
  return touch(id, { failed_login_count: 0, locked_until: 0 });
}

/* ------------------------------------------------------------------ */
/* TOTP                                                                */
/* ------------------------------------------------------------------ */

/** Stored encrypted; a database copy alone does not yield working codes. */
function setTotpSecret(id, secret) {
  return touch(id, { totp_secret: secret === null ? null : encryptSecret(secret) });
}

function getTotpSecret(user) {
  if (!user || !user.totp_secret) return null;
  return decryptSecret(user.totp_secret);
}

function enableTotp(id) {
  return touch(id, { totp_enabled: 1 });
}

function disableTotp(id) {
  return touch(id, { totp_enabled: 0, totp_secret: null, totp_last_step: 0 });
}

function setTotpLastStep(id, step) {
  return touch(id, { totp_last_step: step });
}

/* ------------------------------------------------------------------ */
/* Recovery codes                                                      */
/* ------------------------------------------------------------------ */

const RECOVERY_CODE_COUNT = 10;

function formatRecoveryCode(raw) {
  // 5-5 grouping of Crockford-ish characters: easy to transcribe, ~50 bits.
  return `${raw.slice(0, 5)}-${raw.slice(5, 10)}`;
}

function generateRecoveryCodes(id) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const codes = [];
  for (let i = 0; i < RECOVERY_CODE_COUNT; i += 1) {
    let raw = '';
    while (raw.length < 10) {
      // Rejection sampling keeps the distribution uniform across the alphabet.
      const byte = crypto.randomBytes(1)[0];
      if (byte < 256 - (256 % alphabet.length)) {
        raw += alphabet[byte % alphabet.length];
      }
    }
    codes.push(formatRecoveryCode(raw));
  }

  const db = getDb();
  const replace = db.transaction(() => {
    db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(id);
    const insert = db.prepare('INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)');
    for (const code of codes) insert.run(id, hashToken(code));
  });
  replace();

  return codes;
}

/**
 * Spend a recovery code. Codes are single-use; the row is marked rather than
 * deleted so the audit trail can show how many are gone.
 */
function consumeRecoveryCode(id, submitted) {
  const normalised = String(submitted || '')
    .trim()
    .toUpperCase()
    .replace(/\s/g, '');
  if (!/^[A-Z0-9]{5}-[A-Z0-9]{5}$/.test(normalised)) return false;

  const db = getDb();
  const spend = db.transaction(() => {
    const row = db
      .prepare(
        'SELECT id FROM recovery_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL'
      )
      .get(id, hashToken(normalised));
    if (!row) return false;
    db.prepare('UPDATE recovery_codes SET used_at = ? WHERE id = ?').run(Date.now(), row.id);
    return true;
  });
  return spend();
}

function countUnusedRecoveryCodes(id) {
  return getDb()
    .prepare('SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = ? AND used_at IS NULL')
    .get(id).n;
}

function clearRecoveryCodes(id) {
  getDb().prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(id);
}

module.exports = {
  normaliseEmail,
  create,
  findById,
  findByPublicId,
  findByEmail,
  list,
  countUsableAdmins,
  setPassword,
  setProfile,
  setRole,
  setStatus,
  remove,
  isLocked,
  recordLoginFailure,
  recordLoginSuccess,
  clearLockout,
  setTotpSecret,
  getTotpSecret,
  enableTotp,
  disableTotp,
  setTotpLastStep,
  generateRecoveryCodes,
  consumeRecoveryCode,
  countUnusedRecoveryCodes,
  clearRecoveryCodes,
  RECOVERY_CODE_COUNT,
};
