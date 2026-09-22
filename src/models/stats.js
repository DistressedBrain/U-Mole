'use strict';

const { getDb } = require('../db');

function overview(now = Date.now()) {
  const db = getDb();
  const one = (sql, ...params) => db.prepare(sql).get(...params).n;

  return {
    users: one('SELECT COUNT(*) AS n FROM users'),
    admins: one("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'"),
    pendingInvites: one('SELECT COUNT(*) AS n FROM users WHERE password_hash IS NULL'),
    withoutMfa: one(
      "SELECT COUNT(*) AS n FROM users WHERE totp_enabled = 0 AND status = 'active'"
    ),
    failedLogins24h: one(
      "SELECT COUNT(*) AS n FROM audit_log WHERE event = 'auth.login' AND success = 0 AND at > ?",
      now - 24 * 60 * 60 * 1000
    ),
  };
}

module.exports = { overview };
