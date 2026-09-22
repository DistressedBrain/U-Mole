'use strict';

const { getDb } = require('../db');

/**
 * Append-only record of anything security-relevant. Written on both success
 * and failure — a log that only records successes tells you nothing after a
 * break-in.
 */
function record({
  event,
  success = true,
  actorUserId = null,
  actorEmail = '',
  targetUserId = null,
  targetEmail = '',
  ip = '',
  userAgent = '',
  detail = {},
  at = Date.now(),
}) {
  getDb()
    .prepare(
      `INSERT INTO audit_log
         (at, event, success, actor_user_id, actor_email, target_user_id, target_email, ip, user_agent, detail)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      at,
      event,
      success ? 1 : 0,
      actorUserId,
      actorEmail,
      targetUserId,
      targetEmail,
      ip,
      // Cap the stored user agent; it is attacker-controlled input.
      String(userAgent).slice(0, 255),
      JSON.stringify(detail)
    );
}

/** Convenience wrapper that fills actor/ip/user-agent in from the request. */
function recordFromRequest(req, entry) {
  record({
    actorUserId: req.user ? req.user.id : null,
    actorEmail: req.user ? req.user.email : '',
    ip: req.clientIp || '',
    userAgent: req.get ? req.get('user-agent') || '' : '',
    ...entry,
  });
}

function list({ limit = 50, offset = 0, event = null, search = null } = {}) {
  const clauses = [];
  const params = [];

  if (event) {
    clauses.push('event = ?');
    params.push(event);
  }
  if (search) {
    clauses.push('(actor_email LIKE ? OR target_email LIKE ? OR ip LIKE ?)');
    const like = `%${search}%`;
    params.push(like, like, like);
  }

  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  const rows = getDb()
    .prepare(`SELECT * FROM audit_log ${where} ORDER BY at DESC, id DESC LIMIT ? OFFSET ?`)
    .all(...params, limit, offset);
  const total = getDb()
    .prepare(`SELECT COUNT(*) AS n FROM audit_log ${where}`)
    .get(...params).n;

  return { rows, total };
}

function distinctEvents() {
  return getDb()
    .prepare('SELECT DISTINCT event FROM audit_log ORDER BY event')
    .all()
    .map((row) => row.event);
}

module.exports = { record, recordFromRequest, list, distinctEvents };
