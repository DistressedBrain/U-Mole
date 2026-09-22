'use strict';

const { getDb } = require('../db');

/**
 * Fixed-window counter kept in SQLite so that limits survive a restart and are
 * shared by every worker process pointing at the same database.
 */
function consume(key, { limit, windowMs }, now = Date.now()) {
  const db = getDb();
  const windowStart = now - (now % windowMs);

  const run = db.transaction(() => {
    const row = db.prepare('SELECT count, window_start FROM rate_limits WHERE key = ?').get(key);

    if (!row || row.window_start !== windowStart) {
      db.prepare(
        `INSERT INTO rate_limits (key, count, window_start) VALUES (?, 1, ?)
         ON CONFLICT(key) DO UPDATE SET count = 1, window_start = excluded.window_start`
      ).run(key, windowStart);
      return 1;
    }

    const next = row.count + 1;
    db.prepare('UPDATE rate_limits SET count = ? WHERE key = ?').run(next, key);
    return next;
  });

  const count = run();
  const allowed = count <= limit;
  return {
    allowed,
    count,
    remaining: Math.max(0, limit - count),
    retryAfterMs: allowed ? 0 : windowStart + windowMs - now,
  };
}

/** Drop a counter — used after a successful login so one user's typos do not
 * keep counting against them. */
function reset(key) {
  getDb().prepare('DELETE FROM rate_limits WHERE key = ?').run(key);
}

/** Remove windows that can no longer be current. */
function purgeExpired(olderThanMs = 24 * 60 * 60 * 1000, now = Date.now()) {
  return getDb().prepare('DELETE FROM rate_limits WHERE window_start < ?').run(now - olderThanMs)
    .changes;
}

module.exports = { consume, reset, purgeExpired };
