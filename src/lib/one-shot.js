'use strict';

/**
 * A tiny in-memory, single-use store for values that must be shown to the user
 * exactly once and never written down: invite links, password-reset links and
 * freshly generated recovery codes.
 *
 * Keeping them here rather than in the database or the URL means the secret
 * exists in one process's memory for a couple of minutes and nowhere else —
 * not in the query string, not in access logs, not in a backup.
 *
 * Note: this is per-process. If you run several workers behind a load
 * balancer, pin the admin's session to one worker or accept that the reveal
 * page may come up empty (the action itself still succeeded).
 */
const TTL_MS = 5 * 60 * 1000;
const store = new Map();

function put(key, value, ttlMs = TTL_MS) {
  store.set(key, { value, expiresAt: Date.now() + ttlMs });
}

function take(key) {
  const entry = store.get(key);
  store.delete(key);
  if (!entry || entry.expiresAt <= Date.now()) return null;
  return entry.value;
}

function sweep(now = Date.now()) {
  for (const [key, entry] of store) {
    if (entry.expiresAt <= now) store.delete(key);
  }
}

module.exports = { put, take, sweep, TTL_MS };
