'use strict';

const sessions = require('./models/sessions');
const authTokens = require('./models/auth-tokens');
const rateLimit = require('./models/rate-limit');
const oneShot = require('./lib/one-shot');

const INTERVAL_MS = 15 * 60 * 1000;

/** Drop rows that can no longer authenticate anybody. */
function sweep() {
  const removed = {
    sessions: sessions.purgeExpired(),
    tokens: authTokens.purgeExpired(),
    rateLimits: rateLimit.purgeExpired(),
  };
  oneShot.sweep();
  return removed;
}

function start(intervalMs = INTERVAL_MS) {
  sweep();
  const timer = setInterval(() => {
    try {
      sweep();
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error('[housekeeping]', error);
    }
  }, intervalMs);
  // Never hold the process open just to run cleanup.
  timer.unref();
  return timer;
}

module.exports = { sweep, start, INTERVAL_MS };
