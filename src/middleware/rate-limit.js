'use strict';

const rateLimit = require('../models/rate-limit');
const audit = require('../models/audit');

/**
 * @param {string} bucket  namespace for the counter
 * @param {{limit: number, windowMs: number}} options
 * @param {(req) => string} [keyFn]  defaults to the client address
 */
function limiter(bucket, options, keyFn = (req) => req.clientIp || 'unknown') {
  return function rateLimitMiddleware(req, res, next) {
    const key = `${bucket}:${keyFn(req)}`;
    const result = rateLimit.consume(key, options);

    res.setHeader('RateLimit-Limit', String(options.limit));
    res.setHeader('RateLimit-Remaining', String(result.remaining));

    if (result.allowed) return next();

    const retryAfterSeconds = Math.max(1, Math.ceil(result.retryAfterMs / 1000));
    res.setHeader('Retry-After', String(retryAfterSeconds));

    // Only log the first rejection of a window, so a flood cannot itself be
    // used to fill the audit table.
    if (result.count === options.limit + 1) {
      audit.recordFromRequest(req, {
        event: 'ratelimit.exceeded',
        success: false,
        detail: { bucket, path: req.originalUrl.split('?')[0] },
      });
    }

    return next(
      Object.assign(new Error('Too many requests'), {
        status: 429,
        retryAfterSeconds,
      })
    );
  };
}

module.exports = { limiter };
