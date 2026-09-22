'use strict';

const config = require('../config');
const { randomToken, timingSafeEqualStrings } = require('../lib/crypto');

const ANON_COOKIE = config.session.cookieSecure ? '__Host-umole_csrf' : 'umole_csrf';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function cookieOptions() {
  return {
    httpOnly: true,
    secure: config.session.cookieSecure,
    sameSite: 'strict',
    path: '/',
  };
}

/**
 * Two independent defences, because either one alone has known gaps:
 *
 *  1. Origin/Referer must match this site. Browsers set these on every
 *     cross-site form post and scripts cannot forge them.
 *  2. A secret token must accompany the request. Logged-in users get a
 *     per-session token; anonymous visitors (the login and invite forms) get a
 *     double-submit cookie, which a cross-site attacker cannot read.
 */
function csrfProtection(req, res, next) {
  // Make a token available to every template.
  req.csrfToken = function csrfToken() {
    if (req.session) return req.session.csrf_token;
    let token = req.cookies ? req.cookies[ANON_COOKIE] : null;
    if (!token || typeof token !== 'string' || token.length < 32) {
      token = randomToken(32);
      res.cookie(ANON_COOKIE, token, cookieOptions());
      req.cookies[ANON_COOKIE] = token;
    }
    return token;
  };

  if (SAFE_METHODS.has(req.method)) return next();

  const origin = req.get('origin');
  const referer = req.get('referer');
  let sourceOrigin = null;
  if (origin && origin !== 'null') {
    sourceOrigin = origin;
  } else if (referer) {
    try {
      sourceOrigin = new URL(referer).origin;
    } catch {
      sourceOrigin = null;
    }
  }

  if (sourceOrigin !== config.appOrigin) {
    return next(Object.assign(new Error('Cross-origin form submission rejected'), { status: 403 }));
  }

  const submitted =
    (req.body && typeof req.body._csrf === 'string' && req.body._csrf) ||
    req.get('x-csrf-token') ||
    '';
  const expected = req.session ? req.session.csrf_token : req.cookies[ANON_COOKIE];

  if (!expected || !timingSafeEqualStrings(submitted, expected)) {
    return next(
      Object.assign(new Error('Invalid or missing CSRF token'), { status: 403, csrf: true })
    );
  }

  return next();
}

module.exports = { csrfProtection, ANON_COOKIE };
