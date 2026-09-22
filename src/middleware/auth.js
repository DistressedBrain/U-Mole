'use strict';

const config = require('../config');
const sessions = require('../models/sessions');
const users = require('../models/users');
const audit = require('../models/audit');

function sessionCookieOptions() {
  return {
    httpOnly: true,
    secure: config.session.cookieSecure,
    // Lax rather than Strict so that following a link into the site (an invite
    // email, a bookmark) does not look like a logged-out visit. Every
    // state-changing request is separately protected by the CSRF middleware.
    sameSite: 'lax',
    path: '/',
  };
}

function setSessionCookie(res, token) {
  res.cookie(config.session.cookieName, token, sessionCookieOptions());
}

function clearSessionCookie(res) {
  res.clearCookie(config.session.cookieName, sessionCookieOptions());
}

/** Only ever redirect to a path on this site. */
function safeNextPath(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 512) return null;
  // Reject protocol-relative ("//evil.com"), absolute URLs, and backslash tricks.
  if (!value.startsWith('/') || value.startsWith('//') || value.includes('\\')) return null;
  if (/[\x00-\x1f]/.test(value)) return null;
  return value;
}

/**
 * Resolve the session cookie on every request. Populates `req.session` and
 * `req.user`, and quietly drops sessions that are no longer valid.
 */
function loadSession(req, res, next) {
  req.session = null;
  req.user = null;

  const token = req.cookies ? req.cookies[config.session.cookieName] : null;
  if (!token) return next();

  const session = sessions.resolve(token);
  if (!session) {
    clearSessionCookie(res);
    return next();
  }

  const user = users.findById(session.user_id);
  if (!user || user.status !== 'active') {
    sessions.revoke(session.id);
    clearSessionCookie(res);
    return next();
  }

  // A password change invalidates every session issued before it, including
  // any an attacker was already holding.
  if (user.password_changed_at && session.created_at < user.password_changed_at) {
    sessions.revoke(session.id);
    clearSessionCookie(res);
    return next();
  }

  sessions.touch(session.id, { ip: req.clientIp, userAgent: req.get('user-agent') });
  req.session = session;
  req.user = user;
  req.sessionToken = token;
  return next();
}

/** Everything behind the login wall goes through here. */
function requireAuth(req, res, next) {
  if (!req.session || !req.user) {
    const target = safeNextPath(req.originalUrl);
    const query = target ? `?next=${encodeURIComponent(target)}` : '?msg=session_expired';
    return res.redirect(303, `/login${query}`);
  }

  // Signed in with a password but has not yet passed the second factor.
  if (req.session.mfa_pending) {
    return res.redirect(303, '/login/verify');
  }

  // Routers are mounted under prefixes, so `req.path` here is relative to the
  // mount point. Compare against the full path instead.
  const pathname = req.originalUrl.split('?')[0];

  // Two-factor authentication is mandatory; a fresh account must enrol before
  // it can reach anything else.
  if (!req.user.totp_enabled && !pathname.startsWith('/account/two-factor')) {
    return res.redirect(303, '/account/two-factor/setup');
  }

  if (req.user.must_change_password && pathname !== '/account/password') {
    return res.redirect(303, '/account/password');
  }

  return next();
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    audit.recordFromRequest(req, {
      event: 'authz.denied',
      success: false,
      detail: { path: req.originalUrl.split('?')[0], role: req.user ? req.user.role : null },
    });
    return next(Object.assign(new Error('Forbidden'), { status: 403 }));
  }
  return next();
}

/**
 * Destructive administration requires a recent password re-entry, so that a
 * briefly unattended browser cannot be used to delete accounts or hand out
 * admin rights.
 */
function requireSudo(req, res, next) {
  if (!req.session) return requireAuth(req, res, next);
  if (req.session.sudo_until > Date.now()) return next();

  // A POST cannot be replayed after the detour, so send them back to the page
  // they came from rather than to an action URL that only answers POST.
  let target = null;
  if (req.method === 'GET') {
    target = safeNextPath(req.originalUrl);
  } else {
    const referer = req.get('referer');
    if (referer) {
      try {
        const url = new URL(referer);
        if (url.origin === config.appOrigin) target = safeNextPath(url.pathname + url.search);
      } catch {
        target = null;
      }
    }
  }

  return res.redirect(303, `/sudo?next=${encodeURIComponent(target || '/admin/users')}`);
}

/** Signed-in users have no business on the login page. */
function requireGuest(req, res, next) {
  if (req.session && req.user && !req.session.mfa_pending) return res.redirect(303, '/');
  return next();
}

module.exports = {
  loadSession,
  requireAuth,
  requireAdmin,
  requireSudo,
  requireGuest,
  setSessionCookie,
  clearSessionCookie,
  safeNextPath,
};
