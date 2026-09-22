'use strict';

const express = require('express');

const config = require('../config');
const users = require('../models/users');
const sessions = require('../models/sessions');
const authTokens = require('../models/auth-tokens');
const audit = require('../models/audit');
const rateLimit = require('../models/rate-limit');
const { limiter } = require('../middleware/rate-limit');
const {
  requireGuest,
  requireAuth,
  setSessionCookie,
  clearSessionCookie,
  safeNextPath,
} = require('../middleware/auth');
const { verifyPassword, burnVerifyTime, checkPasswordStrength, hashPassword } = require('../lib/password');
const { verifyTotp } = require('../lib/totp');
const { lookup } = require('../lib/messages');
const views = require('../views/auth');
const { errorPage } = require('../views/error');

const router = express.Router();

/**
 * One message for every way a sign-in can fail. Telling the difference between
 * "no such account", "wrong password", "disabled" and "locked" would let
 * anyone enumerate who has an account here.
 */
const GENERIC_LOGIN_FAILURE =
  'Incorrect email address or password, or the account is unavailable. ' +
  'After several failed attempts an account is locked for a while.';

function flashFrom(req) {
  return lookup(req.query.msg);
}

/* ------------------------------------------------------------------ */
/* Sign in                                                             */
/* ------------------------------------------------------------------ */

router.get('/login', requireGuest, (req, res) => {
  res.send(
    views.loginPage({
      csrfToken: req.csrfToken(),
      next: safeNextPath(req.query.next) || '',
      flash: flashFrom(req),
    })
  );
});

router.post(
  '/login',
  requireGuest,
  limiter('login-ip', config.rateLimits.login),
  async (req, res, next) => {
    const email = users.normaliseEmail(req.body.email);
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    const nextPath = safeNextPath(req.body.next) || '';

    const fail = (reason, user = null) => {
      audit.record({
        event: 'auth.login',
        success: false,
        targetUserId: user ? user.id : null,
        targetEmail: email,
        ip: req.clientIp,
        userAgent: req.get('user-agent') || '',
        detail: { reason },
      });
      // Same status, same body, same timing, whatever went wrong.
      res.status(401).send(
        views.loginPage({
          csrfToken: req.csrfToken(),
          email,
          next: nextPath,
          errors: [GENERIC_LOGIN_FAILURE],
        })
      );
    };

    try {
      if (!email || !password) {
        await burnVerifyTime(password);
        return fail('missing_credentials');
      }

      // A second limiter keyed on the account, so one attacker spraying from
      // many addresses still cannot hammer a single inbox.
      const perAccount = rateLimit.consume(`login-account:${email}`, config.rateLimits.login);
      if (!perAccount.allowed) {
        await burnVerifyTime(password);
        return fail('account_rate_limited');
      }

      const user = users.findByEmail(email);
      if (!user) {
        // Verify against a decoy hash so that a missing account takes as long
        // as a real one — otherwise response time reveals who is registered.
        await burnVerifyTime(password);
        return fail('unknown_account');
      }
      if (user.status !== 'active') {
        await burnVerifyTime(password);
        return fail('disabled', user);
      }
      if (users.isLocked(user)) {
        await burnVerifyTime(password);
        return fail('locked', user);
      }
      if (!user.password_hash) {
        await burnVerifyTime(password);
        return fail('invite_not_redeemed', user);
      }

      const { valid, needsRehash } = await verifyPassword(user.password_hash, password);
      if (!valid) {
        users.recordLoginFailure(user.id);
        return fail('bad_password', user);
      }

      // Transparently upgrade hashes when the cost parameters change.
      if (needsRehash) {
        users.setPassword(user.id, await hashPassword(password), {
          mustChangePassword: user.must_change_password,
        });
      } else {
        users.clearLockout(user.id);
      }
      rateLimit.reset(`login-account:${email}`);

      // Any session the browser already carried is discarded, and a brand new
      // identifier is issued: session fixation has nothing to latch onto.
      if (req.session) sessions.revoke(req.session.id);

      const mfaPending = Boolean(user.totp_enabled);
      const { token } = sessions.create({
        userId: user.id,
        ip: req.clientIp,
        userAgent: req.get('user-agent') || '',
        mfaPending,
      });
      setSessionCookie(res, token);

      audit.record({
        event: 'auth.password_ok',
        success: true,
        actorUserId: user.id,
        actorEmail: user.email,
        targetUserId: user.id,
        targetEmail: user.email,
        ip: req.clientIp,
        userAgent: req.get('user-agent') || '',
        detail: { mfa_required: mfaPending },
      });

      if (mfaPending) {
        const query = nextPath ? `?next=${encodeURIComponent(nextPath)}` : '';
        return res.redirect(303, `/login/verify${query}`);
      }

      users.recordLoginSuccess(user.id);
      return res.redirect(303, nextPath || '/');
    } catch (error) {
      return next(error);
    }
  }
);

/* ------------------------------------------------------------------ */
/* Second factor                                                       */
/* ------------------------------------------------------------------ */

function requirePendingMfa(req, res, next) {
  if (!req.session || !req.user) return res.redirect(303, '/login?msg=session_expired');
  if (!req.session.mfa_pending) return res.redirect(303, '/');
  return next();
}

router.get('/login/verify', requirePendingMfa, (req, res) => {
  res.send(
    views.verifyPage({
      csrfToken: req.csrfToken(),
      mode: req.query.mode === 'recovery' ? 'recovery' : 'totp',
      next: safeNextPath(req.query.next) || '',
    })
  );
});

router.post(
  '/login/verify',
  requirePendingMfa,
  limiter('mfa-ip', config.rateLimits.mfa),
  (req, res) => {
    const mode = req.body.mode === 'recovery' ? 'recovery' : 'totp';
    const nextPath = safeNextPath(req.body.next) || '/';
    const user = req.user;

    const perAccount = rateLimit.consume(`mfa-account:${user.id}`, config.rateLimits.mfa);

    const fail = (reason) => {
      audit.record({
        event: 'auth.mfa',
        success: false,
        actorUserId: user.id,
        actorEmail: user.email,
        targetUserId: user.id,
        targetEmail: user.email,
        ip: req.clientIp,
        userAgent: req.get('user-agent') || '',
        detail: { reason, mode },
      });
      // Repeated second-factor failures count towards the account lockout too,
      // so a stolen password plus code guessing still hits a wall.
      users.recordLoginFailure(user.id);
      res.status(401).send(
        views.verifyPage({
          csrfToken: req.csrfToken(),
          mode,
          next: nextPath === '/' ? '' : nextPath,
          errors: ['That code was not accepted. Check your authenticator and try again.'],
        })
      );
    };

    if (!perAccount.allowed) return fail('rate_limited');

    let usedRecoveryCode = false;

    if (mode === 'recovery') {
      if (!users.consumeRecoveryCode(user.id, req.body.recovery)) return fail('bad_recovery_code');
      usedRecoveryCode = true;
    } else {
      const secret = users.getTotpSecret(user);
      if (!secret) return fail('no_secret');
      const step = verifyTotp(secret, req.body.code, { lastUsedStep: user.totp_last_step });
      if (step === null) return fail('bad_code');
      // Remember the step so the same code cannot be replayed inside its
      // 90-second validity window.
      users.setTotpLastStep(user.id, step);
    }

    sessions.completeMfa(req.session.id);
    // Privilege just increased: issue a new session identifier.
    const { token } = sessions.rotate(req.session.id);
    setSessionCookie(res, token);
    users.recordLoginSuccess(user.id);
    rateLimit.reset(`mfa-account:${user.id}`);

    audit.record({
      event: 'auth.login',
      success: true,
      actorUserId: user.id,
      actorEmail: user.email,
      targetUserId: user.id,
      targetEmail: user.email,
      ip: req.clientIp,
      userAgent: req.get('user-agent') || '',
      detail: { method: usedRecoveryCode ? 'recovery_code' : 'totp' },
    });

    const separator = nextPath.includes('?') ? '&' : '?';
    return res.redirect(
      303,
      usedRecoveryCode ? `${nextPath}${separator}msg=recovery_code_used` : nextPath
    );
  }
);

/* ------------------------------------------------------------------ */
/* Sign out                                                            */
/* ------------------------------------------------------------------ */

router.post('/logout', (req, res) => {
  if (req.session) {
    sessions.revoke(req.session.id);
    audit.record({
      event: 'auth.logout',
      actorUserId: req.user ? req.user.id : null,
      actorEmail: req.user ? req.user.email : '',
      ip: req.clientIp,
      userAgent: req.get('user-agent') || '',
    });
  }
  clearSessionCookie(res);
  res.redirect(303, '/login?msg=signed_out');
});

/* ------------------------------------------------------------------ */
/* Invite redemption and password reset                                */
/* ------------------------------------------------------------------ */

function tokenLandingPage(purpose) {
  return function handler(req, res) {
    const token = typeof req.query.token === 'string' ? req.query.token : '';
    const row = authTokens.peek(token, purpose);
    if (!row) {
      return res.status(400).send(
        errorPage({
          status: 400,
          hint:
            'That link is not valid any more. Links can be used once and expire ' +
            `after ${Math.round(config.invites.ttlMs / 3600000)} hours — ask an administrator for a new one.`,
        })
      );
    }
    const target = users.findById(row.user_id);
    return res.send(
      views.setPasswordPage({
        csrfToken: req.csrfToken(),
        token,
        purpose,
        email: target ? target.email : '',
        minLength: config.password.minLength,
      })
    );
  };
}

function tokenSubmitHandler(purpose) {
  return async function handler(req, res, next) {
    const token = typeof req.body.token === 'string' ? req.body.token : '';
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    const confirm = typeof req.body.confirm === 'string' ? req.body.confirm : '';

    try {
      const row = authTokens.peek(token, purpose);
      if (!row) {
        return res.status(400).send(
          errorPage({ status: 400, hint: 'That link is not valid any more. Ask for a new one.' })
        );
      }
      const target = users.findById(row.user_id);
      if (!target || target.status !== 'active') {
        return res
          .status(400)
          .send(errorPage({ status: 400, hint: 'That account is not available.' }));
      }

      const errors = checkPasswordStrength(password, { email: target.email, name: target.name });
      if (password !== confirm) errors.push('The two passwords do not match.');

      if (errors.length) {
        return res.status(400).send(
          views.setPasswordPage({
            csrfToken: req.csrfToken(),
            token,
            purpose,
            email: target.email,
            errors,
            minLength: config.password.minLength,
          })
        );
      }

      // Spend the token only once the new password has passed every check,
      // and only via the atomic redeem so two submissions cannot both win.
      const redeemed = authTokens.redeem(token, purpose);
      if (!redeemed) {
        return res.status(400).send(
          errorPage({ status: 400, hint: 'That link has already been used. Ask for a new one.' })
        );
      }

      users.setPassword(target.id, await hashPassword(password));

      if (purpose === 'reset') {
        // A reset link is a credential someone may have intercepted. Cut every
        // existing session, and make them sign in again — which still means
        // passing the second factor.
        sessions.revokeAllForUser(target.id);
        audit.record({
          event: 'auth.password_reset',
          actorUserId: target.id,
          actorEmail: target.email,
          targetUserId: target.id,
          targetEmail: target.email,
          ip: req.clientIp,
          userAgent: req.get('user-agent') || '',
        });
        clearSessionCookie(res);
        return res.redirect(303, '/login?msg=password_set');
      }

      // Invite: sign them in so they can enrol a second factor, which
      // `requireAuth` forces before anything else is reachable.
      if (req.session) sessions.revoke(req.session.id);
      const { token: sessionToken } = sessions.create({
        userId: target.id,
        ip: req.clientIp,
        userAgent: req.get('user-agent') || '',
        mfaPending: false,
      });
      setSessionCookie(res, sessionToken);
      users.recordLoginSuccess(target.id);

      audit.record({
        event: 'auth.invite_redeemed',
        actorUserId: target.id,
        actorEmail: target.email,
        targetUserId: target.id,
        targetEmail: target.email,
        ip: req.clientIp,
        userAgent: req.get('user-agent') || '',
      });

      return res.redirect(303, '/account/two-factor/setup');
    } catch (error) {
      return next(error);
    }
  };
}

const tokenLimiter = limiter('token-redeem', config.rateLimits.tokenRedeem);

router.get('/activate', tokenLimiter, tokenLandingPage('invite'));
router.post('/activate', tokenLimiter, tokenSubmitHandler('invite'));
router.get('/reset', tokenLimiter, tokenLandingPage('reset'));
router.post('/reset', tokenLimiter, tokenSubmitHandler('reset'));

/* ------------------------------------------------------------------ */
/* Re-authentication for sensitive actions                             */
/* ------------------------------------------------------------------ */

router.get('/sudo', requireAuth, (req, res) => {
  res.send(
    views.sudoPage({
      csrfToken: req.csrfToken(),
      next: safeNextPath(req.query.next) || '/admin/users',
      user: { ...req.user, csrfToken: req.csrfToken() },
    })
  );
});

router.post(
  '/sudo',
  requireAuth,
  limiter('sudo', config.rateLimits.sensitive, (req) => `${req.user.id}`),
  async (req, res, next) => {
    const target = safeNextPath(req.body.next) || '/admin/users';
    try {
      const password = typeof req.body.password === 'string' ? req.body.password : '';
      const { valid } = await verifyPassword(req.user.password_hash, password);

      if (!valid) {
        audit.recordFromRequest(req, { event: 'auth.sudo', success: false });
        return res.status(401).send(
          views.sudoPage({
            csrfToken: req.csrfToken(),
            next: target,
            errors: ['That password was not accepted.'],
            user: { ...req.user, csrfToken: req.csrfToken() },
          })
        );
      }

      // The session is about to gain elevated rights, so give it a new
      // identifier first, then attach the grant to it.
      const { token } = sessions.rotate(req.session.id);
      sessions.grantSudo(req.session.id);
      setSessionCookie(res, token);
      audit.recordFromRequest(req, { event: 'auth.sudo', success: true });

      return res.redirect(303, target);
    } catch (error) {
      return next(error);
    }
  }
);

module.exports = router;
