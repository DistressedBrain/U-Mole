'use strict';

const express = require('express');
const QRCode = require('qrcode');

const config = require('../config');
const users = require('../models/users');
const sessions = require('../models/sessions');
const audit = require('../models/audit');
const oneShot = require('../lib/one-shot');
const { limiter } = require('../middleware/rate-limit');
const { requireAuth, requireSudo, setSessionCookie } = require('../middleware/auth');
const { verifyPassword, hashPassword, checkPasswordStrength } = require('../lib/password');
const { generateSecret, verifyTotp, otpauthUri } = require('../lib/totp');
const { lookup } = require('../lib/messages');
const views = require('../views/account');
const { errorPage } = require('../views/error');

const router = express.Router();

router.use(requireAuth);

function viewUser(req) {
  return { ...req.user, csrfToken: req.session.csrf_token };
}

/* ------------------------------------------------------------------ */
/* Overview and profile                                                */
/* ------------------------------------------------------------------ */

router.get('/', (req, res) => {
  res.send(
    views.accountPage({
      user: viewUser(req),
      csrfToken: req.session.csrf_token,
      sessions: sessions.listActiveForUser(req.user.id),
      currentSessionId: req.session.id,
      recoveryCodesLeft: users.countUnusedRecoveryCodes(req.user.id),
      flash: lookup(req.query.msg),
    })
  );
});

router.post('/profile', (req, res) => {
  const name = typeof req.body.name === 'string' ? req.body.name.trim().slice(0, 120) : '';
  users.setProfile(req.user.id, { name });
  audit.recordFromRequest(req, {
    event: 'account.profile_updated',
    targetUserId: req.user.id,
    targetEmail: req.user.email,
  });
  res.redirect(303, '/account?msg=profile_updated');
});

/* ------------------------------------------------------------------ */
/* Password                                                            */
/* ------------------------------------------------------------------ */

router.get('/password', (req, res) => {
  res.send(
    views.passwordPage({
      user: viewUser(req),
      csrfToken: req.session.csrf_token,
      minLength: config.password.minLength,
      forced: Boolean(req.user.must_change_password),
    })
  );
});

router.post(
  '/password',
  limiter('password-change', config.rateLimits.sensitive, (req) => `${req.user.id}`),
  async (req, res, next) => {
    const current = typeof req.body.current === 'string' ? req.body.current : '';
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    const confirm = typeof req.body.confirm === 'string' ? req.body.confirm : '';

    const reject = (errors, status = 400) =>
      res.status(status).send(
        views.passwordPage({
          user: viewUser(req),
          csrfToken: req.session.csrf_token,
          minLength: config.password.minLength,
          forced: Boolean(req.user.must_change_password),
          errors,
        })
      );

    try {
      const { valid } = await verifyPassword(req.user.password_hash, current);
      if (!valid) {
        audit.recordFromRequest(req, { event: 'account.password_change', success: false });
        return reject(['Your current password was not accepted.'], 401);
      }

      const errors = checkPasswordStrength(password, {
        email: req.user.email,
        name: req.user.name,
      });
      if (password !== confirm) errors.push('The two new passwords do not match.');
      if (password === current) errors.push('The new password must be different from the old one.');
      if (errors.length) return reject(errors);

      users.setPassword(req.user.id, await hashPassword(password));

      // Everything else the account had open is cut off — if someone else was
      // riding this account, the password change ends it.
      sessions.revokeAllForUser(req.user.id, { exceptSessionId: req.session.id });
      const { token } = sessions.rotate(req.session.id, { resetCreatedAt: true });
      setSessionCookie(res, token);

      audit.recordFromRequest(req, {
        event: 'account.password_change',
        success: true,
        targetUserId: req.user.id,
        targetEmail: req.user.email,
      });

      return res.redirect(303, '/account?msg=password_updated');
    } catch (error) {
      return next(error);
    }
  }
);

/* ------------------------------------------------------------------ */
/* Two-factor authentication                                           */
/* ------------------------------------------------------------------ */

router.get('/two-factor/setup', async (req, res, next) => {
  if (req.user.totp_enabled) return res.redirect(303, '/account');

  try {
    // Reuse a secret that was already handed out, so refreshing the page does
    // not orphan the entry the user has just scanned.
    let secret = users.getTotpSecret(req.user);
    if (!secret) {
      secret = generateSecret();
      users.setTotpSecret(req.user.id, secret);
    }

    const uri = otpauthUri(secret, req.user.email);
    const qrSvg = await QRCode.toString(uri, { type: 'svg', margin: 1, width: 220 });

    return res.send(
      views.twoFactorSetupPage({
        user: viewUser(req),
        csrfToken: req.session.csrf_token,
        qrSvg,
        secret,
      })
    );
  } catch (error) {
    return next(error);
  }
});

router.post(
  '/two-factor/setup',
  limiter('totp-enrol', config.rateLimits.mfa, (req) => `${req.user.id}`),
  async (req, res, next) => {
    if (req.user.totp_enabled) return res.redirect(303, '/account');

    try {
      const secret = users.getTotpSecret(req.user);
      if (!secret) return res.redirect(303, '/account/two-factor/setup');

      const step = verifyTotp(secret, req.body.code, { lastUsedStep: req.user.totp_last_step });
      if (step === null) {
        audit.recordFromRequest(req, { event: 'account.mfa_enrol', success: false });
        const uri = otpauthUri(secret, req.user.email);
        const qrSvg = await QRCode.toString(uri, { type: 'svg', margin: 1, width: 220 });
        return res.status(400).send(
          views.twoFactorSetupPage({
            user: viewUser(req),
            csrfToken: req.session.csrf_token,
            qrSvg,
            secret,
            errors: [
              'That code did not match. Check your device clock is correct and try the next code.',
            ],
          })
        );
      }

      users.setTotpLastStep(req.user.id, step);
      users.enableTotp(req.user.id);
      const codes = users.generateRecoveryCodes(req.user.id);

      // Enrolment raises the security level of the session.
      const { token } = sessions.rotate(req.session.id);
      setSessionCookie(res, token);

      audit.recordFromRequest(req, {
        event: 'account.mfa_enrol',
        success: true,
        targetUserId: req.user.id,
        targetEmail: req.user.email,
      });

      // Held in memory only, shown once, never written anywhere.
      oneShot.put(`codes:${req.session.id}`, codes);
      return res.redirect(303, '/account/two-factor/recovery-codes');
    } catch (error) {
      return next(error);
    }
  }
);

router.get('/two-factor/recovery-codes', (req, res) => {
  const codes = oneShot.take(`codes:${req.session.id}`);
  if (!codes) {
    return res.status(404).send(
      errorPage({
        status: 404,
        user: viewUser(req),
        hint: 'Recovery codes are shown once only. Generate a fresh set from your account page.',
      })
    );
  }
  return res.send(views.recoveryCodesPage({ user: viewUser(req), codes }));
});

router.post(
  '/two-factor/recovery-codes',
  // These codes stand in for the second factor indefinitely, so minting a new
  // set is treated like any other credential change: the password, again, now.
  requireSudo,
  limiter('recovery-regen', config.rateLimits.sensitive, (req) => `${req.user.id}`),
  (req, res) => {
    if (!req.user.totp_enabled) return res.redirect(303, '/account/two-factor/setup');

    const codes = users.generateRecoveryCodes(req.user.id);
    audit.recordFromRequest(req, {
      event: 'account.recovery_codes_regenerated',
      targetUserId: req.user.id,
      targetEmail: req.user.email,
    });
    oneShot.put(`codes:${req.session.id}`, codes);
    res.redirect(303, '/account/two-factor/recovery-codes');
  }
);

/* ------------------------------------------------------------------ */
/* Sessions                                                            */
/* ------------------------------------------------------------------ */

router.post('/sessions/revoke', (req, res) => {
  const sessionId = Number.parseInt(req.body.session_id, 10);
  const target = Number.isFinite(sessionId) ? sessions.findById(sessionId) : null;

  // Only ever your own sessions, and never the one making the request.
  if (!target || target.user_id !== req.user.id || target.id === req.session.id) {
    return res
      .status(400)
      .send(errorPage({ status: 400, user: viewUser(req), hint: 'That session is not yours.' }));
  }

  sessions.revoke(target.id);
  audit.recordFromRequest(req, {
    event: 'account.session_revoked',
    targetUserId: req.user.id,
    targetEmail: req.user.email,
    detail: { session_id: target.id },
  });
  return res.redirect(303, '/account?msg=session_revoked');
});

router.post('/sessions/revoke-others', (req, res) => {
  const count = sessions.revokeAllForUser(req.user.id, { exceptSessionId: req.session.id });
  audit.recordFromRequest(req, {
    event: 'account.sessions_revoked',
    targetUserId: req.user.id,
    targetEmail: req.user.email,
    detail: { revoked: count },
  });
  res.redirect(303, '/account?msg=sessions_revoked');
});

module.exports = router;
