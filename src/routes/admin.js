'use strict';

const express = require('express');

const config = require('../config');
const users = require('../models/users');
const sessions = require('../models/sessions');
const authTokens = require('../models/auth-tokens');
const audit = require('../models/audit');
const oneShot = require('../lib/one-shot');
const { limiter } = require('../middleware/rate-limit');
const { requireAuth, requireAdmin, requireSudo } = require('../middleware/auth');
const { lookup } = require('../lib/messages');
const views = require('../views/admin');
const { errorPage } = require('../views/error');

const router = express.Router();

router.use(requireAuth, requireAdmin);
router.use(limiter('admin', config.rateLimits.sensitive, (req) => `${req.user.id}`));

const PAGE_SIZE = 25;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function viewUser(req) {
  return { ...req.user, csrfToken: req.session.csrf_token };
}

function parseOffset(value) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? Math.min(parsed, 1_000_000) : 0;
}

function cleanSearch(value) {
  return typeof value === 'string' ? value.trim().slice(0, 120) : '';
}

/** Load the user named in the URL, or answer 404. */
function loadTarget(req, res, next) {
  const target = users.findByPublicId(req.params.publicId);
  if (!target) {
    return res
      .status(404)
      .send(errorPage({ status: 404, user: viewUser(req), hint: 'No such user.' }));
  }
  req.target = target;
  return next();
}

/**
 * Refuse any change that would leave nobody able to administer the site, and
 * refuse the self-inflicted ones (changing your own role, disabling or
 * deleting yourself). These are the mistakes that end with everyone locked out.
 */
function guard(req, { requireOther = false, requireNotLastAdmin = false } = {}) {
  if (requireOther && req.target.id === req.user.id) {
    return 'You cannot do that to your own account.';
  }
  if (
    requireNotLastAdmin &&
    req.target.role === 'admin' &&
    users.countUsableAdmins(req.target.id) === 0
  ) {
    return 'This is the last administrator who can sign in. Promote someone else first.';
  }
  return null;
}

function reveal(req, payload) {
  oneShot.put(`reveal:${req.session.id}`, payload);
}

function takeReveal(req) {
  return oneShot.take(`reveal:${req.session.id}`);
}

function issueLink(req, purpose) {
  const { token, expiresAt } = authTokens.issue({
    userId: req.target.id,
    purpose,
    createdBy: req.user.id,
  });
  const path = purpose === 'invite' ? '/activate' : '/reset';
  return {
    heading: purpose === 'invite' ? 'One-time invite link' : 'One-time password-reset link',
    email: req.target.email,
    expiresAt,
    url: `${config.appUrl}${path}?token=${encodeURIComponent(token)}`,
  };
}

/* ------------------------------------------------------------------ */
/* User list                                                           */
/* ------------------------------------------------------------------ */

router.get('/users', (req, res) => {
  const search = cleanSearch(req.query.search);
  const offset = parseOffset(req.query.offset);
  const { rows, total } = users.list({ search, limit: PAGE_SIZE, offset });

  res.send(
    views.usersPage({
      user: viewUser(req),
      csrfToken: req.session.csrf_token,
      rows,
      total,
      offset,
      limit: PAGE_SIZE,
      search,
      flash: lookup(req.query.msg),
      revealLink: takeReveal(req),
    })
  );
});

router.get('/users/new', requireSudo, (req, res) => {
  res.send(views.newUserPage({ user: viewUser(req), csrfToken: req.session.csrf_token }));
});

router.post('/users/new', requireSudo, (req, res) => {
  const email = users.normaliseEmail(req.body.email);
  const name = typeof req.body.name === 'string' ? req.body.name.trim().slice(0, 120) : '';
  const role = req.body.role === 'admin' ? 'admin' : 'user';

  const errors = [];
  if (!EMAIL_PATTERN.test(email) || email.length > 254) {
    errors.push('Enter a valid email address.');
  }
  if (users.findByEmail(email)) {
    errors.push('An account with that email address already exists.');
  }
  if (errors.length) {
    return res.status(400).send(
      views.newUserPage({
        user: viewUser(req),
        csrfToken: req.session.csrf_token,
        errors,
        values: { email: req.body.email, name, role },
      })
    );
  }

  const created = users.create({ email, name, role, createdBy: req.user.id });
  req.target = created;

  audit.recordFromRequest(req, {
    event: 'admin.user_created',
    targetUserId: created.id,
    targetEmail: created.email,
    detail: { role },
  });

  reveal(req, issueLink(req, 'invite'));
  return res.redirect(303, `/admin/users/${created.public_id}?msg=user_created`);
});

/* ------------------------------------------------------------------ */
/* Single user                                                         */
/* ------------------------------------------------------------------ */

router.get('/users/:publicId', loadTarget, (req, res) => {
  res.send(
    views.userDetailPage({
      user: viewUser(req),
      csrfToken: req.session.csrf_token,
      target: req.target,
      sessionCount: sessions.listActiveForUser(req.target.id).length,
      recoveryCodesLeft: users.countUnusedRecoveryCodes(req.target.id),
      isSelf: req.target.id === req.user.id,
      isLastAdmin: req.target.role === 'admin' && users.countUsableAdmins(req.target.id) === 0,
      flash: lookup(req.query.msg),
      revealLink: takeReveal(req),
    })
  );
});

function detailError(req, res, message, status = 400) {
  return res.status(status).send(
    views.userDetailPage({
      user: viewUser(req),
      csrfToken: req.session.csrf_token,
      target: req.target,
      sessionCount: sessions.listActiveForUser(req.target.id).length,
      recoveryCodesLeft: users.countUnusedRecoveryCodes(req.target.id),
      isSelf: req.target.id === req.user.id,
      isLastAdmin: req.target.role === 'admin' && users.countUsableAdmins(req.target.id) === 0,
      errors: [message],
    })
  );
}

router.post('/users/:publicId/profile', loadTarget, requireSudo, (req, res) => {
  const email = users.normaliseEmail(req.body.email);
  const name = typeof req.body.name === 'string' ? req.body.name.trim().slice(0, 120) : '';

  if (!EMAIL_PATTERN.test(email) || email.length > 254) {
    return detailError(req, res, 'Enter a valid email address.');
  }
  const clash = users.findByEmail(email);
  if (clash && clash.id !== req.target.id) {
    return detailError(req, res, 'Another account already uses that email address.');
  }

  const emailChanged = email !== req.target.email;
  users.setProfile(req.target.id, { email, name });

  if (emailChanged) {
    // The email address is the sign-in identifier; changing it ends every
    // session held under the old one.
    sessions.revokeAllForUser(req.target.id);
    authTokens.revokeAllForUser(req.target.id);
  }

  audit.recordFromRequest(req, {
    event: 'admin.user_updated',
    targetUserId: req.target.id,
    targetEmail: email,
    detail: { email_changed: emailChanged, previous_email: emailChanged ? req.target.email : undefined },
  });

  return res.redirect(303, `/admin/users/${req.target.public_id}?msg=user_updated`);
});

router.post('/users/:publicId/role', loadTarget, requireSudo, (req, res) => {
  const role = req.body.role === 'admin' ? 'admin' : 'user';

  const problem =
    guard(req, { requireOther: true }) ||
    (role !== 'admin' ? guard(req, { requireNotLastAdmin: true }) : null);
  if (problem) return detailError(req, res, problem, 409);

  if (role !== req.target.role) {
    users.setRole(req.target.id, role);
    // A role change must not be something an already-open session carries
    // forward unnoticed; make them sign in again under the new rights.
    sessions.revokeAllForUser(req.target.id);
    audit.recordFromRequest(req, {
      event: 'admin.role_changed',
      targetUserId: req.target.id,
      targetEmail: req.target.email,
      detail: { from: req.target.role, to: role },
    });
  }

  return res.redirect(303, `/admin/users/${req.target.public_id}?msg=user_updated`);
});

router.post('/users/:publicId/disable', loadTarget, requireSudo, (req, res) => {
  const problem =
    guard(req, { requireOther: true }) || guard(req, { requireNotLastAdmin: true });
  if (problem) return detailError(req, res, problem, 409);

  users.setStatus(req.target.id, 'disabled');
  sessions.revokeAllForUser(req.target.id);
  authTokens.revokeAllForUser(req.target.id);

  audit.recordFromRequest(req, {
    event: 'admin.user_disabled',
    targetUserId: req.target.id,
    targetEmail: req.target.email,
  });
  return res.redirect(303, `/admin/users/${req.target.public_id}?msg=user_disabled`);
});

router.post('/users/:publicId/enable', loadTarget, requireSudo, (req, res) => {
  users.setStatus(req.target.id, 'active');
  users.clearLockout(req.target.id);
  audit.recordFromRequest(req, {
    event: 'admin.user_enabled',
    targetUserId: req.target.id,
    targetEmail: req.target.email,
  });
  res.redirect(303, `/admin/users/${req.target.public_id}?msg=user_enabled`);
});

router.post('/users/:publicId/unlock', loadTarget, (req, res) => {
  users.clearLockout(req.target.id);
  audit.recordFromRequest(req, {
    event: 'admin.lockout_cleared',
    targetUserId: req.target.id,
    targetEmail: req.target.email,
  });
  res.redirect(303, `/admin/users/${req.target.public_id}?msg=user_lock_cleared`);
});

router.post('/users/:publicId/revoke-sessions', loadTarget, (req, res) => {
  const count = sessions.revokeAllForUser(req.target.id, {
    exceptSessionId: req.target.id === req.user.id ? req.session.id : null,
  });
  audit.recordFromRequest(req, {
    event: 'admin.sessions_revoked',
    targetUserId: req.target.id,
    targetEmail: req.target.email,
    detail: { revoked: count },
  });
  res.redirect(303, `/admin/users/${req.target.public_id}?msg=user_sessions_revoked`);
});

router.post('/users/:publicId/invite-link', loadTarget, requireSudo, (req, res) => {
  if (req.target.password_hash) {
    return detailError(
      req,
      res,
      'That account already has a password. Generate a reset link instead.'
    );
  }
  reveal(req, issueLink(req, 'invite'));
  audit.recordFromRequest(req, {
    event: 'admin.invite_issued',
    targetUserId: req.target.id,
    targetEmail: req.target.email,
  });
  return res.redirect(303, `/admin/users/${req.target.public_id}?msg=invite_reissued`);
});

router.post('/users/:publicId/require-password-change', loadTarget, requireSudo, (req, res) => {
  if (!req.target.password_hash) {
    return detailError(req, res, 'That account has no password yet.');
  }

  users.setPassword(req.target.id, req.target.password_hash, { mustChangePassword: 1 });
  sessions.revokeAllForUser(req.target.id, {
    exceptSessionId: req.target.id === req.user.id ? req.session.id : null,
  });

  audit.recordFromRequest(req, {
    event: 'admin.password_change_required',
    targetUserId: req.target.id,
    targetEmail: req.target.email,
  });
  return res.redirect(303, `/admin/users/${req.target.public_id}?msg=password_change_required`);
});

router.post('/users/:publicId/reset-link', loadTarget, requireSudo, (req, res) => {
  reveal(req, issueLink(req, 'reset'));
  audit.recordFromRequest(req, {
    event: 'admin.reset_issued',
    targetUserId: req.target.id,
    targetEmail: req.target.email,
  });
  res.redirect(303, `/admin/users/${req.target.public_id}?msg=reset_issued`);
});

router.post('/users/:publicId/reset-two-factor', loadTarget, requireSudo, (req, res) => {
  users.disableTotp(req.target.id);
  users.clearRecoveryCodes(req.target.id);
  sessions.revokeAllForUser(req.target.id, {
    exceptSessionId: req.target.id === req.user.id ? req.session.id : null,
  });

  audit.recordFromRequest(req, {
    event: 'admin.mfa_reset',
    targetUserId: req.target.id,
    targetEmail: req.target.email,
  });
  res.redirect(303, `/admin/users/${req.target.public_id}?msg=user_mfa_reset`);
});

router.post('/users/:publicId/delete', loadTarget, requireSudo, (req, res) => {
  const problem =
    guard(req, { requireOther: true }) || guard(req, { requireNotLastAdmin: true });
  if (problem) return detailError(req, res, problem, 409);

  // Typing the address is a deliberate speed bump on an irreversible action.
  const confirmEmail = users.normaliseEmail(req.body.confirm_email);
  if (confirmEmail !== req.target.email) {
    return detailError(req, res, 'Type the exact email address to confirm the deletion.');
  }

  const { id, email } = req.target;
  users.remove(id);

  // Deliberately recorded after the row is gone: the log outlives the account.
  audit.recordFromRequest(req, {
    event: 'admin.user_deleted',
    targetUserId: null,
    targetEmail: email,
    detail: { deleted_user_id: id },
  });
  return res.redirect(303, '/admin/users?msg=user_deleted');
});

/* ------------------------------------------------------------------ */
/* Audit log                                                           */
/* ------------------------------------------------------------------ */

router.get('/audit', (req, res) => {
  const search = cleanSearch(req.query.search);
  const offset = parseOffset(req.query.offset);
  const events = audit.distinctEvents();
  const event = events.includes(req.query.event) ? req.query.event : '';

  const { rows, total } = audit.list({
    limit: PAGE_SIZE,
    offset,
    search: search || null,
    event: event || null,
  });

  res.send(
    views.auditPage({
      user: viewUser(req),
      rows,
      total,
      offset,
      limit: PAGE_SIZE,
      search,
      event,
      events,
      flash: lookup(req.query.msg),
    })
  );
});

module.exports = router;
