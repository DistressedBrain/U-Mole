'use strict';

/**
 * Flash messages are passed between requests as short codes in the query
 * string and looked up here. Nothing user-supplied is ever echoed back into a
 * page, so a crafted link cannot put attacker-chosen text in front of a user.
 */
const MESSAGES = {
  signed_out: { type: 'ok', message: 'You have been signed out.' },
  session_expired: { type: 'warn', message: 'Your session expired. Please sign in again.' },
  password_updated: { type: 'ok', message: 'Your password has been updated.' },
  password_set: { type: 'ok', message: 'Your password has been set.' },
  profile_updated: { type: 'ok', message: 'Your profile has been updated.' },
  mfa_enabled: { type: 'ok', message: 'Two-factor authentication is now active on your account.' },
  mfa_reset: { type: 'ok', message: 'Two-factor authentication has been reset.' },
  recovery_codes_regenerated: {
    type: 'ok',
    message: 'New recovery codes generated. Your previous codes no longer work.',
  },
  recovery_code_used: {
    type: 'warn',
    message: 'You signed in with a recovery code. That code has been used up.',
  },
  sessions_revoked: { type: 'ok', message: 'Other sessions have been signed out.' },
  session_revoked: { type: 'ok', message: 'That session has been signed out.' },
  user_created: { type: 'ok', message: 'User created. Share the invite link shown below.' },
  user_updated: { type: 'ok', message: 'User updated.' },
  user_deleted: { type: 'ok', message: 'User deleted.' },
  user_disabled: { type: 'ok', message: 'User disabled and signed out everywhere.' },
  user_enabled: { type: 'ok', message: 'User re-enabled.' },
  invite_reissued: { type: 'ok', message: 'A new invite link has been generated.' },
  reset_issued: { type: 'ok', message: 'A password-reset link has been generated.' },
  user_mfa_reset: {
    type: 'ok',
    message: 'That user must enrol a new authenticator the next time they sign in.',
  },
  user_lock_cleared: { type: 'ok', message: 'Lockout cleared.' },
  password_change_required: {
    type: 'ok',
    message: 'That user must choose a new password the next time they sign in.',
  },
  user_sessions_revoked: { type: 'ok', message: 'All of that user’s sessions were signed out.' },
  sudo_granted: { type: 'ok', message: 'Re-authenticated. Sensitive actions are unlocked briefly.' },
};

function lookup(code) {
  if (!code || typeof code !== 'string') return [];
  const entry = MESSAGES[code];
  return entry ? [entry] : [];
}

module.exports = { lookup, MESSAGES };
