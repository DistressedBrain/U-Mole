'use strict';

const { html, raw } = require('../lib/html');
const { layout } = require('./layout');
const { errorList } = require('./auth');

function formatTime(ms) {
  if (!ms) return 'never';
  return new Date(ms).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

function accountPage({ user, csrfToken, sessions, currentSessionId, recoveryCodesLeft, flash = [], errors = [] }) {
  return layout({
    title: 'Your account',
    user,
    flash,
    body: html`
      <section class="card">
        <h2>Profile</h2>
        ${errorList(errors)}
        <form method="post" action="/account/profile">
          <input type="hidden" name="_csrf" value="${csrfToken}" />
          <label for="name">Display name</label>
          <input id="name" name="name" value="${user.name}" maxlength="120" />
          <p class="hint">
            Email: <strong>${user.email}</strong> — only an administrator can change this.<br />
            Role: <strong>${user.role}</strong>
          </p>
          <button type="submit">Save</button>
        </form>
      </section>

      <section class="card">
        <h2>Password</h2>
        <p class="hint">Last changed: ${formatTime(user.password_changed_at)}</p>
        <a class="button" href="/account/password">Change password</a>
      </section>

      <section class="card">
        <h2>Two-factor authentication</h2>
        <p class="hint">
          Status: <strong>${user.totp_enabled ? 'enabled' : 'not set up'}</strong><br />
          Unused recovery codes: <strong>${recoveryCodesLeft}</strong>
          ${recoveryCodesLeft <= 2
            ? html`<span class="warn-inline"> — generate a new set soon.</span>`
            : ''}
        </p>
        <form method="post" action="/account/two-factor/recovery-codes">
          <input type="hidden" name="_csrf" value="${csrfToken}" />
          <button type="submit">Generate new recovery codes</button>
        </form>
        <p class="hint">
          Generating a new set immediately invalidates every previous code.
          To move to a different authenticator app, ask an administrator to reset
          your second factor.
        </p>
      </section>

      <section class="card">
        <h2>Active sessions</h2>
        <table>
          <thead>
            <tr><th>Signed in</th><th>Last seen</th><th>Address</th><th>Browser</th><th></th></tr>
          </thead>
          <tbody>
            ${sessions.map(
              (session) => html`
                <tr>
                  <td>${formatTime(session.created_at)}</td>
                  <td>${formatTime(session.last_seen_at)}</td>
                  <td>${session.ip || '—'}</td>
                  <td class="truncate">
                    ${session.user_agent || '—'}
                    ${session.id === currentSessionId ? html`<strong> (this one)</strong>` : ''}
                  </td>
                  <td>
                    ${session.id === currentSessionId
                      ? ''
                      : html`
                          <form method="post" action="/account/sessions/revoke">
                            <input type="hidden" name="_csrf" value="${csrfToken}" />
                            <input type="hidden" name="session_id" value="${session.id}" />
                            <button type="submit" class="danger">Sign out</button>
                          </form>
                        `}
                  </td>
                </tr>
              `
            )}
          </tbody>
        </table>
        <form method="post" action="/account/sessions/revoke-others">
          <input type="hidden" name="_csrf" value="${csrfToken}" />
          <button type="submit" class="danger">Sign out everywhere else</button>
        </form>
      </section>
    `,
  });
}

function passwordPage({ user, csrfToken, errors = [], minLength, forced = false, flash = [] }) {
  return layout({
    title: 'Change password',
    user,
    flash,
    body: html`
      <form method="post" action="/account/password" class="card">
        <input type="hidden" name="_csrf" value="${csrfToken}" />
        ${errorList(errors)}
        ${forced
          ? html`<p class="flash flash-warn">
              An administrator has required you to choose a new password before continuing.
            </p>`
          : ''}
        <label for="current">Current password</label>
        <input
          id="current"
          name="current"
          type="password"
          autocomplete="current-password"
          required
          autofocus
          maxlength="128"
        />
        <label for="password">New password</label>
        <input
          id="password"
          name="password"
          type="password"
          autocomplete="new-password"
          required
          minlength="${minLength}"
          maxlength="128"
        />
        <label for="confirm">Confirm new password</label>
        <input
          id="confirm"
          name="confirm"
          type="password"
          autocomplete="new-password"
          required
          minlength="${minLength}"
          maxlength="128"
        />
        <button type="submit">Change password</button>
        <p class="hint">
          Changing your password signs out every other session, including anyone
          else who may have one.
        </p>
      </form>
    `,
  });
}

function twoFactorSetupPage({ user, csrfToken, qrSvg, secret, errors = [] }) {
  return layout({
    title: 'Set up two-factor authentication',
    user,
    body: html`
      <section class="card">
        <p>
          Two-factor authentication is required on every account here. Scan this
          code with an authenticator app — Aegis, Google Authenticator, 1Password,
          Bitwarden and others all work — then enter the six-digit code it shows.
        </p>
        <div class="qr">${raw(qrSvg)}</div>
        <p class="hint">
          Cannot scan? Enter this key manually:<br />
          <code class="secret">${secret}</code>
        </p>
        <form method="post" action="/account/two-factor/setup">
          <input type="hidden" name="_csrf" value="${csrfToken}" />
          ${errorList(errors)}
          <label for="code">Six-digit code</label>
          <input
            id="code"
            name="code"
            inputmode="numeric"
            pattern="[0-9]*"
            autocomplete="one-time-code"
            maxlength="6"
            required
            autofocus
          />
          <button type="submit">Turn on two-factor authentication</button>
        </form>
      </section>
    `,
  });
}

function recoveryCodesPage({ user, codes, heading = 'Save your recovery codes' }) {
  return layout({
    title: heading,
    user,
    body: html`
      <section class="card">
        <p class="flash flash-warn">
          These codes are shown once and cannot be retrieved again. Store them
          somewhere safe and offline — a password manager or a piece of paper.
          Each one works a single time, and lets you back in if you lose your
          authenticator.
        </p>
        <ul class="codes">
          ${codes.map((code) => html`<li><code>${code}</code></li>`)}
        </ul>
        <a class="button" href="/">I have saved them — continue</a>
      </section>
    `,
  });
}

module.exports = { accountPage, passwordPage, twoFactorSetupPage, recoveryCodesPage, formatTime };
