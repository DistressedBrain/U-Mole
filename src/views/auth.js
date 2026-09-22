'use strict';

const { html } = require('../lib/html');
const { layout } = require('./layout');

function errorList(errors = []) {
  if (!errors.length) return '';
  return html`
    <ul class="errors">
      ${errors.map((message) => html`<li>${message}</li>`)}
    </ul>
  `;
}

function loginPage({ csrfToken, email = '', next = '', errors = [], flash = [] }) {
  return layout({
    title: 'Sign in',
    flash,
    body: html`
      <form method="post" action="/login" class="card" autocomplete="on">
        <input type="hidden" name="_csrf" value="${csrfToken}" />
        ${next ? html`<input type="hidden" name="next" value="${next}" />` : ''}
        ${errorList(errors)}
        <label for="email">Email address</label>
        <input
          id="email"
          name="email"
          type="email"
          value="${email}"
          autocomplete="username"
          required
          autofocus
          maxlength="254"
        />
        <label for="password">Password</label>
        <input
          id="password"
          name="password"
          type="password"
          autocomplete="current-password"
          required
          maxlength="128"
        />
        <button type="submit">Sign in</button>
        <p class="hint">
          Accounts are created by an administrator. If you cannot get in, ask them
          for a new invite or reset link.
        </p>
      </form>
    `,
  });
}

function verifyPage({ csrfToken, errors = [], flash = [], mode = 'totp', next = '' }) {
  const nextField = next ? html`<input type="hidden" name="next" value="${next}" />` : '';
  const nextQuery = next ? `&next=${encodeURIComponent(next)}` : '';

  const totpForm = html`
    <form method="post" action="/login/verify" class="card">
      <input type="hidden" name="_csrf" value="${csrfToken}" />
      <input type="hidden" name="mode" value="totp" />
      ${nextField}
      ${errorList(errors)}
      <label for="code">Six-digit code from your authenticator app</label>
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
      <button type="submit">Verify</button>
      <p class="hint">
        <a href="${`/login/verify?mode=recovery${nextQuery}`}">Use a recovery code instead</a>
      </p>
    </form>
  `;

  const recoveryForm = html`
    <form method="post" action="/login/verify" class="card">
      <input type="hidden" name="_csrf" value="${csrfToken}" />
      <input type="hidden" name="mode" value="recovery" />
      ${nextField}
      ${errorList(errors)}
      <label for="recovery">Recovery code</label>
      <input
        id="recovery"
        name="recovery"
        autocomplete="off"
        spellcheck="false"
        maxlength="16"
        placeholder="XXXXX-XXXXX"
        required
        autofocus
      />
      <button type="submit">Use recovery code</button>
      <p class="hint">
        Each recovery code works once.
        <a href="${`/login/verify?mode=totp${nextQuery}`}">Back to authenticator code</a>
      </p>
    </form>
  `;

  return layout({
    title: 'Two-factor verification',
    flash,
    body: html`
      ${mode === 'recovery' ? recoveryForm : totpForm}
      <form method="post" action="/logout" class="cancel">
        <input type="hidden" name="_csrf" value="${csrfToken}" />
        <button type="submit" class="link-button">Cancel and sign out</button>
      </form>
    `,
  });
}

function setPasswordPage({ csrfToken, token, purpose, email, errors = [], minLength }) {
  const heading = purpose === 'invite' ? 'Set up your account' : 'Choose a new password';
  const action = purpose === 'invite' ? '/activate' : '/reset';
  return layout({
    title: heading,
    body: html`
      <form method="post" action="${action}" class="card">
        <input type="hidden" name="_csrf" value="${csrfToken}" />
        <input type="hidden" name="token" value="${token}" />
        ${errorList(errors)}
        <p class="hint">Setting the password for <strong>${email}</strong>.</p>
        <label for="password">New password</label>
        <input
          id="password"
          name="password"
          type="password"
          autocomplete="new-password"
          required
          autofocus
          minlength="${minLength}"
          maxlength="128"
        />
        <label for="confirm">Confirm password</label>
        <input
          id="confirm"
          name="confirm"
          type="password"
          autocomplete="new-password"
          required
          minlength="${minLength}"
          maxlength="128"
        />
        <button type="submit">Save password</button>
        <p class="hint">
          At least ${minLength} characters. A passphrase of a few unrelated words is
          both stronger and easier to remember than a short jumble.
        </p>
      </form>
    `,
  });
}

function sudoPage({ csrfToken, next, errors = [], user }) {
  return layout({
    title: 'Confirm it is you',
    user,
    body: html`
      <form method="post" action="/sudo" class="card">
        <input type="hidden" name="_csrf" value="${csrfToken}" />
        <input type="hidden" name="next" value="${next}" />
        ${errorList(errors)}
        <p class="hint">This action is sensitive. Re-enter your password to continue.</p>
        <label for="password">Password</label>
        <input
          id="password"
          name="password"
          type="password"
          autocomplete="current-password"
          required
          autofocus
          maxlength="128"
        />
        <button type="submit">Confirm</button>
      </form>
    `,
  });
}

module.exports = { loginPage, verifyPage, setPasswordPage, sudoPage, errorList };
