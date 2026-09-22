'use strict';

const { html } = require('../lib/html');
const { layout } = require('./layout');
const { errorList } = require('./auth');
const { formatTime } = require('./account');

function pager(baseUrl, { offset, limit, total }) {
  const prev = Math.max(0, offset - limit);
  const next = offset + limit;
  return html`
    <p class="pager">
      ${offset > 0 ? html`<a href="${`${baseUrl}offset=${prev}`}">← Previous</a>` : ''}
      <span>${total === 0 ? 0 : offset + 1}–${Math.min(total, offset + limit)} of ${total}</span>
      ${next < total ? html`<a href="${`${baseUrl}offset=${next}`}">Next →</a>` : ''}
    </p>
  `;
}

function statusBadge(user, now = Date.now()) {
  if (user.status === 'disabled') return html`<span class="badge badge-off">disabled</span>`;
  if (user.locked_until > now) return html`<span class="badge badge-warn">locked</span>`;
  if (!user.password_hash) return html`<span class="badge badge-warn">invited</span>`;
  if (!user.totp_enabled) return html`<span class="badge badge-warn">no 2FA yet</span>`;
  return html`<span class="badge badge-ok">active</span>`;
}

function usersPage({ user, csrfToken, rows, total, offset, limit, search, flash = [], revealLink = null }) {
  const base = `/admin/users?search=${encodeURIComponent(search || '')}&`;
  return layout({
    title: 'Users',
    user,
    flash,
    body: html`
      ${revealLink
        ? html`
            <section class="card reveal">
              <h2>${revealLink.heading}</h2>
              <p class="hint">
                Send this to <strong>${revealLink.email}</strong> over a channel you
                trust. It works once and expires ${formatTime(revealLink.expiresAt)}.
                It is shown here only this once.
              </p>
              <code class="secret break">${revealLink.url}</code>
            </section>
          `
        : ''}

      <section class="card">
        <form method="get" action="/admin/users" class="inline">
          <label for="search">Search</label>
          <input id="search" name="search" value="${search || ''}" maxlength="120" />
          <button type="submit">Search</button>
          <a class="button" href="/admin/users/new">Add user</a>
        </form>
      </section>

      <section class="card">
        <table>
          <thead>
            <tr>
              <th>Email</th><th>Name</th><th>Role</th><th>Status</th>
              <th>Last sign-in</th><th></th>
            </tr>
          </thead>
          <tbody>
            ${rows.map(
              (row) => html`
                <tr>
                  <td>${row.email}</td>
                  <td>${row.name || '—'}</td>
                  <td>${row.role}</td>
                  <td>${statusBadge(row)}</td>
                  <td>${formatTime(row.last_login_at)}</td>
                  <td><a href="${`/admin/users/${row.public_id}`}">Manage</a></td>
                </tr>
              `
            )}
            ${rows.length === 0 ? html`<tr><td colspan="6">No users match.</td></tr>` : ''}
          </tbody>
        </table>
        ${pager(base, { offset, limit, total })}
      </section>
    `,
  });
}

function newUserPage({ user, csrfToken, errors = [], values = {} }) {
  return layout({
    title: 'Add user',
    user,
    body: html`
      <form method="post" action="/admin/users/new" class="card">
        <input type="hidden" name="_csrf" value="${csrfToken}" />
        ${errorList(errors)}
        <label for="email">Email address</label>
        <input
          id="email"
          name="email"
          type="email"
          required
          autofocus
          maxlength="254"
          value="${values.email || ''}"
        />
        <label for="name">Display name (optional)</label>
        <input id="name" name="name" maxlength="120" value="${values.name || ''}" />
        <label for="role">Role</label>
        <select id="role" name="role">
          <option value="user" ${values.role === 'admin' ? '' : 'selected'}>user</option>
          <option value="admin" ${values.role === 'admin' ? 'selected' : ''}>admin</option>
        </select>
        <button type="submit">Create and generate invite link</button>
        <p class="hint">
          No email is sent. You will get a one-time link to pass to the person
          yourself. They choose their own password and enrol two-factor
          authentication when they open it.
        </p>
      </form>
    `,
  });
}

function actionForm(csrfToken, action, label, { danger = false, confirm = null, extra = null } = {}) {
  return html`
    <form method="post" action="${action}" class="action">
      <input type="hidden" name="_csrf" value="${csrfToken}" />
      ${extra}
      <button type="submit" class="${danger ? 'danger' : ''}">${label}</button>
      ${confirm ? html`<span class="hint">${confirm}</span>` : ''}
    </form>
  `;
}

function userDetailPage({
  user,
  csrfToken,
  target,
  sessionCount,
  recoveryCodesLeft,
  isSelf,
  isLastAdmin,
  flash = [],
  errors = [],
  revealLink = null,
}) {
  const base = `/admin/users/${target.public_id}`;
  return layout({
    title: target.email,
    user,
    flash,
    body: html`
      ${revealLink
        ? html`
            <section class="card reveal">
              <h2>${revealLink.heading}</h2>
              <p class="hint">
                Pass this to <strong>${revealLink.email}</strong> over a channel you
                trust. Single use, expires ${formatTime(revealLink.expiresAt)}, shown
                only once.
              </p>
              <code class="secret break">${revealLink.url}</code>
            </section>
          `
        : ''}

      <section class="card">
        <h2>Details</h2>
        ${errorList(errors)}
        <dl class="details">
          <dt>Status</dt><dd>${statusBadge(target)}</dd>
          <dt>Two-factor</dt>
          <dd>${target.totp_enabled ? `enabled, ${recoveryCodesLeft} recovery codes left` : 'not enrolled'}</dd>
          <dt>Created</dt><dd>${formatTime(target.created_at)}</dd>
          <dt>Last sign-in</dt><dd>${formatTime(target.last_login_at)}</dd>
          <dt>Password set</dt><dd>${formatTime(target.password_changed_at)}</dd>
          <dt>Failed attempts</dt><dd>${target.failed_login_count}</dd>
          <dt>Locked until</dt>
          <dd>${target.locked_until > Date.now() ? formatTime(target.locked_until) : '—'}</dd>
          <dt>Active sessions</dt><dd>${sessionCount}</dd>
        </dl>
      </section>

      <section class="card">
        <h2>Profile</h2>
        <form method="post" action="${`${base}/profile`}">
          <input type="hidden" name="_csrf" value="${csrfToken}" />
          <label for="email">Email address</label>
          <input id="email" name="email" type="email" value="${target.email}" required maxlength="254" />
          <label for="name">Display name</label>
          <input id="name" name="name" value="${target.name}" maxlength="120" />
          <button type="submit">Save</button>
        </form>
      </section>

      <section class="card">
        <h2>Access</h2>
        ${isLastAdmin
          ? html`<p class="flash flash-warn">
              This is the last administrator who can sign in. Role, status and
              deletion are locked until another administrator exists.
            </p>`
          : ''}
        <form method="post" action="${`${base}/role`}" class="action">
          <input type="hidden" name="_csrf" value="${csrfToken}" />
          <label for="role">Role</label>
          <select id="role" name="role" ${isLastAdmin || isSelf ? 'disabled' : ''}>
            <option value="user" ${target.role === 'user' ? 'selected' : ''}>user</option>
            <option value="admin" ${target.role === 'admin' ? 'selected' : ''}>admin</option>
          </select>
          <button type="submit" ${isLastAdmin || isSelf ? 'disabled' : ''}>Change role</button>
          ${isSelf ? html`<span class="hint">You cannot change your own role.</span>` : ''}
        </form>

        ${target.status === 'active'
          ? actionForm(csrfToken, `${base}/disable`, 'Disable account', {
              danger: true,
              confirm: 'Signs them out everywhere and blocks sign-in.',
            })
          : actionForm(csrfToken, `${base}/enable`, 'Re-enable account')}

        ${target.locked_until > Date.now()
          ? actionForm(csrfToken, `${base}/unlock`, 'Clear lockout')
          : ''}

        ${sessionCount > 0
          ? actionForm(csrfToken, `${base}/revoke-sessions`, 'Sign out all their sessions', {
              danger: true,
            })
          : ''}
      </section>

      <section class="card">
        <h2>Credentials</h2>
        ${target.password_hash
          ? actionForm(csrfToken, `${base}/reset-link`, 'Generate password-reset link')
          : actionForm(csrfToken, `${base}/invite-link`, 'Generate a new invite link')}
        ${target.password_hash
          ? actionForm(
              csrfToken,
              `${base}/require-password-change`,
              'Require a new password at next sign-in',
              { confirm: 'Also signs them out everywhere.' }
            )
          : ''}
        ${actionForm(csrfToken, `${base}/reset-two-factor`, 'Reset two-factor authentication', {
          danger: true,
          confirm: 'They will enrol a new authenticator at next sign-in.',
        })}
      </section>

      <section class="card danger-zone">
        <h2>Delete</h2>
        <p class="hint">
          Permanently removes the account, its sessions and its recovery codes.
          Audit log entries about them are kept.
        </p>
        ${isSelf
          ? html`<p class="hint">You cannot delete your own account.</p>`
          : actionForm(csrfToken, `${base}/delete`, 'Delete this user', {
              danger: true,
              extra: html`
                <label for="confirm_email">Type the email address to confirm</label>
                <input id="confirm_email" name="confirm_email" maxlength="254" />
              `,
            })}
      </section>
    `,
  });
}

function auditPage({ user, rows, total, offset, limit, search, event, events, flash = [] }) {
  const base = `/admin/audit?search=${encodeURIComponent(search || '')}&event=${encodeURIComponent(
    event || ''
  )}&`;
  return layout({
    title: 'Audit log',
    user,
    flash,
    body: html`
      <section class="card">
        <form method="get" action="/admin/audit" class="inline">
          <label for="search">Search</label>
          <input id="search" name="search" value="${search || ''}" maxlength="120" />
          <label for="event">Event</label>
          <select id="event" name="event">
            <option value="">all events</option>
            ${events.map(
              (name) => html`<option value="${name}" ${name === event ? 'selected' : ''}>${name}</option>`
            )}
          </select>
          <button type="submit">Filter</button>
        </form>
      </section>

      <section class="card">
        <table class="audit">
          <thead>
            <tr><th>When</th><th>Event</th><th>Actor</th><th>Target</th><th>Address</th><th>Detail</th></tr>
          </thead>
          <tbody>
            ${rows.map(
              (row) => html`
                <tr class="${row.success ? '' : 'row-fail'}">
                  <td>${formatTime(row.at)}</td>
                  <td>${row.event}${row.success ? '' : ' ✗'}</td>
                  <td>${row.actor_email || '—'}</td>
                  <td>${row.target_email || '—'}</td>
                  <td>${row.ip || '—'}</td>
                  <td class="truncate">${row.detail === '{}' ? '' : row.detail}</td>
                </tr>
              `
            )}
            ${rows.length === 0 ? html`<tr><td colspan="6">Nothing recorded yet.</td></tr>` : ''}
          </tbody>
        </table>
        ${pager(base, { offset, limit, total })}
      </section>
    `,
  });
}

module.exports = { usersPage, newUserPage, userDetailPage, auditPage };
