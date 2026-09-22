'use strict';

const { html } = require('../lib/html');
const { layout } = require('./layout');
const { formatTime } = require('./account');

/**
 * The protected content of the site. Everything rendered from here is behind
 * `requireAuth`, so there is no anonymous path to any of it — replace this
 * body with whatever the site is actually for.
 */
function dashboardPage({ user, stats, flash = [] }) {
  return layout({
    title: 'Dashboard',
    user,
    flash,
    body: html`
      <section class="card">
        <h2>Welcome, ${user.name || user.email}</h2>
        <p>
          You are signed in as <strong>${user.role}</strong>. Last sign-in:
          ${formatTime(user.last_login_at)}.
        </p>
        <p class="hint">
          This page is the placeholder for the site's real content. Anything you
          add under <code>src/routes/app.js</code> is reachable only after a
          password and a second factor.
        </p>
      </section>

      ${user.role === 'admin'
        ? html`
            <section class="card">
              <h2>At a glance</h2>
              <dl class="details">
                <dt>Users</dt><dd>${stats.users}</dd>
                <dt>Administrators</dt><dd>${stats.admins}</dd>
                <dt>Awaiting first sign-in</dt><dd>${stats.pendingInvites}</dd>
                <dt>Without two-factor yet</dt><dd>${stats.withoutMfa}</dd>
                <dt>Failed sign-ins (24h)</dt><dd>${stats.failedLogins24h}</dd>
              </dl>
              <p><a href="/admin/users">Manage users</a> · <a href="/admin/audit">Audit log</a></p>
            </section>
          `
        : ''}
    `,
  });
}

module.exports = { dashboardPage };
