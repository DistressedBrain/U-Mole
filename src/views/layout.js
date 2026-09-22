'use strict';

const { html, raw } = require('../lib/html');

function nav(user) {
  if (!user) return raw('');
  return html`
    <nav class="nav">
      <a class="brand" href="/">U-Mole</a>
      <div class="nav-links">
        <a href="/">Dashboard</a>
        <a href="/account">Account</a>
        ${user.role === 'admin' ? html`<a href="/admin/users">Users</a>` : ''}
        ${user.role === 'admin' ? html`<a href="/admin/audit">Audit log</a>` : ''}
      </div>
      <form method="post" action="/logout" class="nav-logout">
        <input type="hidden" name="_csrf" value="${user.csrfToken}" />
        <span class="whoami">${user.email}</span>
        <button type="submit" class="link-button">Sign out</button>
      </form>
    </nav>
  `;
}

function flashes(messages = []) {
  if (!messages.length) return raw('');
  return html`
    <div class="flashes">
      ${messages.map((flash) => html`<p class="flash flash-${flash.type}">${flash.message}</p>`)}
    </div>
  `;
}

/**
 * @param {object} options
 * @param {string} options.title
 * @param {import('../lib/html').SafeHtml} options.body
 * @param {object} [options.user] current user, for the nav bar
 * @param {Array<{type: string, message: string}>} [options.flash]
 */
function layout({ title, body, user = null, flash = [] }) {
  return html`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="referrer" content="same-origin" />
    <meta name="robots" content="noindex, nofollow" />
    <title>${title} · U-Mole</title>
    <link rel="stylesheet" href="/static/app.css" />
    <link rel="icon" href="data:," />
  </head>
  <body>
    ${nav(user)}
    <main class="${user ? 'main' : 'main main-narrow'}">
      <h1>${title}</h1>
      ${flashes(flash)}
      ${body}
    </main>
  </body>
</html>`.toString();
}

module.exports = { layout };
