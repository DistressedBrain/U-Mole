'use strict';

const { html } = require('../lib/html');
const { layout } = require('./layout');

const TITLES = {
  400: 'Bad request',
  403: 'Not allowed',
  404: 'Not found',
  405: 'Method not allowed',
  413: 'Request too large',
  429: 'Too many requests',
  500: 'Something went wrong',
};

/**
 * Error pages deliberately say very little. Detailed messages and stack traces
 * go to the server log, not to whoever is probing the site.
 */
function errorPage({ status, user = null, hint = null }) {
  const title = TITLES[status] || TITLES[500];
  return layout({
    title,
    user,
    body: html`
      <section class="card">
        <p>${hint || 'The request could not be completed.'}</p>
        <p><a href="/">Back to the start</a></p>
      </section>
    `,
  });
}

module.exports = { errorPage, TITLES };
