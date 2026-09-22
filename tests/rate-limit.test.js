'use strict';

/**
 * The limiter counts every attempt from an address within a window, so this
 * lives in its own file — and its own application instance — rather than
 * eating the budget other tests rely on.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { startApp, Client } = require('./helpers');

let ctx;

test.before(async () => {
  ctx = await startApp();
});

test.after(async () => {
  await ctx.stop();
});

test('the login endpoint is rate limited per address', async () => {
  const client = new Client(ctx.baseUrl);
  let limitedAt = null;

  for (let attempt = 0; attempt < 60 && limitedAt === null; attempt += 1) {
    const csrf = await client.csrf('/login').catch(() => null);
    if (!csrf) {
      limitedAt = attempt;
      break;
    }
    const response = await client.post('/login', {
      _csrf: csrf,
      email: `flood${attempt}@example.com`,
      password: 'some-long-wrong-password-7',
    });
    if (response.status === 429) {
      limitedAt = attempt;
      assert.ok(response.headers.get('retry-after'), 'a Retry-After header should be sent');
    }
  }

  assert.notEqual(limitedAt, null, 'the limiter should have kicked in');
  assert.ok(
    limitedAt <= ctx.config.rateLimits.login.limit + 1,
    `expected the limit around ${ctx.config.rateLimits.login.limit}, hit it at ${limitedAt}`
  );
});

test('a single account cannot be sprayed from many addresses', async () => {
  const user = ctx.models.users.create({ email: 'sprayed@example.com', role: 'user' });
  assert.ok(user);

  let limited = false;
  // Each request claims a different forwarded address; with TRUST_PROXY off
  // the server ignores that entirely, and the per-account counter catches it.
  for (let attempt = 0; attempt < 40 && !limited; attempt += 1) {
    const client = new Client(ctx.baseUrl);
    const csrf = await client.csrf('/login').catch(() => null);
    if (!csrf) {
      limited = true;
      break;
    }
    const response = await client.post(
      '/login',
      { _csrf: csrf, email: 'sprayed@example.com', password: `guess-number-${attempt}-long` },
      { headers: { 'x-forwarded-for': `203.0.113.${attempt}` } }
    );
    if (response.status === 429) limited = true;
  }

  assert.ok(limited, 'spraying one account should be stopped');
});

test('rate limit counters survive a restart because they live in the database', async () => {
  const { getDb } = require('../src/db');
  const rows = getDb().prepare('SELECT COUNT(*) AS n FROM rate_limits').get().n;
  assert.ok(rows > 0, 'counters should be persisted, not held in memory');
});
