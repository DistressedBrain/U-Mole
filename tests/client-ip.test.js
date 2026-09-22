'use strict';

/**
 * Behind a Cloudflare Tunnel every request arrives from cloudflared's own
 * address, so the per-address rate limits and the lockout only work if the
 * real client is read out of a header the proxy sets. Getting this wrong in
 * either direction is a security bug, so both directions are tested.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { startApp, Client } = require('./helpers');

function lastLoginFailureIp(ctx) {
  const { rows } = ctx.models.audit.list({ limit: 1, event: 'auth.login' });
  return rows[0] ? rows[0].ip : null;
}

test('without CLIENT_IP_HEADER, a forged header is ignored', async () => {
  const ctx = await startApp();
  try {
    const client = new Client(ctx.baseUrl);
    const csrf = await client.csrf('/login');
    await client.post(
      '/login',
      { _csrf: csrf, email: 'someone@example.com', password: 'a-long-wrong-password-1' },
      { headers: { 'cf-connecting-ip': '203.0.113.9', 'x-forwarded-for': '198.51.100.7' } }
    );

    const recorded = lastLoginFailureIp(ctx);
    assert.ok(recorded, 'the attempt should have been logged');
    assert.ok(
      !recorded.includes('203.0.113.9') && !recorded.includes('198.51.100.7'),
      `a client must not be able to choose its own address, got ${recorded}`
    );
  } finally {
    await ctx.stop();
  }
});

test('with CLIENT_IP_HEADER set, the named header is used', async () => {
  const ctx = await startApp({ CLIENT_IP_HEADER: 'cf-connecting-ip' });
  try {
    const client = new Client(ctx.baseUrl);
    const csrf = await client.csrf('/login');
    await client.post(
      '/login',
      { _csrf: csrf, email: 'someone@example.com', password: 'a-long-wrong-password-1' },
      { headers: { 'cf-connecting-ip': '203.0.113.9' } }
    );

    assert.equal(lastLoginFailureIp(ctx), '203.0.113.9');
  } finally {
    await ctx.stop();
  }
});

test('two clients behind the same proxy get their own rate-limit budgets', async () => {
  const ctx = await startApp({ CLIENT_IP_HEADER: 'cf-connecting-ip' });
  try {
    // Exhaust one address's login budget.
    let limited = false;
    for (let attempt = 0; attempt < 40 && !limited; attempt += 1) {
      const client = new Client(ctx.baseUrl);
      const csrf = await client.csrf('/login').catch(() => null);
      if (!csrf) {
        limited = true;
        break;
      }
      const response = await client.post(
        '/login',
        { _csrf: csrf, email: `a${attempt}@example.com`, password: 'a-long-wrong-password-1' },
        { headers: { 'cf-connecting-ip': '203.0.113.9' } }
      );
      if (response.status === 429) limited = true;
    }
    assert.ok(limited, 'the noisy address should have been limited');

    // A different address is unaffected, even though both arrive on the same
    // socket from the tunnel.
    const innocent = new Client(ctx.baseUrl);
    const csrf = await innocent.csrf('/login');
    const response = await innocent.post(
      '/login',
      { _csrf: csrf, email: 'innocent@example.com', password: 'a-long-wrong-password-1' },
      { headers: { 'cf-connecting-ip': '198.51.100.7' } }
    );
    assert.notEqual(response.status, 429, 'an unrelated visitor must not be punished');
  } finally {
    await ctx.stop();
  }
});

test('a missing header falls back to the socket address rather than a blank key', async () => {
  const ctx = await startApp({ CLIENT_IP_HEADER: 'cf-connecting-ip' });
  try {
    const client = new Client(ctx.baseUrl);
    const csrf = await client.csrf('/login');
    await client.post('/login', {
      _csrf: csrf,
      email: 'someone@example.com',
      password: 'a-long-wrong-password-1',
    });

    const recorded = lastLoginFailureIp(ctx);
    assert.ok(recorded && recorded.length > 0, `expected a fallback address, got ${recorded}`);
  } finally {
    await ctx.stop();
  }
});
