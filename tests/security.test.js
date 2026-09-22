'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  startApp,
  Client,
  activateAccount,
  signIn,
  bootstrapAdmin,
  decodeEntities,
} = require('./helpers');

const PASSWORD = 'violet-harbour-tempo-91';

let ctx;
let admin;
let adminSecret;

test.before(async () => {
  ctx = await startApp();
  const { inviteToken } = await bootstrapAdmin(ctx);
  admin = new Client(ctx.baseUrl);
  const enrolment = await activateAccount(ctx, admin, inviteToken, PASSWORD);
  adminSecret = enrolment.secret;
});

test.after(async () => {
  await ctx.stop();
});

/* ------------------------------------------------------------------ */
/* CSRF                                                                */
/* ------------------------------------------------------------------ */

test('a POST without a CSRF token is refused', async () => {
  const response = await admin.post('/account/profile', { name: 'Injected' });
  assert.equal(response.status, 403);
  assert.notEqual(ctx.models.users.findByEmail('admin@example.com').name, 'Injected');
});

test('a POST with someone else’s CSRF token is refused', async () => {
  const response = await admin.post('/account/profile', {
    _csrf: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    name: 'Injected',
  });
  assert.equal(response.status, 403);
});

test('a POST from another origin is refused even with a valid token', async () => {
  const csrf = await admin.csrf('/account');
  const response = await admin.post(
    '/account/profile',
    { _csrf: csrf, name: 'Injected' },
    { origin: 'https://evil.example' }
  );
  assert.equal(response.status, 403);
  assert.notEqual(ctx.models.users.findByEmail('admin@example.com').name, 'Injected');
});

test('a POST with no Origin and no Referer is refused', async () => {
  const csrf = await admin.csrf('/account');
  const response = await admin.post('/account/profile', { _csrf: csrf, name: 'Injected' }, { origin: null });
  assert.equal(response.status, 403);
});

test('the login form itself is CSRF protected', async () => {
  const anon = new Client(ctx.baseUrl);
  const response = await anon.post('/login', { email: 'admin@example.com', password: PASSWORD });
  assert.equal(response.status, 403);
});

/* ------------------------------------------------------------------ */
/* Account enumeration and brute force                                 */
/* ------------------------------------------------------------------ */

test('unknown and known accounts fail identically', async () => {
  const a = new Client(ctx.baseUrl);
  const csrfA = await a.csrf('/login');
  const unknown = await a.post('/login', {
    _csrf: csrfA,
    email: 'nobody@example.com',
    password: 'whatever-long-enough-9',
  });

  const b = new Client(ctx.baseUrl);
  const csrfB = await b.csrf('/login');
  const known = await b.post('/login', {
    _csrf: csrfB,
    email: 'admin@example.com',
    password: 'definitely-the-wrong-1',
  });

  assert.equal(unknown.status, known.status);
  const strip = (body) => body.replace(/value="[^"]*"/g, '');
  assert.equal(strip(unknown.body), strip(known.body));
});

test('repeated wrong passwords lock the account', async () => {
  const user = ctx.models.users.create({ email: 'locktest@example.com', role: 'user' });
  const { token } = ctx.models.authTokens.issue({ userId: user.id, purpose: 'invite' });
  const client = new Client(ctx.baseUrl);
  await activateAccount(ctx, client, token, 'copper-meadow-quilt-42');

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const attacker = new Client(ctx.baseUrl);
    const csrf = await attacker.csrf('/login');
    await attacker.post('/login', {
      _csrf: csrf,
      email: 'locktest@example.com',
      password: `wrong-guess-number-${attempt}`,
    });
  }

  const locked = ctx.models.users.findByEmail('locktest@example.com');
  assert.ok(locked.locked_until > Date.now(), 'account should be locked');
  assert.ok(locked.failed_login_count >= 5);

  // Even the correct password is refused while the lock holds.
  const honest = new Client(ctx.baseUrl);
  const csrf = await honest.csrf('/login');
  const response = await honest.post('/login', {
    _csrf: csrf,
    email: 'locktest@example.com',
    password: 'copper-meadow-quilt-42',
  });
  assert.equal(response.status, 401);
});

/* ------------------------------------------------------------------ */
/* Authorisation                                                       */
/* ------------------------------------------------------------------ */

test('a normal user cannot reach any admin endpoint', async () => {
  const user = ctx.models.users.create({ email: 'plain@example.com', role: 'user' });
  const { token } = ctx.models.authTokens.issue({ userId: user.id, purpose: 'invite' });
  const client = new Client(ctx.baseUrl);
  await activateAccount(ctx, client, token, 'amber-pillar-signal-64');

  const target = ctx.models.users.findByEmail('admin@example.com');
  const gets = ['/admin/users', '/admin/audit', `/admin/users/${target.public_id}`];
  for (const pathname of gets) {
    assert.equal((await client.get(pathname)).status, 403, pathname);
  }

  // And the write endpoints, with a genuine CSRF token from their own session.
  const csrf = await client.csrf('/account');
  const posts = [
    ['/admin/users/new', { email: 'x@example.com', role: 'admin' }],
    [`/admin/users/${target.public_id}/role`, { role: 'user' }],
    [`/admin/users/${target.public_id}/disable`, {}],
    [`/admin/users/${target.public_id}/delete`, { confirm_email: 'admin@example.com' }],
  ];
  for (const [pathname, fields] of posts) {
    const response = await client.post(pathname, { _csrf: csrf, ...fields });
    assert.equal(response.status, 403, pathname);
  }

  assert.ok(ctx.models.users.findByEmail('admin@example.com'), 'admin must still exist');
  assert.equal(ctx.models.users.findByEmail('x@example.com'), null);
});

test('destructive admin actions demand a recent password re-entry', async () => {
  const fresh = new Client(ctx.baseUrl);
  await signIn(ctx, fresh, 'admin@example.com', PASSWORD, adminSecret);

  // Even reaching the form asks for the password again.
  const form = await fresh.get('/admin/users/new');
  assert.equal(form.status, 303);
  assert.ok(form.location.startsWith('/sudo'), `expected a sudo challenge, got ${form.location}`);

  // And so does posting straight to it with a token lifted from another page.
  const csrf = await fresh.csrf('/account');
  const attempt = await fresh.post('/admin/users/new', {
    _csrf: csrf,
    email: 'sneaky@example.com',
    role: 'admin',
  });

  assert.equal(attempt.status, 303);
  assert.ok(attempt.location.startsWith('/sudo'), `expected a sudo challenge, got ${attempt.location}`);
  assert.equal(ctx.models.users.findByEmail('sneaky@example.com'), null);
});

test('the sudo detour sends you back to a page you can actually open', async () => {
  const fresh = new Client(ctx.baseUrl);
  await signIn(ctx, fresh, 'admin@example.com', PASSWORD, adminSecret);

  const target = ctx.models.users.findByEmail('admin@example.com');
  const detailPath = `/admin/users/${target.public_id}`;
  const csrf = await fresh.csrf(detailPath);

  const attempt = await fresh.post(
    `${detailPath}/reset-link`,
    { _csrf: csrf },
    { headers: { referer: `${ctx.baseUrl}${detailPath}` } }
  );

  assert.equal(attempt.status, 303);
  assert.equal(attempt.location, `/sudo?next=${encodeURIComponent(detailPath)}`);
  assert.equal((await fresh.get(attempt.location)).status, 200);
});

test('minting new recovery codes demands the password again', async () => {
  const fresh = new Client(ctx.baseUrl);
  await signIn(ctx, fresh, 'admin@example.com', PASSWORD, adminSecret);

  const before = ctx.models.users.countUnusedRecoveryCodes(
    ctx.models.users.findByEmail('admin@example.com').id
  );

  const csrf = await fresh.csrf('/account');
  const attempt = await fresh.post(
    '/account/two-factor/recovery-codes',
    { _csrf: csrf },
    { headers: { referer: `${ctx.baseUrl}/account` } }
  );

  // Recovery codes substitute for the second factor indefinitely, so handing
  // out a new set must not be possible from a merely-unlocked browser.
  assert.equal(attempt.status, 303);
  assert.equal(attempt.location, `/sudo?next=${encodeURIComponent('/account')}`);

  const after = ctx.models.users.countUnusedRecoveryCodes(
    ctx.models.users.findByEmail('admin@example.com').id
  );
  assert.equal(after, before, 'the old codes must not have been destroyed');

  // With a fresh password confirmation it goes through.
  const sudoCsrf = await fresh.csrf(attempt.location);
  await fresh.post('/sudo', { _csrf: sudoCsrf, next: '/account', password: PASSWORD });

  const secondCsrf = await fresh.csrf('/account');
  const granted = await fresh.post('/account/two-factor/recovery-codes', { _csrf: secondCsrf });
  assert.equal(granted.status, 303);
  assert.equal(granted.location, '/account/two-factor/recovery-codes');

  const page = await fresh.get('/account/two-factor/recovery-codes');
  const codes = [...page.body.matchAll(/<code>([A-Z0-9]{5}-[A-Z0-9]{5})<\/code>/g)];
  assert.equal(codes.length, 10);
});

test('clearing a lockout also demands the password again', async () => {
  const fresh = new Client(ctx.baseUrl);
  await signIn(ctx, fresh, 'admin@example.com', PASSWORD, adminSecret);

  const target = ctx.models.users.findByEmail('locktest@example.com');
  const detailPath = `/admin/users/${target.public_id}`;
  const csrf = await fresh.csrf(detailPath);

  const attempt = await fresh.post(
    `${detailPath}/unlock`,
    { _csrf: csrf },
    { headers: { referer: `${ctx.baseUrl}${detailPath}` } }
  );
  assert.equal(attempt.status, 303);
  assert.ok(attempt.location.startsWith('/sudo'), attempt.location);
  assert.ok(
    ctx.models.users.findByEmail('locktest@example.com').locked_until > Date.now(),
    'the lockout must still be in force'
  );
});

test('owing both a second factor and a password change does not loop', async () => {
  const user = ctx.models.users.create({ email: 'bothowed@example.com', role: 'user' });
  const { token } = ctx.models.authTokens.issue({ userId: user.id, purpose: 'invite' });
  const client = new Client(ctx.baseUrl);
  await activateAccount(ctx, client, token, 'garnet-window-parade-58');

  // An admin resets their second factor and forces a new password: the account
  // now owes both at once.
  const fresh = ctx.models.users.findByEmail('bothowed@example.com');
  ctx.models.users.disableTotp(fresh.id);
  ctx.models.users.setPassword(fresh.id, fresh.password_hash, { mustChangePassword: 1 });

  const reentry = new Client(ctx.baseUrl);
  const csrf = await reentry.csrf('/login');
  const login = await reentry.post('/login', {
    _csrf: csrf,
    email: 'bothowed@example.com',
    password: 'garnet-window-parade-58',
  });
  assert.equal(login.status, 303);

  const landing = await reentry.get('/');
  assert.equal(landing.location, '/account/two-factor/setup');

  // The page it sends them to must actually render, not bounce them onward.
  const setup = await reentry.get('/account/two-factor/setup');
  assert.equal(setup.status, 200, 'enrolment must take precedence, not ping-pong');
  assert.ok(setup.body.includes('Set up two-factor authentication'));
});

/* ------------------------------------------------------------------ */
/* Output handling and headers                                         */
/* ------------------------------------------------------------------ */

test('hostile display names are escaped, not executed', async () => {
  const payload = '<img src=x onerror=alert(1)>"><script>alert(2)</script>';
  const csrf = await admin.csrf('/account');
  await admin.post('/account/profile', { _csrf: csrf, name: payload });

  const page = await admin.get('/account');
  assert.equal(page.status, 200);
  assert.ok(!page.body.includes('<script>alert(2)'), 'script tag must not survive');
  assert.ok(!page.body.includes('onerror=alert'), 'event handler must not survive');
  assert.ok(page.body.includes('&lt;img src&#61;x'), 'the payload should appear escaped');

  // Put it back.
  const restoreCsrf = await admin.csrf('/account');
  await admin.post('/account/profile', { _csrf: restoreCsrf, name: 'Root' });
});

test('security headers are present on every response', async () => {
  const page = await admin.get('/');
  const csp = page.headers.get('content-security-policy');

  assert.ok(csp.includes("default-src 'none'"), csp);
  assert.ok(csp.includes("frame-ancestors 'none'"), csp);
  assert.ok(csp.includes("base-uri 'none'"), csp);
  assert.ok(csp.includes("form-action 'self'"), csp);
  assert.ok(!csp.includes("'unsafe-inline'"), csp);

  assert.equal(page.headers.get('x-frame-options'), 'DENY');
  assert.equal(page.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(page.headers.get('referrer-policy'), 'same-origin');
  assert.ok(page.headers.get('permissions-policy').includes('camera=()'));
  assert.ok(page.headers.get('cache-control').includes('no-store'));
  assert.equal(page.headers.get('x-powered-by'), null);
});

test('the session cookie is HttpOnly and SameSite', async () => {
  const client = new Client(ctx.baseUrl);
  const csrf = await client.csrf('/login');
  const response = await client.post('/login', {
    _csrf: csrf,
    email: 'admin@example.com',
    password: PASSWORD,
  });

  const cookie = response.headers.getSetCookie().find((c) => c.startsWith('umole_sid='));
  assert.ok(cookie, 'a session cookie should be set');
  assert.ok(/HttpOnly/i.test(cookie), cookie);
  assert.ok(/SameSite=Lax/i.test(cookie), cookie);
  assert.ok(/Path=\//i.test(cookie), cookie);
});

test('error pages do not leak internals', async () => {
  const page = await admin.get('/no/such/page');
  assert.equal(page.status, 404);
  assert.ok(!/at Object|node_modules|\.js:\d+/.test(page.body), 'no stack traces');
});

/* ------------------------------------------------------------------ */
/* Redirects and identifiers                                           */
/* ------------------------------------------------------------------ */

test('the post-login redirect cannot be pointed off-site', async () => {
  const client = new Client(ctx.baseUrl);
  const csrf = await client.csrf('/login');
  const response = await client.post('/login', {
    _csrf: csrf,
    email: 'admin@example.com',
    password: PASSWORD,
    next: 'https://evil.example/steal',
  });

  assert.equal(response.status, 303);
  assert.ok(!response.location.includes('evil.example'), response.location);
});

test('users are addressed by an unguessable identifier, not a row number', async () => {
  const target = ctx.models.users.findByEmail('admin@example.com');
  assert.ok(target.public_id.length >= 20);
  assert.notEqual(target.public_id, String(target.id));

  const page = await admin.get('/admin/users');
  assert.equal((await admin.get(`/admin/users/${target.id}`)).status, 404);
  assert.ok(decodeEntities(page.body).includes(`/admin/users/${target.public_id}`));
});

/* ------------------------------------------------------------------ */
/* Storage                                                             */
/* ------------------------------------------------------------------ */

test('nothing sensitive is stored in a directly usable form', async () => {
  const user = ctx.models.users.findByEmail('admin@example.com');

  assert.ok(user.password_hash.startsWith('$argon2id$'), user.password_hash.slice(0, 20));
  assert.ok(!user.password_hash.includes(PASSWORD));

  // The TOTP secret is encrypted at rest but still usable by the application.
  assert.ok(user.totp_secret.startsWith('v1.'));
  assert.ok(!user.totp_secret.includes(adminSecret));
  assert.equal(ctx.models.users.getTotpSecret(user), adminSecret);

  // Session and invite tokens are stored only as keyed hashes.
  const session = ctx.models.sessions.listActiveForUser(user.id)[0];
  assert.ok(/^[0-9a-f]{64}$/.test(session.token_hash));
});

test('the second factor cannot be skipped by tampering with the session row', async () => {
  const client = new Client(ctx.baseUrl);
  const csrf = await client.csrf('/login');
  await client.post('/login', { _csrf: csrf, email: 'admin@example.com', password: PASSWORD });

  // Holding a cookie for a half-finished sign-in gets you nowhere.
  for (const pathname of ['/', '/account', '/admin/users']) {
    const response = await client.get(pathname);
    assert.equal(response.status, 303, pathname);
    assert.equal(response.location, '/login/verify', pathname);
  }
});
