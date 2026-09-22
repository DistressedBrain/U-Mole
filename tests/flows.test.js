'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  startApp,
  Client,
  activateAccount,
  signIn,
  inviteUser,
  bootstrapAdmin,
  freshTotpCode,
} = require('./helpers');

const ADMIN_PASSWORD = 'violet-harbour-tempo-91';
const USER_PASSWORD = 'quiet-lantern-fjord-73';

let ctx;

test.before(async () => {
  ctx = await startApp();
});

test.after(async () => {
  await ctx.stop();
});

test('every page is private until you sign in', async () => {
  const anon = new Client(ctx.baseUrl);
  for (const pathname of ['/', '/account', '/admin/users', '/admin/audit']) {
    const response = await anon.get(pathname);
    assert.equal(response.status, 303, `${pathname} should redirect`);
    assert.ok(response.location.startsWith('/login'), `${pathname} -> ${response.location}`);
  }
});

test('the invite link takes a new admin all the way to a signed-in session', async () => {
  const { inviteToken } = await bootstrapAdmin(ctx);
  const admin = new Client(ctx.baseUrl);

  const { secret, recoveryCodes } = await activateAccount(ctx, admin, inviteToken, ADMIN_PASSWORD);

  assert.equal(recoveryCodes.length, 10);
  assert.ok(secret.length >= 32);

  const dashboard = await admin.get('/');
  assert.equal(dashboard.status, 200);
  assert.ok(dashboard.body.includes('Dashboard'));

  ctx.admin = { client: admin, secret, recoveryCodes, email: 'admin@example.com' };
});

test('an invite link cannot be redeemed twice', async () => {
  const { inviteToken } = await bootstrapAdmin(ctx, 'twice@example.com');
  const first = new Client(ctx.baseUrl);
  await activateAccount(ctx, first, inviteToken, 'copper-meadow-quilt-42');

  const second = new Client(ctx.baseUrl);
  const csrf = await second.csrf('/login'); // anonymous CSRF cookie
  const replay = await second.post('/activate', {
    _csrf: csrf,
    token: inviteToken,
    password: 'another-valid-passphrase-8',
    confirm: 'another-valid-passphrase-8',
  });
  assert.equal(replay.status, 400);
});

test('signing in requires the second factor', async () => {
  const client = new Client(ctx.baseUrl);
  const csrf = await client.csrf('/login');

  const login = await client.post('/login', {
    _csrf: csrf,
    email: ctx.admin.email,
    password: ADMIN_PASSWORD,
  });
  assert.equal(login.status, 303);
  assert.equal(login.location, '/login/verify');

  // The password alone gets you nowhere.
  const blocked = await client.get('/');
  assert.equal(blocked.status, 303);
  assert.equal(blocked.location, '/login/verify');

  const verifyCsrf = await client.csrf('/login/verify');
  const code = freshTotpCode(ctx, ctx.admin.email, ctx.admin.secret);
  const verified = await client.post('/login/verify', { _csrf: verifyCsrf, mode: 'totp', code });
  assert.equal(verified.status, 303);

  const dashboard = await client.get('/');
  assert.equal(dashboard.status, 200);
});

test('the session identifier changes after the second factor', async () => {
  const client = new Client(ctx.baseUrl);
  const csrf = await client.csrf('/login');
  await client.post('/login', { _csrf: csrf, email: ctx.admin.email, password: ADMIN_PASSWORD });

  const beforeVerification = client.cookies.get('umole_sid');
  const verifyCsrf = await client.csrf('/login/verify');
  const code = freshTotpCode(ctx, ctx.admin.email, ctx.admin.secret);
  await client.post('/login/verify', { _csrf: verifyCsrf, mode: 'totp', code });
  const afterVerification = client.cookies.get('umole_sid');

  assert.notEqual(beforeVerification, afterVerification);

  // The pre-verification identifier is dead, not merely superseded.
  const stale = new Client(ctx.baseUrl);
  stale.cookies.set('umole_sid', beforeVerification);
  const response = await stale.get('/');
  assert.equal(response.status, 303);
  assert.ok(response.location.startsWith('/login'));
});

test('a TOTP code cannot be replayed', async () => {
  // No rewinding of the replay marker here: this is the real behaviour a
  // network eavesdropper would run into.
  const client = new Client(ctx.baseUrl);
  const csrf = await client.csrf('/login');
  await client.post('/login', { _csrf: csrf, email: ctx.admin.email, password: ADMIN_PASSWORD });

  const verifyCsrf = await client.csrf('/login/verify');
  const code = freshTotpCode(ctx, ctx.admin.email, ctx.admin.secret);
  const first = await client.post('/login/verify', { _csrf: verifyCsrf, mode: 'totp', code });
  assert.equal(first.status, 303);

  const second = new Client(ctx.baseUrl);
  const secondCsrf = await second.csrf('/login');
  await second.post('/login', {
    _csrf: secondCsrf,
    email: ctx.admin.email,
    password: ADMIN_PASSWORD,
  });
  const replayCsrf = await second.csrf('/login/verify');
  const replay = await second.post('/login/verify', {
    _csrf: replayCsrf,
    mode: 'totp',
    code,
  });
  assert.equal(replay.status, 401, 'the same code must not work a second time');
});

test('a recovery code works once and then is spent', async () => {
  const client = new Client(ctx.baseUrl);
  const csrf = await client.csrf('/login');
  await client.post('/login', { _csrf: csrf, email: ctx.admin.email, password: ADMIN_PASSWORD });

  const code = ctx.admin.recoveryCodes[0];
  const verifyCsrf = await client.csrf('/login/verify?mode=recovery');
  const used = await client.post('/login/verify', {
    _csrf: verifyCsrf,
    mode: 'recovery',
    recovery: code,
  });
  assert.equal(used.status, 303);
  assert.equal((await client.get('/')).status, 200);

  const again = new Client(ctx.baseUrl);
  const againCsrf = await again.csrf('/login');
  await again.post('/login', { _csrf: againCsrf, email: ctx.admin.email, password: ADMIN_PASSWORD });
  const replayCsrf = await again.csrf('/login/verify?mode=recovery');
  const replay = await again.post('/login/verify', {
    _csrf: replayCsrf,
    mode: 'recovery',
    recovery: code,
  });
  assert.equal(replay.status, 401);
});

test('an admin can invite a user, who then reaches the site but not the admin area', async () => {
  const inviteToken = await inviteUser(ctx, ctx.admin.client, {
    email: 'member@example.com',
    name: 'Member',
    role: 'user',
    password: ADMIN_PASSWORD,
  });

  const member = new Client(ctx.baseUrl);
  const { secret } = await activateAccount(ctx, member, inviteToken, USER_PASSWORD);

  assert.equal((await member.get('/')).status, 200);
  assert.equal((await member.get('/account')).status, 200);
  assert.equal((await member.get('/admin/users')).status, 403);
  assert.equal((await member.get('/admin/audit')).status, 403);

  ctx.member = { client: member, secret, email: 'member@example.com' };
});

test('an admin can disable a user, which cuts their session immediately', async () => {
  const detail = await ctx.admin.client.get('/admin/users');
  assert.ok(detail.body.includes('member@example.com'));

  const target = ctx.models.users.findByEmail('member@example.com');
  const page = await ctx.admin.client.get(`/admin/users/${target.public_id}`);
  const csrf = page.body.match(/name="_csrf" value="([^"]+)"/)[1];

  const disabled = await ctx.admin.client.post(
    `/admin/users/${target.public_id}/disable`,
    { _csrf: csrf }
  );
  assert.equal(disabled.status, 303);

  // The member's existing cookie stops working on the very next request.
  const response = await ctx.member.client.get('/');
  assert.equal(response.status, 303);
  assert.ok(response.location.startsWith('/login'));

  // And they cannot sign in again.
  const retry = new Client(ctx.baseUrl);
  const loginCsrf = await retry.csrf('/login');
  const login = await retry.post('/login', {
    _csrf: loginCsrf,
    email: 'member@example.com',
    password: USER_PASSWORD,
  });
  assert.equal(login.status, 401);
});

test('changing your password signs out every other session', async () => {
  const inviteToken = await inviteUser(ctx, ctx.admin.client, {
    email: 'rotator@example.com',
    password: ADMIN_PASSWORD,
  });

  const first = new Client(ctx.baseUrl);
  const { secret } = await activateAccount(ctx, first, inviteToken, 'amber-pillar-signal-64');

  const second = new Client(ctx.baseUrl);
  const signedIn = await signIn(ctx, second, 'rotator@example.com', 'amber-pillar-signal-64', secret);
  assert.equal(signedIn.status, 303);
  assert.equal((await second.get('/')).status, 200);

  const csrf = await first.csrf('/account/password');
  const changed = await first.post('/account/password', {
    _csrf: csrf,
    current: 'amber-pillar-signal-64',
    password: 'garnet-window-parade-58',
    confirm: 'garnet-window-parade-58',
  });
  assert.equal(changed.status, 303);

  assert.equal((await first.get('/')).status, 200, 'the session that changed it survives');
  const other = await second.get('/');
  assert.equal(other.status, 303, 'the other session is gone');
});

test('the audit log records sign-ins, failures and administrative actions', async () => {
  const page = await ctx.admin.client.get('/admin/audit');
  assert.equal(page.status, 200);
  for (const event of ['auth.login', 'admin.user_created', 'admin.user_disabled']) {
    assert.ok(page.body.includes(event), `expected ${event} in the audit log`);
  }
});

test('an administrator cannot lock the site out by demoting the last admin', async () => {
  const target = ctx.models.users.findByEmail('admin@example.com');
  const page = await ctx.admin.client.get(`/admin/users/${target.public_id}`);
  const csrf = page.body.match(/name="_csrf" value="([^"]+)"/)[1];

  const demote = await ctx.admin.client.post(`/admin/users/${target.public_id}/role`, {
    _csrf: csrf,
    role: 'user',
  });
  assert.equal(demote.status, 409);

  const deleted = await ctx.admin.client.post(`/admin/users/${target.public_id}/delete`, {
    _csrf: csrf,
    confirm_email: 'admin@example.com',
  });
  assert.equal(deleted.status, 409);

  assert.equal(ctx.models.users.findByEmail('admin@example.com').role, 'admin');
});

test('signing out invalidates the session server-side', async () => {
  const client = new Client(ctx.baseUrl);
  await signIn(ctx, client, ctx.admin.email, ADMIN_PASSWORD, ctx.admin.secret);
  const cookie = client.cookies.get('umole_sid');

  const csrf = await client.csrf('/account');
  const out = await client.post('/logout', { _csrf: csrf });
  assert.equal(out.status, 303);

  const replay = new Client(ctx.baseUrl);
  replay.cookies.set('umole_sid', cookie);
  const response = await replay.get('/');
  assert.equal(response.status, 303);
  assert.ok(response.location.startsWith('/login'));
});
