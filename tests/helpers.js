'use strict';

const net = require('node:net');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

/** Reserve a port before the config module reads APP_URL. */
async function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

/**
 * Boot a completely fresh application: new database file, new secret, new
 * port. Every test file gets its own, so nothing leaks between them.
 */
async function startApp(overrides = {}) {
  const port = await freePort();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'umole-test-'));
  const dbPath = path.join(dir, 'test.sqlite3');

  process.env.NODE_ENV = 'test';
  process.env.PORT = String(port);
  process.env.HOST = '127.0.0.1';
  process.env.APP_URL = `http://127.0.0.1:${port}`;
  process.env.SECRET_KEY = crypto.randomBytes(32).toString('hex');
  process.env.DATABASE_PATH = dbPath;
  process.env.TRUST_PROXY = '0';
  // Keep Argon2 honest but fast enough for a test run.
  process.env.PASSWORD_MEMORY_COST_KIB = '8192';
  process.env.PASSWORD_TIME_COST = '1';
  Object.assign(process.env, overrides);

  // Fresh module registry so config/db pick up the environment above.
  for (const key of Object.keys(require.cache)) {
    if (key.includes(`${path.sep}src${path.sep}`)) delete require.cache[key];
  }

  const config = require('../src/config');
  const { createApp } = require('../src/app');
  const { closeDb } = require('../src/db');

  const app = createApp();
  const server = await new Promise((resolve) => {
    const s = app.listen(port, '127.0.0.1', () => resolve(s));
  });

  return {
    port,
    config,
    baseUrl: `http://127.0.0.1:${port}`,
    models: {
      users: require('../src/models/users'),
      sessions: require('../src/models/sessions'),
      authTokens: require('../src/models/auth-tokens'),
      audit: require('../src/models/audit'),
    },
    lib: {
      totp: require('../src/lib/totp'),
    },
    async stop() {
      await new Promise((resolve) => server.close(resolve));
      closeDb();
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** Minimal browser: keeps cookies, follows nothing automatically. */
class Client {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.cookies = new Map();
  }

  cookieHeader() {
    return [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; ');
  }

  absorb(response) {
    for (const raw of response.headers.getSetCookie()) {
      const [pair, ...attributes] = raw.split(';');
      const index = pair.indexOf('=');
      const name = pair.slice(0, index).trim();
      const value = pair.slice(index + 1).trim();
      const expired = attributes.some((a) => /expires=thu, 01 jan 1970/i.test(a.trim()));
      if (!value || expired) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
  }

  async get(pathname, { headers = {} } = {}) {
    const response = await fetch(new URL(pathname, this.baseUrl), {
      redirect: 'manual',
      headers: { cookie: this.cookieHeader(), ...headers },
    });
    this.absorb(response);
    return withBody(response);
  }

  async post(pathname, fields = {}, { headers = {}, origin = this.baseUrl } = {}) {
    const body = new URLSearchParams(fields).toString();
    const response = await fetch(new URL(pathname, this.baseUrl), {
      method: 'POST',
      redirect: 'manual',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        cookie: this.cookieHeader(),
        ...(origin ? { origin } : {}),
        ...headers,
      },
      body,
    });
    this.absorb(response);
    return withBody(response);
  }

  /** Fetch a page and pull the CSRF token out of its form. */
  async csrf(pathname) {
    const page = await this.get(pathname);
    const match = page.body.match(/name="_csrf" value="([^"]+)"/);
    if (!match) throw new Error(`No CSRF token on ${pathname} (status ${page.status})`);
    return match[1];
  }
}

async function withBody(response) {
  const body = await response.text();
  return {
    status: response.status,
    headers: response.headers,
    location: response.headers.get('location'),
    body,
  };
}

/** Walk an account from invite link to fully enrolled and signed in. */
async function activateAccount(ctx, client, inviteToken, password) {
  const csrf = await client.csrf(`/activate?token=${encodeURIComponent(inviteToken)}`);
  const activated = await client.post('/activate', {
    _csrf: csrf,
    token: inviteToken,
    password,
    confirm: password,
  });
  if (activated.status !== 303) {
    throw new Error(`Activation failed (${activated.status}): ${activated.body.slice(0, 400)}`);
  }

  const setup = await client.get('/account/two-factor/setup');
  const secret = setup.body.match(/<code class="secret">([A-Z2-7]+)<\/code>/)[1];
  const setupCsrf = setup.body.match(/name="_csrf" value="([^"]+)"/)[1];

  const code = ctx.lib.totp.hotp(
    ctx.lib.totp.base32Decode(secret),
    ctx.lib.totp.currentStep(),
    6
  );
  const enrolled = await client.post('/account/two-factor/setup', { _csrf: setupCsrf, code });
  if (enrolled.status !== 303) {
    throw new Error(`Enrolment failed (${enrolled.status}): ${enrolled.body.slice(0, 400)}`);
  }

  const codesPage = await client.get('/account/two-factor/recovery-codes');
  const recoveryCodes = [...codesPage.body.matchAll(/<code>([A-Z0-9]{5}-[A-Z0-9]{5})<\/code>/g)].map(
    (m) => m[1]
  );

  return { secret, recoveryCodes };
}

/**
 * A TOTP code can be spent only once, so two sign-ins inside the same
 * 30-second window would otherwise need a real 30-second wait. Rewinding the
 * account's replay marker by one step is the same thing as that window having
 * passed, and keeps the suite fast.
 *
 * The replay protection itself is tested directly, without this helper, in
 * `a TOTP code cannot be replayed` and in the unit tests.
 */
function freshTotpCode(ctx, email, secret) {
  const user = ctx.models.users.findByEmail(email);
  const step = ctx.lib.totp.currentStep();
  if (user) ctx.models.users.setTotpLastStep(user.id, step - 1);
  return ctx.lib.totp.hotp(ctx.lib.totp.base32Decode(secret), step, 6);
}

/** Sign in from scratch, including the second factor. */
async function signIn(ctx, client, email, password, secret) {
  const csrf = await client.csrf('/login');
  const login = await client.post('/login', { _csrf: csrf, email, password });
  if (login.status !== 303) return login;

  const verifyCsrf = await client.csrf('/login/verify');
  const code = freshTotpCode(ctx, email, secret);
  return client.post('/login/verify', { _csrf: verifyCsrf, mode: 'totp', code });
}

/** Create a user through the admin UI and return their invite token. */
async function inviteUser(ctx, adminClient, { email, name = '', role = 'user', password }) {
  const sudoCsrf = await adminClient.csrf('/sudo?next=%2Fadmin%2Fusers%2Fnew');
  await adminClient.post('/sudo', { _csrf: sudoCsrf, next: '/admin/users/new', password });

  const csrf = await adminClient.csrf('/admin/users/new');
  const created = await adminClient.post('/admin/users/new', { _csrf: csrf, email, name, role });
  if (created.status !== 303) {
    throw new Error(`Create user failed (${created.status}): ${created.body.slice(0, 400)}`);
  }

  const detail = await adminClient.get(created.location);
  const match = decodeEntities(detail.body).match(/\/activate\?token=([^<"\s]+)/);
  if (!match) throw new Error('No invite link revealed after creating the user');
  return decodeURIComponent(match[1]);
}

/** The templates escape `&`, `=` and quotes, so undo that before matching URLs. */
function decodeEntities(text) {
  return text
    .replace(/&#61;/g, '=')
    .replace(/&#39;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&#96;/g, '`')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

/** Bootstrap the first admin the way scripts/create-admin.js does. */
async function bootstrapAdmin(ctx, email = 'admin@example.com') {
  const user = ctx.models.users.create({ email, name: 'Root', role: 'admin' });
  const { token } = ctx.models.authTokens.issue({ userId: user.id, purpose: 'invite' });
  return { user, inviteToken: token };
}

module.exports = {
  startApp,
  Client,
  decodeEntities,
  activateAccount,
  signIn,
  freshTotpCode,
  inviteUser,
  bootstrapAdmin,
};
