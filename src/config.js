'use strict';

require('dotenv').config();

const path = require('node:path');

function required(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `Missing required environment variable ${name}. ` +
        'Copy .env.example to .env and fill it in (see README).'
    );
  }
  return value;
}

function int(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) {
    throw new Error(`Environment variable ${name} must be an integer, got ${raw}`);
  }
  return parsed;
}

function bool(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  return raw === '1' || raw.toLowerCase() === 'true';
}

const env = process.env.NODE_ENV || 'development';
const isProduction = env === 'production';
const isTest = env === 'test';

const secretHex = isTest ? process.env.SECRET_KEY || 'a'.repeat(64) : required('SECRET_KEY');
if (!/^[0-9a-fA-F]{64}$/.test(secretHex)) {
  throw new Error('SECRET_KEY must be exactly 64 hexadecimal characters. Run: node scripts/gen-secret.js');
}

const appUrl = (process.env.APP_URL || `http://localhost:${int('PORT', 3000)}`).replace(/\/+$/, '');
let appOrigin;
try {
  appOrigin = new URL(appUrl).origin;
} catch {
  throw new Error(`APP_URL is not a valid absolute URL: ${appUrl}`);
}

// Cookies are only marked Secure over HTTPS; the `__Host-` prefix requires it.
const cookieSecure = appUrl.startsWith('https://');
if (isProduction && !cookieSecure) {
  // eslint-disable-next-line no-console
  console.warn(
    '[security] APP_URL is not https:// — session cookies will not be marked Secure. ' +
      'Serve this application over TLS in production.'
  );
}

const config = {
  env,
  isProduction,
  isTest,
  port: int('PORT', 3000),
  host: process.env.HOST || '127.0.0.1',
  appUrl,
  appOrigin,
  secret: Buffer.from(secretHex, 'hex'),
  databasePath:
    process.env.DATABASE_PATH || path.join(__dirname, '..', 'data', 'umole.sqlite3'),
  trustProxy: bool('TRUST_PROXY', false),

  session: {
    cookieName: cookieSecure ? '__Host-umole_sid' : 'umole_sid',
    cookieSecure,
    idleTimeoutMs: int('SESSION_IDLE_TIMEOUT_MINUTES', 30) * 60 * 1000,
    absoluteTimeoutMs: int('SESSION_ABSOLUTE_TIMEOUT_HOURS', 12) * 60 * 60 * 1000,
    sudoTimeoutMs: int('SUDO_TIMEOUT_MINUTES', 15) * 60 * 1000,
  },

  totp: {
    issuer: process.env.TOTP_ISSUER || 'U-Mole',
    stepSeconds: 30,
    digits: 6,
    // Accept the previous and next step to tolerate clock drift.
    window: 1,
  },

  invites: {
    ttlMs: int('INVITE_TTL_HOURS', 48) * 60 * 60 * 1000,
  },

  password: {
    minLength: 12,
    maxLength: 128,
    // Argon2id parameters, comfortably above the OWASP minimum
    // (19 MiB / t=2 / p=1). Raise them until a hash takes ~0.5s on your
    // hardware; the test suite turns them down so it can run quickly.
    memoryCost: int('PASSWORD_MEMORY_COST_KIB', 64 * 1024), // 64 MiB
    timeCost: int('PASSWORD_TIME_COST', 3),
    parallelism: int('PASSWORD_PARALLELISM', 1),
  },

  lockout: {
    // Failed attempts before the account itself is locked.
    threshold: 5,
    baseLockMs: 15 * 60 * 1000,
    maxLockMs: 4 * 60 * 60 * 1000,
  },

  rateLimits: {
    global: { limit: 600, windowMs: 60 * 1000 },
    login: { limit: 20, windowMs: 15 * 60 * 1000 },
    mfa: { limit: 10, windowMs: 15 * 60 * 1000 },
    tokenRedeem: { limit: 20, windowMs: 60 * 60 * 1000 },
    sensitive: { limit: 60, windowMs: 60 * 1000 },
  },
};

module.exports = config;
