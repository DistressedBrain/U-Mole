#!/usr/bin/env node
'use strict';

/**
 * Bootstrap the first administrator.
 *
 * Deliberately does NOT set a password. It creates the account and prints a
 * one-time invite link; the human opens it, chooses their own password and
 * enrols a second factor. That way no password ever passes through a shell
 * history, a process list or a deployment log.
 *
 * Usage:
 *   node scripts/create-admin.js you@example.com "Your Name"
 */

const readline = require('node:readline/promises');
const { stdin, stdout } = require('node:process');

const config = require('../src/config');
const { getDb, closeDb } = require('../src/db');
const users = require('../src/models/users');
const authTokens = require('../src/models/auth-tokens');
const audit = require('../src/models/audit');

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

async function main() {
  getDb();

  let email = process.argv[2];
  let name = process.argv[3] || '';

  if (!email) {
    const rl = readline.createInterface({ input: stdin, output: stdout });
    email = await rl.question('Email address for the first administrator: ');
    name = await rl.question('Display name (optional): ');
    rl.close();
  }

  email = users.normaliseEmail(email);
  if (!EMAIL_PATTERN.test(email)) {
    throw new Error(`Not a valid email address: ${email}`);
  }

  let user = users.findByEmail(email);
  if (user) {
    if (user.role !== 'admin') {
      users.setRole(user.id, 'admin');
      user = users.findById(user.id);
      console.log(`Existing account ${email} promoted to admin.`);
    } else {
      console.log(`Account ${email} already exists and is an admin.`);
    }
    if (user.password_hash) {
      console.log(
        'It already has a password. Sign in normally, or use the admin UI to issue a reset link.'
      );
      return;
    }
  } else {
    user = users.create({ email, name: name.trim(), role: 'admin' });
    console.log(`Created admin account ${email}.`);
  }

  const { token, expiresAt } = authTokens.issue({ userId: user.id, purpose: 'invite' });
  audit.record({
    event: 'admin.bootstrap',
    actorEmail: 'cli',
    targetUserId: user.id,
    targetEmail: user.email,
    detail: { via: 'scripts/create-admin.js' },
  });

  const url = `${config.appUrl}/activate?token=${encodeURIComponent(token)}`;

  console.log('\nOpen this link to choose a password and enrol two-factor authentication:\n');
  console.log(`  ${url}\n`);
  console.log(`It can be used once and expires ${new Date(expiresAt).toISOString()}.`);
  if (!config.session.cookieSecure) {
    console.log(
      '\nNote: APP_URL is not https://. Set it to the real public HTTPS address before ' +
        'inviting anyone, or the link (and the session cookie) will not be protected in transit.'
    );
  }
}

main()
  .then(() => closeDb())
  .catch((error) => {
    console.error(`\n${error.message}\n`);
    closeDb();
    process.exit(1);
  });
