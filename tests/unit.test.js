'use strict';

process.env.NODE_ENV = 'test';

const test = require('node:test');
const assert = require('node:assert/strict');

const { html, raw, escapeHtml } = require('../src/lib/html');
const totp = require('../src/lib/totp');
const { checkPasswordStrength } = require('../src/lib/password');
const { encryptSecret, decryptSecret, timingSafeEqualStrings, hashToken } = require('../src/lib/crypto');
const { safeNextPath } = require('../src/middleware/auth');

test('html templates escape interpolated values', () => {
  const evil = '"><script>alert(1)</script>';
  const output = html`<p title="${evil}">${evil}</p>`.toString();
  assert.ok(!output.includes('<script>'));
  assert.ok(output.includes('&lt;script&gt;'));
});

test('html templates do not escape explicitly trusted fragments', () => {
  assert.equal(html`${raw('<b>ok</b>')}`.toString(), '<b>ok</b>');
});

test('escapeHtml covers attribute-breaking characters', () => {
  assert.equal(escapeHtml(`&<>"'\`=`), '&amp;&lt;&gt;&quot;&#39;&#96;&#61;');
});

test('arrays and nullish values render safely', () => {
  assert.equal(html`${[1, '<b>', null, undefined, false]}`.toString(), '1&lt;b&gt;');
});

test('TOTP matches the RFC 6238 test vectors', () => {
  const secret = totp.base32Encode(Buffer.from('12345678901234567890', 'ascii'));
  const buffer = totp.base32Decode(secret);
  assert.equal(totp.hotp(buffer, Math.floor(59 / 30), 8), '94287082');
  assert.equal(totp.hotp(buffer, Math.floor(1111111109 / 30), 8), '07081804');
  assert.equal(totp.hotp(buffer, Math.floor(1234567890 / 30), 8), '89005924');
  assert.equal(totp.hotp(buffer, Math.floor(2000000000 / 30), 8), '69279037');
});

test('TOTP accepts the current code and rejects a replay of it', () => {
  const secret = totp.generateSecret();
  const now = Date.now();
  const step = totp.currentStep(now);
  const code = totp.hotp(totp.base32Decode(secret), step, 6);

  assert.equal(totp.verifyTotp(secret, code, { now }), step);
  assert.equal(totp.verifyTotp(secret, code, { now, lastUsedStep: step }), null);
});

test('TOTP tolerates one step of clock drift but not two', () => {
  const secret = totp.generateSecret();
  const now = Date.now();
  const step = totp.currentStep(now);
  const decoded = totp.base32Decode(secret);

  assert.equal(totp.verifyTotp(secret, totp.hotp(decoded, step - 1, 6), { now }), step - 1);
  assert.equal(totp.verifyTotp(secret, totp.hotp(decoded, step + 1, 6), { now }), step + 1);
  assert.equal(totp.verifyTotp(secret, totp.hotp(decoded, step - 3, 6), { now }), null);
});

test('TOTP rejects malformed input without throwing', () => {
  const secret = totp.generateSecret();
  for (const bad of ['', '12345', '1234567', 'abcdef', null, undefined, '  ']) {
    assert.equal(totp.verifyTotp(secret, bad), null);
  }
  assert.equal(totp.verifyTotp('not base32!!', '123456'), null);
});

test('password policy rejects weak choices', () => {
  const cases = [
    'short',
    'password1234',
    'aaaaaaaaaaaaaa',
    'abcdefghijklmn',
    '              ',
  ];
  for (const password of cases) {
    assert.ok(
      checkPasswordStrength(password, { email: 'a@b.c', name: '' }).length > 0,
      `expected ${JSON.stringify(password)} to be rejected`
    );
  }
});

test('password policy rejects passwords containing the user identity', () => {
  const problems = checkPasswordStrength('jane.doe-is-here!', {
    email: 'jane.doe@example.com',
    name: 'Jane Doe',
  });
  assert.ok(problems.some((p) => p.includes('name, email')));
});

test('password policy accepts a reasonable passphrase', () => {
  assert.deepEqual(
    checkPasswordStrength('violet-harbour-tempo-91', {
      email: 'someone@example.com',
      name: 'Someone',
    }),
    []
  );
});

test('secrets survive an encrypt/decrypt round trip and reject tampering', () => {
  const encrypted = encryptSecret('JBSWY3DPEHPK3PXP');
  assert.notEqual(encrypted, 'JBSWY3DPEHPK3PXP');
  assert.equal(decryptSecret(encrypted), 'JBSWY3DPEHPK3PXP');

  const parts = encrypted.split('.');
  parts[3] = Buffer.from('tampered').toString('base64url');
  assert.equal(decryptSecret(parts.join('.')), null);
  assert.equal(decryptSecret('nonsense'), null);
});

test('encryption is randomised per call', () => {
  assert.notEqual(encryptSecret('same'), encryptSecret('same'));
});

test('token hashing is deterministic and one-way', () => {
  assert.equal(hashToken('abc'), hashToken('abc'));
  assert.notEqual(hashToken('abc'), hashToken('abd'));
  assert.ok(!hashToken('abc').includes('abc'));
});

test('constant-time comparison distinguishes length and content', () => {
  assert.equal(timingSafeEqualStrings('abc', 'abc'), true);
  assert.equal(timingSafeEqualStrings('abc', 'abcd'), false);
  assert.equal(timingSafeEqualStrings('abc', 'abd'), false);
  assert.equal(timingSafeEqualStrings('abc', null), false);
});

test('redirect targets outside this site are refused', () => {
  const rejected = [
    'https://evil.example/',
    '//evil.example/',
    '/\\evil.example',
    'javascript:alert(1)',
    '',
    null,
    `/ok\u0000`,
  ];
  for (const value of rejected) {
    assert.equal(safeNextPath(value), null, `expected ${JSON.stringify(value)} to be rejected`);
  }
  assert.equal(safeNextPath('/admin/users?offset=25'), '/admin/users?offset=25');
});
