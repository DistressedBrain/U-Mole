# U-Mole

A small website where **every page is behind a login**, accounts are created and
managed by administrators, and the security decisions are made conservatively by
default.

Node.js + Express + SQLite. No build step, no client-side framework, no external
services. Clone it, set two environment variables, and it runs.

---

## What it does

**For everyone**

- Sign in with an email address, a password and a six-digit code from an
  authenticator app. Two-factor authentication is mandatory, not optional.
- Recovery codes for when the phone is lost.
- Change your own password, see every device signed in as you, and sign any of
  them out.

**For administrators**

- Create accounts and hand out one-time invite links. There is no public
  sign-up form to attack.
- Promote and demote, disable and re-enable, delete.
- Issue password-reset links, reset somebody's second factor, clear a lockout,
  force a password change, sign a user out everywhere.
- Read an audit log of every sign-in, failed attempt and administrative action.

**Content**

`src/routes/app.js` holds the placeholder dashboard. Anything you add there is
private by default — see [Adding your own pages](#adding-your-own-pages).

---

## Getting started

```bash
npm install

cp .env.example .env
node scripts/gen-secret.js     # paste the output into SECRET_KEY in .env
$EDITOR .env                   # set APP_URL to your real public address

node scripts/create-admin.js you@example.com "Your Name"
npm start
```

`create-admin` prints a one-time link. Open it, choose a password, scan the QR
code with an authenticator app, and save the recovery codes it shows you — they
are displayed once and never again.

From then on, everything is done through the web interface at **Users**.

### Running the tests

```bash
npm test
```

50 tests covering the sign-in flow, two-factor enrolment and replay protection,
CSRF, account lockout, rate limiting, authorisation, output escaping and
storage. They start real servers on real ports against real SQLite databases.

---

## Configuration

Everything lives in `.env`. See `.env.example` for the full list; these are the
ones that matter most.

| Variable | Why it matters |
| --- | --- |
| `SECRET_KEY` | 64 hex characters. Peppers every password hash, encrypts TOTP secrets and keys the token index. **Changing or losing it invalidates every password, every session and every outstanding link.** Back it up separately from the database — holding both is what an attacker needs. |
| `APP_URL` | Your real public origin, e.g. `https://example.com`. Used for invite links *and* for rejecting cross-site form posts, so it must match exactly. Setting an `https://` URL is also what switches session cookies to `Secure` and the `__Host-` prefix. |
| `TRUST_PROXY` | `1` only when exactly one reverse proxy sits in front and sets `X-Forwarded-For`. Getting this wrong in either direction breaks rate limiting: left off behind a proxy, every visitor shares the proxy's address; turned on without one, any client can forge their address. |
| `DATABASE_PATH` | The SQLite file. It contains password hashes and encrypted secrets — back it up, and keep the backups as carefully as the file. |
| `SESSION_IDLE_TIMEOUT_MINUTES` / `SESSION_ABSOLUTE_TIMEOUT_HOURS` | 30 minutes idle, 12 hours absolute. Both are enforced server-side. |
| `PASSWORD_MEMORY_COST_KIB` | Argon2id memory, default 64 MiB. Raise it until hashing takes roughly half a second on your hardware. |

### Deploying

Run it behind a TLS-terminating reverse proxy. The application deliberately
does not speak HTTPS itself.

```nginx
server {
  listen 443 ssl http2;
  server_name example.com;

  # ssl_certificate ... ssl_certificate_key ...

  location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

With that in place set `TRUST_PROXY=1` and `APP_URL=https://example.com`, keep
the Node process bound to `127.0.0.1`, and run it under a supervisor
(systemd, Docker, pm2) as an unprivileged user.

---

## How the security works

Each of these is a deliberate choice, not a default that happened to be on.

### Passwords

Hashed with **Argon2id** at 64 MiB / 3 passes, the memory-hard function that
won the Password Hashing Competition and the one OWASP recommends first. Each
hash is also **peppered** with `SECRET_KEY`, which lives in the environment and
not in the database — so a stolen database alone cannot be attacked offline.
Cost parameters are checked on every sign-in and hashes are re-hashed
transparently when you raise them.

The policy follows NIST SP 800-63B: a 12-character minimum, a blocklist of
common and breached passwords, and rejection of anything containing the user's
own name or address — but no forced symbols, no forced expiry, and no silent
truncation. Length is what actually helps.

### Two-factor authentication

Standard **TOTP** (RFC 6238, HMAC-SHA1, 30-second steps), verified against the
RFC's own published test vectors in the test suite. It works with any
authenticator app.

- Shared secrets are **encrypted at rest** with AES-256-GCM under a key derived
  from `SECRET_KEY`, so the database alone does not yield working codes.
- Codes are **single use**: the time step a code belongs to is recorded, and
  anything at or before it is refused. Without this, a code captured by someone
  watching the network stays valid for up to 90 seconds.
- Comparison is constant-time over the whole accepted window, so response
  timing does not leak which step matched.
- Ten single-use recovery codes, stored only as keyed hashes. Because a
  recovery code substitutes for the second factor indefinitely, minting a new
  set asks for the password again first.

### Sessions

Server-side, in the database. The cookie carries nothing but a 256-bit random
identifier; the database stores its HMAC.

- A stolen database cannot be turned back into a working cookie.
- Revocation is immediate and total — no waiting for a token to expire.
- `HttpOnly`, `SameSite`, `Secure` and the `__Host-` prefix over HTTPS.
- The identifier is **rotated** on every privilege change: password accepted,
  second factor accepted, password changed, re-authentication granted. Session
  fixation has nothing to latch onto.
- Idle timeout *and* absolute timeout, both enforced server-side.
- Changing a password kills every other session. So does being disabled,
  having your role changed, having your email changed, or an administrator
  cutting you off.

### Cross-site request forgery

Two independent defences, because each has known gaps alone:

1. `Origin`/`Referer` must match `APP_URL`. A request with neither is refused.
2. A secret token must accompany the request — per-session for signed-in users,
   a double-submit cookie for the login and invite forms (login CSRF is a real
   attack, not a theoretical one).

Tokens are compared in constant time.

### Cross-site scripting

Templates are built with a tagged template literal that **escapes every
interpolation by default**. Getting it wrong requires explicitly calling
`raw()`. On top of that, a strict Content-Security-Policy: `default-src 'none'`,
scripts and styles from this origin only, no `unsafe-inline`, no `<base>`, forms
may only submit back to this site, and the page may not be framed.

### Brute force and enumeration

- Every sign-in failure produces the **same message, the same status code and
  the same timing** — a login for an account that does not exist is still
  verified against a decoy hash. There is no way to discover who has an account.
- Accounts lock after 5 failed attempts, with the lock doubling each further
  failure up to 4 hours. Failed second-factor attempts count too.
- Rate limits on sign-in, second-factor entry, token redemption and sensitive
  actions, applied **per address and per account** — so spraying one account
  from many addresses is caught as well. Counters live in SQLite, so a restart
  does not clear them.

### Administration

- **Re-authentication.** Actions that destroy something, weaken a defence, or
  mint new credentials require the password again within the last 15 minutes —
  deleting or disabling an account, changing a role, issuing an invite or reset
  link, resetting somebody's second factor, clearing a lockout, and generating
  recovery codes. An unattended browser is not enough.
- **Lockout prevention.** The application refuses to demote, disable or delete
  the last administrator who can actually sign in.
- **No self-inflicted wounds.** You cannot change your own role, disable
  yourself, or delete yourself.
- **Deletion is confirmed** by typing the email address.
- **Users are addressed by a random public identifier**, never by row number,
  so URLs reveal nothing and cannot be walked.

### Secrets that are shown once

Invite links, reset links and recovery codes are held in process memory for a
few minutes and shown a single time. They are never written to the database as
plaintext, never put in a query string, and so never end up in an access log or
a backup.

### Audit log

Sign-ins, failures, lockouts, rate-limit trips, enrolments, password changes and
every administrative action, with actor, target, address and timestamp.
Failures are recorded as carefully as successes — a log that only records
successes tells you nothing after a break-in.

### Other

- Database: WAL, `synchronous = FULL`, foreign keys on, extension loading off,
  file mode `0600`. Every query is parameterised.
- Only `GET`, `HEAD` and `POST` are accepted. Request bodies are capped at 32 KB
  and 64 fields. There is no JSON parser, because nothing here consumes JSON.
- Slow-loris timeouts on headers, requests and keep-alive.
- Error pages say almost nothing; detail goes to the server log.
- Schema migrations are versioned, and an older binary refuses to start against
  a newer database rather than corrupting it.

---

## Adding your own pages

Put them in `src/routes/app.js`, or add a router and mount it after the
authentication middleware in `src/app.js`:

```js
router.get('/reports', requireAuth, (req, res) => {
  res.send(views.reportsPage({ user: req.user }));
});
```

`requireAuth` guarantees: signed in, second factor passed, account active, and
no forced password change outstanding. For admin-only pages add `requireAdmin`;
for anything destructive add `requireSudo`.

Build HTML with the `html` tagged template from `src/lib/html.js` so that
escaping happens automatically:

```js
const { html } = require('../lib/html');
html`<p>Hello, ${user.name}</p>`;   // escaped, always
```

---

## Project layout

```
src/
  config.js            environment parsing and validation
  app.js               middleware stack and route mounting
  server.js            listener, timeouts, graceful shutdown
  housekeeping.js      periodic purge of expired rows
  db/                  connection, pragmas, versioned migrations
  lib/                 crypto, password policy, TOTP, HTML escaping
  middleware/          security headers, CSRF, authentication, rate limiting
  models/              users, sessions, tokens, audit log, rate limits
  routes/              auth, account, admin, and your content
  views/               server-rendered pages
public/app.css         the only static asset
scripts/               first-admin bootstrap, secret generation, cleanup
tests/                 unit, end-to-end flow, and security tests
```

---

## Operating it

**Back up** `DATABASE_PATH` and `SECRET_KEY` — and store them apart from each
other. Together they are the whole system.

**Housekeeping** runs in-process every 15 minutes. If you would rather drive it
from cron, `npm run housekeeping` does one pass.

**Watch the audit log** for `auth.login` failures, `ratelimit.exceeded` and
`authz.denied` clustering around one account or address.

**Losing the last administrator** is recoverable from a shell on the server:

```bash
node scripts/create-admin.js someone@example.com
```

It promotes an existing account or creates a new one, and prints an invite link.

---

## Hardening beyond the defaults

Worth doing, deliberately left out of the box:

- **Check passwords against Have I Been Pwned.** The blocklist here is small and
  offline; the HIBP range API uses k-anonymity, so candidates are never sent in
  full. `src/lib/password.js` is where it goes.
- **Passkeys / WebAuthn** as a second factor. Phishing-resistant in a way TOTP
  is not, since a code can be typed into a convincing fake site.
- **Email delivery** for invites and resets, so links do not have to be passed
  by hand. Whatever you add, keep reset links single-use and short-lived.
- **Ship the audit log off the box** to somewhere append-only. An attacker with
  the database can edit the local copy.
- **Move to Postgres** if you outgrow one machine. The models are the only
  files that touch SQL.
- **Content backups and restore drills.** An untested backup is a hope.
