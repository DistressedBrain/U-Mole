# Deploying U-Mole on a VPS behind a Cloudflare Tunnel

The result: your site on your domain, TLS handled by Cloudflare, and **no
inbound port open on the server at all**. The only route in is an outbound
connection `cloudflared` makes to Cloudflare, so the VPS can refuse every
inbound packet except SSH.

Budget about 30 minutes.

---

## What you need

- A VPS. The smallest tier anywhere is plenty — 1 vCPU and 1 GB of RAM runs
  this comfortably. Hetzner CX22, DigitalOcean's $6 droplet, Vultr, Linode.
- A domain on Cloudflare (nameservers pointed at them). A free plan is fine.
- Docker on the VPS.

---

## Step 1 — Prepare the server

SSH in as root, then make yourself a non-root user and lock the door behind you:

```bash
adduser --disabled-password --gecos "" deploy
usermod -aG sudo deploy
rsync --archive --chown=deploy:deploy ~/.ssh /home/deploy/

# Close everything inbound except SSH. The tunnel needs nothing opened.
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw --force enable

# Unattended security updates.
apt-get update && apt-get install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
```

Then disable password SSH logins in `/etc/ssh/sshd_config`
(`PasswordAuthentication no`, `PermitRootLogin no`) and `systemctl restart ssh`.

Install Docker as `deploy`:

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker deploy
newgrp docker
```

> Adding a user to the `docker` group is equivalent to giving them root on that
> box. That is acceptable here because `deploy` is already the admin of a
> single-purpose machine — but do not add anyone else to it.

---

## Step 2 — Create the tunnel

In the Cloudflare dashboard: **Zero Trust → Networks → Tunnels → Create a
tunnel → Cloudflared**.

1. Name it (`u-mole`).
2. Cloudflare shows an install command containing a long token. **Copy just the
   token** — the part after `--token`. You do not run their command; Docker
   Compose runs `cloudflared` for you.
3. On the **Public Hostname** tab, add a route:
   - **Subdomain / Domain** — whatever you want the site to be, e.g.
     `u-mole.example.com`
   - **Type** — `HTTP`
   - **URL** — `app:3000`

   `app` is the service name in `compose.yaml`; Docker's internal DNS resolves
   it. Plain HTTP here is correct and safe — that hop never leaves the Docker
   network on your own machine. TLS runs between the browser and Cloudflare.

---

## Step 3 — Configure

```bash
git clone https://github.com/DistressedBrain/U-Mole.git
cd U-Mole
cp .env.example .env
```

Generate the secret **on the server** and put it in `.env`:

```bash
docker run --rm node:22-bookworm-slim node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Edit `.env`:

```ini
NODE_ENV=production
APP_URL=https://u-mole.example.com     # exactly your public hostname
SECRET_KEY=<the 64 hex characters you just generated>
TUNNEL_TOKEN=<the token from step 2>
```

`compose.yaml` sets `CLIENT_IP_HEADER`, `TRUST_PROXY` and `DATABASE_PATH` for
you; leave them alone unless you know why you are changing them.

Then lock the file down — it holds both the tunnel token and the key that
peppers every password hash:

```bash
chmod 600 .env
```

### Why `CLIENT_IP_HEADER` and not `TRUST_PROXY`

Every request arrives at the app from `cloudflared`'s container address. Left
alone, all your visitors would share one address and the per-address rate limits
and the account lockout would misfire — one person's typos would throttle
everyone.

`cf-connecting-ip` is set by Cloudflare's edge and holds the true client. It is
trustworthy **here specifically** because this deployment publishes no port:
nothing can reach the app without passing through Cloudflare, so nothing can
forge it.

If you ever expose the app directly — a published port, a second reverse proxy,
a health check from outside — **clear `CLIENT_IP_HEADER` first**. Any client
that can connect directly could otherwise pick its own address and walk past the
rate limits and the lockout.

---

## Step 4 — Start it

```bash
docker compose up -d --build
docker compose ps          # both services running, app healthy
docker compose logs -f     # ctrl-c to stop following
```

Create the first administrator:

```bash
docker compose exec app node scripts/create-admin.js you@example.com "Your Name"
```

It prints a one-time link on your public hostname. Open it, choose a password,
scan the QR code with an authenticator app, and **save the recovery codes** —
they are shown once.

From there, everything is managed at **Users** in the web interface.

---

## Step 5 — Add Cloudflare Access (recommended)

This puts a *second*, independent authentication gate at Cloudflare's edge, in
front of the whole site. Requests never reach your server unless the visitor
passes it first. An attacker then has to defeat two unrelated systems, and your
app never sees traffic from anyone unauthenticated. Free for up to 50 users.

**Zero Trust → Access → Applications → Add an application → Self-hosted**:

- **Application domain** — your hostname
- **Policy** — *Allow*, with a rule such as **Emails** listing your users, or
  **Emails ending in** `@yourcompany.com`
- **Identity provider** — the built-in one-time PIN works with no setup;
  Google, GitHub and Microsoft are available if you prefer

Worth knowing: Access is a gate, not an identity U-Mole understands. Everyone
still signs in to the app itself afterwards, and U-Mole's own accounts remain
the authority on who can do what. That double sign-in is the point.

### Other edge settings worth a minute

**Security → WAF → Rate limiting rules** — add a rule on `/login` as a coarse
outer limit. The app already rate-limits per address *and* per account, but
stopping a flood at the edge means it never costs you bandwidth.

**SSL/TLS → Overview** — set encryption mode to **Full (strict)** and turn on
**Always Use HTTPS**.

---

## Backups

The database holds your password hashes and encrypted TOTP secrets. Copying the
file with `cp` while the server runs can capture a torn write, so use the
included script — it uses SQLite's online backup API and is safe on a live
database.

```bash
docker compose exec app node scripts/backup.js /data/backups --keep 14
```

Nightly, via `crontab -e` as `deploy`:

```cron
17 3 * * * cd /home/deploy/U-Mole && docker compose exec -T app node scripts/backup.js /data/backups --keep 14 >> /home/deploy/backup.log 2>&1
```

Then copy them **off the machine** — a backup that dies with the server is not a
backup:

```bash
docker compose cp app:/data/backups ./backups
rsync -az ./backups/ you@elsewhere:/srv/u-mole-backups/
```

> **Store `SECRET_KEY` somewhere other than the backups.** A snapshot without
> the key is useless to a thief; the two together are the entire system. Put the
> key in a password manager, not next to the database.

**Restoring:**

```bash
docker compose down
docker compose run --rm -v "$PWD/backups:/restore" app \
  sh -c 'cp /restore/umole-<timestamp>.sqlite3 /data/umole.sqlite3'
docker compose up -d
```

The same `SECRET_KEY` must be in `.env`, or every password, session and
outstanding link in that snapshot is void.

---

## Updating

```bash
cd ~/U-Mole
git pull
docker compose up -d --build
```

Schema migrations run automatically at start-up and are versioned, so an
interrupted deploy will not half-apply one. Take a backup first anyway.

---

## What this setup does and does not protect

**Cloudflare protects the network path.** Your server's IP is never published,
no inbound port is open, volumetric attacks land on Cloudflare, TLS is managed,
and edge rules filter traffic before it reaches you.

**It does not protect the application.** Cloudflare forwards requests
faithfully; an application bug would pass straight through. U-Mole's own
defences — password, second factor, session handling, CSRF, escaping, lockout —
are what stand behind it.

**It does not protect the machine.** If someone gets a shell another way — SSH,
another service on the box, a compromised dependency — the edge is irrelevant.
That is why the app runs as a non-root user in a read-only container with all
capabilities dropped, and why the box should do nothing else.

**It does not protect your data at rest.** The database is a file on that
server's disk. Back it up, keep `SECRET_KEY` apart from it, and remember a
disposed or seized disk takes the hashes with it.

**It does not absorb your responsibility.** If other people have accounts, you
hold their email addresses and you are the data controller under GDPR or its
equivalent. Cloudflare hides your address from the public — not from Cloudflare,
and not from a court order.

---

## Troubleshooting

**Cloudflare error 1033, or "Tunnel not found".** `cloudflared` is not
connected. `docker compose logs cloudflared` — usually a mistyped
`TUNNEL_TOKEN`.

**Error 502.** The tunnel is up but cannot reach the app. Check the Public
Hostname URL is exactly `app:3000`, and that `docker compose ps` shows the app
as `healthy`.

**Every form submission is rejected as cross-origin.** `APP_URL` does not match
the address in the browser. It must match scheme, host and port exactly —
`https://u-mole.example.com`, no trailing slash.

**One person's failed logins lock out everyone.** `CLIENT_IP_HEADER` is not
reaching the app. Confirm `docker compose exec app printenv CLIENT_IP_HEADER`
prints `cf-connecting-ip`.

**Locked out of the admin account.** From the server:
`docker compose exec app node scripts/create-admin.js you@example.com` — it
promotes an existing account or creates one, and prints a fresh invite link.
