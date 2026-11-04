# Deploying CorpSEC

One Docker host runs everything: Caddy (HTTPS), the web app, the API, the scan worker,
Postgres, Redis and nightly backups. Files: [`deploy/production/`](../deploy/production).

## 1. Before you start (decisions only you can make)

| Item | Why it matters |
| --- | --- |
| **Domain** | Caddy needs it to get the HTTPS certificate; emailed links use it. |
| **Server** | Any VPS with Docker. Start with 2 vCPU / 4 GB RAM / 40 GB disk (Hetzner, DigitalOcean, OVH, …). Choosing an EU region keeps GDPR simple (spec §17 Q4). |
| **Email provider** | Sign-in links are emailed, so this is required. Postmark, Amazon SES, Mailgun or any SMTP server. |
| **Legal review** | The privacy page and terms in `apps/web/src/app/{privacy,terms}` are drafts. |
| **Contacts** | A security/abuse address (published in `security.txt` and on `/bot`) and a privacy address (privacy page). |

The server's outbound traffic *is* the scanner: some hosting providers want to know about
security-scanning services. Read your provider's acceptable-use policy and tell them what
CorpSEC does (passive, rate-limited checks, see `/bot`) so abuse reports don't surprise them.

## 2. DNS

| Record | Value |
| --- | --- |
| `A` (and `AAAA` if the server has IPv6) for `corpsec.example.com` | server address |
| `A`/`AAAA` for `www.corpsec.example.com` (optional) | server address; redirects to the main domain |
| SPF, DKIM, DMARC for the sender domain | from your email provider, so sign-in links don't land in spam |
| `CAA` (optional) | `0 issue "letsencrypt.org"` |

Also set the server's reverse DNS (PTR) to the domain in your provider's panel: site owners
who see CorpSEC traffic in their logs can then tell where it came from.

## 3. Server

```bash
# Debian/Ubuntu
curl -fsSL https://get.docker.com | sh
ufw allow OpenSSH && ufw allow 80/tcp && ufw allow 443/tcp && ufw allow 443/udp && ufw enable
git clone git@github.com:nadirakb/CorpSEC.git /opt/corpsec
cd /opt/corpsec/deploy/production
cp env.example .env && chmod 600 .env
```

Fill in `.env`. Generate secrets with `openssl rand -hex 32` (database password: `openssl rand -hex 24`,
hex only because it goes into a URL).

## 4. Start

```bash
docker compose up -d --build
docker compose ps        # everything "healthy"; migrate and intel-sync "exited (0)"
```

Caddy gets the certificate on the first request; `docker compose logs proxy` shows it.

The API and worker **refuse to start** in production while a setting is unsafe (development
secret key, `http://` web address, no SMTP host, development database password). The error
lists what to fix:

```bash
docker compose logs api | grep -A6 Refusing
```

## 5. Check it

1. Open `https://<domain>` and sign in with your own email (tests SMTP and DNS for mail).
2. `curl -sI https://<domain>` shows `strict-transport-security` and a `content-security-policy`
   with a nonce.
3. `https://<domain>/.well-known/security.txt` shows your contact.
4. Scan your own domain in CorpSEC. It must get **A+** (spec §15). Add it as a site, verify
   it and turn on monitoring so it is checked every week.
5. Optional: add Google / Microsoft sign-in (README, "Sign in with Google / Microsoft") with
   redirect URIs on your domain, then `docker compose up -d`.

## 6. Updating

```bash
cd /opt/corpsec && git pull
cd deploy/production && docker compose up -d --build
```

Database migrations run automatically (`migrate` service) before the API and worker start.

## 7. Backups and restore

The `backup` service writes a `pg_dump` into `CORPSEC_BACKUP_DIR` (default
`deploy/production/backups`) when it starts and every night at 03:00 UTC, and keeps
`CORPSEC_BACKUP_KEEP_DAYS` days. **Copy that folder off the server** (restic, rsync, your
provider's storage): a backup on the same disk is lost with the disk.

Restore a dump (stops the app, replaces the database):

```bash
cd /opt/corpsec/deploy/production
docker compose stop api worker web
docker compose exec -T postgres sh -c 'dropdb -U corpsec corpsec && createdb -U corpsec corpsec'
docker compose exec -T postgres pg_restore -U corpsec -d corpsec < backups/corpsec-YYYYMMDD-HHMM.dump
docker compose up -d
```

Test a restore once after going live, and again every few months.

Also keep a copy of `.env` somewhere safe (password manager). Without `CORPSEC_SECRET_KEY`,
existing opt-out records can't be checked.

## 8. Day-to-day

| Task | Command |
| --- | --- |
| Logs | `docker compose logs -f api worker` (rotated: 5 × 10 MB per service) |
| Health | `docker compose ps` (API has a health check on `/healthz`) |
| Restart | `docker compose restart api worker` |
| Disk | `docker system df`; old images: `docker image prune` |
| Stop | `docker compose down` (data stays in volumes; never add `-v` unless you mean it) |

Uptime: point an external monitor (UptimeRobot, Better Stack, …) at `https://<domain>/` and
`https://<domain>/api/v1/auth/providers`.

## What runs where

| Service | Exposed | Notes |
| --- | --- | --- |
| proxy (Caddy) | 80, 443 | Automatic HTTPS, HTTP→HTTPS, `www` redirect, `security.txt`; overwrites `X-Forwarded-For` |
| web (Next.js) | internal | Nonce CSP per request |
| api (FastAPI) | internal | 2 processes; rate limits shared through Redis |
| worker (arq) | internal | Scans, weekly monitoring, daily light checks, nightly intel refresh 02:41, purge 03:17, digest Mondays 08:07 (UTC) |
| postgres, redis | internal | Volumes `pgdata`, `redisdata` (append-only, queued scans survive restarts) |
| backup | internal | `pg_dump` to the host folder |
