<p align="center">
  <img src="docs/assets/banner.png" alt="CorpSEC: website and email security checks anyone can understand" width="100%">
</p>

# CorpSEC

**Website and email security checks that anyone can understand.**

CorpSEC checks a website or domain and returns an A–F grade, the three things to fix first, and step-by-step fix guides for the platform you actually use (WordPress, Shopify, Wix, Google Workspace, Microsoft 365, …). No security or IT knowledge required.

It is inspired by professional tools such as OWASP ZAP, Nmap, OpenVAS, Burp Suite, Qualys and Acunetix, but is built for small businesses, freelancers, schools and NGOs rather than security specialists.

> **Status:** pre-alpha. MVP milestones M0–M5 are done, plus the post-MVP work: 8 more checks, an operator dashboard, owner progress reports and a production deployment. Not yet running at a public address.

## What you get

- **Check any site in the browser**, no account needed: live progress, then an A+ to F grade with a score, a grade per area, and the three things to fix first.
- **Plain-language report**: every problem says what it is, why it matters and how to fix it, with steps for your platform (WordPress, Shopify, Wix, Squarespace, Webflow, Cloudflare, Google Workspace, Microsoft 365, …) and a technical section for your IT person.
- **Act on findings**: "I fixed it, check again" re-runs one check; hide what doesn't apply (serious problems only as a false alarm); "This looks wrong" sends a report to the CorpSEC team.
- **Share and print**: email a read-only report link to whoever will fix it (valid 30 days), or save the report as a PDF.
- **Accounts**: sign in with an emailed link, Google or Microsoft. No passwords.
- **Your sites**: prove ownership (DNS record, uploaded file or meta tag), then CorpSEC re-checks every week and checks certificate expiry, domain expiry and uptime every day. Emails when the grade drops, a serious new problem appears or something is about to expire. Optional Monday summary email.
- **Progress**: score over time, grade per area, typical time to fix, how the site compares with similar sites, an overview across all your sites with one "fix these first" list, and a monthly report you can save as a PDF.
- **Your data**: download everything stored about you, or delete your account, from the Account page.
- **For the people running CorpSEC**: an operator dashboard (`/admin`) with launch goals, checks per day, the visit-to-account funnel, failing checks and "This looks wrong" reports.

## What it checks

63 passive checks (the full catalog with severities is in [docs/MVP-SPEC.md §6](docs/MVP-SPEC.md#6-check-catalog-mvp)):

| Area | Examples |
|---|---|
| Connection | HTTPS available, HTTP → HTTPS redirect, mixed content, risky open services (databases, remote desktop) |
| Encryption | Certificate validity and expiry, old TLS versions, weak ciphers, HSTS |
| Website settings | Security headers, cookie flags, CORS, directory listing, exposed `.git` / `.env` / backups, unpinned or compromised third-party code |
| Software | CMS / plugin / JS library versions with known vulnerabilities |
| Email & domain | SPF, DKIM, DMARC, BIMI, domain expiry, DNSSEC, subdomain takeover, forgotten test sites (certificate logs), look-alike domains, spam/phishing blocklists |

All checks are **passive**: CorpSEC behaves like an ordinary visitor and never sends attack payloads. Requests are rate-limited, never leave the scanned domain (apart from public lookups such as certificate logs and domain registries), and private or internal addresses are refused. See [docs/MVP-SPEC.md §5](docs/MVP-SPEC.md#5-scan-scope-and-safety-envelope-mvp).

Two checks depend on outside data with licence terms you must accept for your deployment:

- **Spam and phishing blocklists** (`REP-001`, `REP-002`) query Spamhaus. Its free public servers allow only low-volume, non-commercial use and refuse queries sent through big public DNS resolvers; a commercial service needs a Data Query Service key in `CORPSEC_SPAMHAUS_DQS_KEY`.
- **Risky open services** (`PORT-001`) reads Shodan's InternetDB instead of probing ports. It is off until you set `CORPSEC_INTERNETDB_ENABLED=true`.

From the command line: `uv run corpsec-scan example.com --config internetdb=on --config spamhaus_dqs_key=…`.

## Responsible use

Only check websites and domains you own or are authorized to assess. Monitoring and detailed evidence (for example the contents of an exposed file) require proving ownership via DNS, an uploaded file or a meta tag. Anonymous checks are rate-limited per visitor.

Site owners can ask CorpSEC never to check their domain by adding a DNS record shown on the `/bot` page, which also explains how to recognise CorpSEC's requests (user agent `CorpSEC/0.1`).

## Privacy

- No advertising trackers and no third-party analytics. Usage is counted first-party, without cookies and without storing IP addresses: visitors are a code that changes every day. Browsers sending Global Privacy Control or Do Not Track are not counted.
- Anonymous checks are deleted after 7 days, the abuse log after a year, usage counts after 13 months.
- Secrets found during a check (passwords, keys) are masked before they are stored.
- The privacy page (`/privacy`) and terms (`/terms`) are drafts that need a lawyer's review before launch.

## Development

Requires [uv](https://docs.astral.sh/uv/), Docker, and Node.js 24 for the web app.

```bash
uv sync                                    # install workspace + dev tools
uv run corpsec-intel-sync --out intel.json # fetch vulnerability/product data (optional; see below)
uv run corpsec-scan example.com --intel intel.json   # scan from the command line, prints JSON
docker compose -f deploy/docker-compose.yml up --build   # front proxy (:8088), web (:3000), API (:8000), worker, Postgres, Redis, Mailpit (:8025)
```

Open http://localhost:8088 for the app. The API's interactive documentation is at http://localhost:8000/docs. For example:

```bash
curl -X POST localhost:8000/v1/scans -H 'content-type: application/json' -d '{"target":"example.com"}'
curl localhost:8000/v1/scans/<id>
```

Working on one part outside Docker (Postgres and Redis from the compose stack; stop the compose service you replace first, e.g. `docker compose -f deploy/docker-compose.yml stop web`, since it uses the same port):

```bash
cd apps/api && uv run alembic upgrade head                    # database migrations
uv run uvicorn corpsec_api.main:app --reload --app-dir apps/api/src   # API on :8000
uv run arq corpsec_api.worker.WorkerSettings                  # worker (scans, scheduled jobs)
npm --prefix apps/web install && npm --prefix apps/web run dev    # web app on :3000
```

Tests, lint and types (API tests need a Postgres URL; they are skipped without one):

```bash
CORPSEC_TEST_DATABASE_URL=postgresql+asyncpg://corpsec:corpsec@localhost:5432/corpsec uv run pytest
uv run ruff check . && uv run ruff format --check . && uv run mypy
npm --prefix apps/web run lint && npm --prefix apps/web run typecheck && npm --prefix apps/web test
```

Database changes: edit `apps/api/src/corpsec_api/db.py`, then from `apps/api` run `uv run alembic revision --autogenerate --rev-id <next number> -m "<what changed>"` and review the generated file.

### Configuration

All settings are environment variables (in `deploy/.env` for the compose stack, `deploy/production/.env` in production; both gitignored). The most important ones:

| Variable | Default | What it does |
|---|---|---|
| `CORPSEC_ENVIRONMENT` | `development` | `production` refuses to start on unsafe defaults |
| `CORPSEC_DATABASE_URL` | local Postgres | `postgresql+asyncpg://…` |
| `CORPSEC_REDIS_URL` | `redis://localhost:6379/0` | job queue, live progress, rate limits |
| `CORPSEC_WEB_URL` | `http://localhost:3000` | public address of the web app (emailed links, allowed origin) |
| `CORPSEC_EXTRA_ORIGINS` | `[]` | other addresses the web app is served from |
| `CORPSEC_SECRET_KEY` | development value | signs opt-out records and keys usage counting; 32+ random characters in production |
| `CORPSEC_TRUSTED_PROXIES` | localhost | networks allowed to set `X-Forwarded-For` |
| `CORPSEC_SMTP_HOST`, `_PORT`, `_USERNAME`, `_PASSWORD`, `_STARTTLS`, `CORPSEC_MAIL_FROM` | none | outgoing email; without a host, emails go to the log |
| `CORPSEC_INTEL_PATH` | none | vulnerability data snapshot file, refreshed nightly |
| `CORPSEC_WORDFENCE_API_KEY` | none | WordPress vulnerability data (see below) |
| `CORPSEC_SPAMHAUS_DQS_KEY` | none | commercial blocklist access |
| `CORPSEC_INTERNETDB_ENABLED` | `false` | open-ports check |
| `CORPSEC_GOOGLE_CLIENT_ID` / `_SECRET`, `CORPSEC_MICROSOFT_CLIENT_ID` / `_SECRET`, `CORPSEC_MICROSOFT_TENANT` | none / `common` | Google and Microsoft sign-in |
| `CORPSEC_ADMIN_EMAILS` | `[]` | who sees the operator dashboard |
| `CORPSEC_METRICS_TOKEN` | none | turns on `GET /metrics` (Prometheus) |
| `CORPSEC_SENTRY_DSN` | none | error tracking (Sentry or GlitchTip) |
| `CORPSEC_ANON_SCANS_PER_HOUR` / `_PER_DAY`, `CORPSEC_USER_SCANS_PER_DAY`, `CORPSEC_MAX_SITES_PER_USER`, `CORPSEC_RECHECKS_PER_HOUR`, `CORPSEC_SHARES_PER_DAY`, `CORPSEC_SAME_TARGET_MINUTES` | 5 / 20, 10, 3, 30, 10, 10 | rate limits |
| `CORPSEC_SESSION_DAYS`, `CORPSEC_LOGIN_TOKEN_MINUTES` | 30, 15 | sign-in session and link lifetimes |

The full list with explanations is in [`apps/api/src/corpsec_api/settings.py`](apps/api/src/corpsec_api/settings.py); the production template is [`deploy/production/env.example`](deploy/production/env.example).

### Scheduled jobs

The worker runs these on its own (times in UTC):

| When | Job |
|---|---|
| every 15 minutes | start weekly checks that are due (ownership is confirmed again first) |
| twice an hour | daily light checks: certificate and domain expiry, site reachable |
| 02:41 daily | refresh vulnerability data |
| 03:17 daily | delete expired data (anonymous checks, old logs, usage counts) |
| Monday 08:07 | weekly summary emails for people who turned them on |

### Email in development

The compose stack sends all email (sign-in links, alerts) to [Mailpit](https://mailpit.axllent.org/). Open http://localhost:8025 to read it. For real delivery set `CORPSEC_SMTP_HOST`, `CORPSEC_SMTP_PORT`, `CORPSEC_SMTP_USERNAME`, `CORPSEC_SMTP_PASSWORD` and `CORPSEC_MAIL_FROM`; set `CORPSEC_WEB_URL` to the public address of the web app so links point to it.

### Sign in with Google and Microsoft

Email sign-in links always work. "Continue with Google" and "Continue with Microsoft" buttons appear only for providers whose client id **and** secret are set; without them the provider is switched off and its endpoints return 404. Both use OpenID Connect (authorization code + PKCE, `state` and `nonce`; the ID token's signature, issuer, audience, expiry and nonce are checked). A provider account is linked to an existing CorpSEC account only through an email address the provider has verified, and is remembered by its stable subject id, so a later email change at the provider doesn't lock anyone out.

The redirect (callback) URL to register is built from `CORPSEC_WEB_URL`, because the browser reaches the API through the web app's `/api` rewrite:

```
{CORPSEC_WEB_URL}/api/v1/auth/oauth/google/callback
{CORPSEC_WEB_URL}/api/v1/auth/oauth/microsoft/callback
```

For the compose stack (`CORPSEC_WEB_URL=http://localhost:8088`, the front proxy) that is `http://localhost:8088/api/v1/auth/oauth/<provider>/callback` (both providers allow `http://localhost`); in production use your public `https://` address.

**Google** ([Google Cloud console](https://console.cloud.google.com/)):

1. Create or pick a project. Under **Google Auth Platform → Branding**, fill in the app name, support email and authorised domain; under **Audience** choose *External*.
2. Under **Data Access** add the scopes `openid`, `email` and `profile` (no sensitive scopes, so no Google review is needed).
3. Under **Clients → Create client** choose *Web application* and add the callback URL above to **Authorised redirect URIs**.
4. Copy the client id and secret into `CORPSEC_GOOGLE_CLIENT_ID` and `CORPSEC_GOOGLE_CLIENT_SECRET`.

**Microsoft** ([Microsoft Entra admin center](https://entra.microsoft.com/) → **App registrations → New registration**):

1. **Supported account types**: *Accounts in any organizational directory and personal Microsoft accounts* (matches the default `CORPSEC_MICROSOFT_TENANT=common`; set a tenant id instead to allow only one organisation).
2. **Redirect URI**: platform *Web*, the callback URL above.
3. Under **Token configuration → Add optional claim → ID** add `email` and `xms_edov`. Microsoft's `email` claim is not verified by itself: CorpSEC accepts it from work/school accounts only when `xms_edov` is true (the email domain's owner is verified), and from personal Microsoft accounts. Without `xms_edov`, work and school accounts are refused with a message to use the email link instead.
4. Under **API permissions** make sure Microsoft Graph `openid`, `email` and `profile` (delegated) are listed.
5. Under **Certificates & secrets → New client secret**, create a secret (note its expiry date; sign-in with Microsoft stops when it lapses).
6. Copy the **Application (client) ID** and the secret's **Value** into `CORPSEC_MICROSOFT_CLIENT_ID` and `CORPSEC_MICROSOFT_CLIENT_SECRET`.

Put the variables in the API's environment, or in `deploy/.env` (gitignored) for the compose stack, and restart the API. `GET /v1/auth/providers` lists the providers that are switched on.

### Running in production

Step-by-step guide for one Docker host with automatic HTTPS, backups and restore: [docs/DEPLOY.md](docs/DEPLOY.md) (files in `deploy/production/`). Notes:

- Put CorpSEC behind a reverse proxy that **overwrites** `X-Forwarded-For` with the real client address (the included [Caddyfile](deploy/Caddyfile) does). Rate limits depend on it: the Next.js rewrite forwards whatever client header it receives and adds none of its own.
- `CORPSEC_TRUSTED_PROXIES`: JSON list of networks allowed to tell the API the client address (the web app's network).
- `CORPSEC_WEB_URL`: the public address; `CORPSEC_EXTRA_ORIGINS` for any other address the web app is served from. Writes from other origins are refused.
- `CORPSEC_SECRET_KEY`: long random value (signs opt-out records). With `CORPSEC_ENVIRONMENT=production` the API and worker refuse to start on development defaults (secret key, `http://` web address, missing SMTP, development database password).
- Rate limits (`CORPSEC_ANON_SCANS_PER_HOUR`, `CORPSEC_USER_SCANS_PER_DAY`, `CORPSEC_MAX_SITES_PER_USER`, …) are shared across API processes through Redis.
- Operator dashboard: set `CORPSEC_ADMIN_EMAILS` (JSON list) and open `/admin` while signed in with one of them: launch goals (spec §18), checks per day, funnel, failing checks and "This looks wrong" reports. Optional: `CORPSEC_METRICS_TOKEN` turns on `GET /metrics` for Prometheus, `CORPSEC_SENTRY_DSN` sends errors to Sentry or GlitchTip.
- The privacy page and terms are drafts and must be reviewed by a lawyer. The production Caddyfile serves `security.txt` with `CORPSEC_SECURITY_CONTACT`.

### WordPress vulnerability data (Wordfence)

WordPress core and plugin vulnerabilities come from the [Wordfence Intelligence](https://www.wordfence.com/threat-intel/) feed, which is free for personal and commercial use but needs an API key:

1. Create a free account at wordfence.com and generate a key under **Account → Integrations**.
2. Put it in your environment or in `deploy/.env` (gitignored): `CORPSEC_WORDFENCE_API_KEY=…`
3. Re-run `corpsec-intel-sync` (or restart the compose stack). The worker also refreshes the snapshot every night at 02:41 UTC when `CORPSEC_INTEL_PATH` is set; a source that fails keeps the previous night's data. Wordfence limits how often its feed can be downloaded, so repeated manual runs can be refused for a while (the previous data is kept).

Without a key the sync skips this source and WordPress vulnerability checks stay silent. The licence requires showing a link to each Wordfence record and the Defiant (and, for CVEs, MITRE) copyright notices wherever the data is displayed; findings carry them in their evidence.

Other sources need no key: WordPress.org, endoflife.date, retire.js (JavaScript libraries), the CISA Known Exploited Vulnerabilities catalog and the IANA domain-registry list.

If the operator dashboard shows vulnerability data older than 48 hours on a compose stack created before the API image switched to a non-root user, the `intel` volume is still owned by root. Fix it once with `docker run --rm -v corpsec_intel:/data alpine chown -R 10001 /data`.

### Layout

| Path | What |
|---|---|
| `packages/scanner` | Scan engine: check interface, dependency planner, SSRF-guarded rate-limited HTTP client, DNS, CLI |
| `packages/checks` | Check catalog: one module per check, grouped by area (`connection/`, `tls/`, `website/`, `software/`, `exposure/`, `mail/`, `reputation/`), registered via the `corpsec.checks` entry point; plain-language explanations in `explain/en/` |
| `packages/grader` | Grading model: score, A+ to F letter, caps, stage grades, fix-first priority (spec §9) |
| `packages/intel` | `corpsec-intel-sync`: builds the vulnerability/product snapshot used by software checks |
| `apps/web` | Next.js web app: landing page, live scan progress, reports, sites, account, operator dashboard ([README](apps/web/README.md)) |
| `apps/api` | FastAPI app, SQLAlchemy models, Alembic migrations, arq worker |
| `deploy` | Dockerfiles, docker-compose and Caddyfile for local development |
| `deploy/production` | Production stack: Caddy with automatic HTTPS, backups, settings template ([guide](docs/DEPLOY.md)) |
| `deploy/lab` | Vulnerable lab: a broken and a hardened site on an isolated network, scanned end-to-end in CI |
| `schemas` | JSON Schemas shared with the frontend |
| `docs` | Specification and deployment guide |

### Adding a check

1. Create `packages/checks/src/corpsec_checks/<area>/<id>.py` with a `Check` subclass (`id`, `version`, `stage`, optional `requires` / `uses` / `provides` facts, `async run(ctx)`).
2. Add it to `CHECKS` in `corpsec_checks/__init__.py`.
3. Write its explanation in `packages/checks/src/corpsec_checks/explain/en/<ID>.yaml`. CI checks reading level (Flesch-Kincaid grade 8 or lower), unexplained jargon, placeholders and fix-step counts.
4. Add positive and negative tests with the `scan` fixture and `FakeSite` / `FakeDns` (no real network in unit tests).
5. If the lab can show it, add a case to `deploy/lab` and its expected finding to `deploy/lab/tests/test_lab.py`.

Checks must only use `ctx.http`, `ctx.tls`, `ctx.dns` and `ctx.external`; they enforce the safety limits in spec §5.

Vulnerable lab (what CI runs):

```bash
docker compose -f deploy/lab/compose.yml build
docker compose -f deploy/lab/compose.yml up -d --wait dns bad good self
docker compose -f deploy/lab/compose.yml run --rm runner
docker compose -f deploy/lab/compose.yml down -v
```

## Documentation

- [MVP specification](docs/MVP-SPEC.md)
- [Deploying to production](docs/DEPLOY.md)
- [Web app notes](apps/web/README.md)
- [Finding JSON Schema](schemas/finding.schema.json)

## Reporting a security problem in CorpSEC

Please don't open a public issue. Use GitHub's private vulnerability reporting ("Report a vulnerability" on the repository's **Security** tab), or write to the contact in the deployment's `/.well-known/security.txt`.

## Licence

No licence has been chosen yet (spec §17), so all rights are reserved: you may read the code, but not copy, modify or redistribute it.
