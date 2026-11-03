# CorpSEC

**Website and email security checks that anyone can understand.**

CorpSEC checks a website or domain and returns an A–F grade, the three things to fix first, and step-by-step fix guides for the platform you actually use (WordPress, Shopify, Wix, Google Workspace, Microsoft 365, …). No security or IT knowledge required.

It is inspired by professional tools such as OWASP ZAP, Nmap, OpenVAS, Burp Suite, Qualys and Acunetix, but is built for small businesses, freelancers, schools and NGOs rather than security specialists.

> **Status:** pre-alpha — MVP milestones M0–M5 done. Scan in the browser, read an A–F report in plain language, verify and monitor your sites, share or print reports. Rate limits, redaction and opt-out protect the people whose sites get scanned.

## What the MVP checks

| Area | Examples |
|---|---|
| Connection | HTTPS available, HTTP → HTTPS redirect, mixed content |
| Encryption | Certificate validity and expiry, old TLS versions, weak ciphers, HSTS |
| Website settings | Security headers, cookie flags, CORS, directory listing, exposed `.git` / `.env` / backups |
| Software | CMS / plugin / JS library versions with known vulnerabilities |
| Email & domain | SPF, DKIM, DMARC, domain expiry, DNSSEC, subdomain takeover |

All MVP checks are **passive**: CorpSEC behaves like an ordinary visitor and never sends attack payloads. See [docs/MVP-SPEC.md §5](docs/MVP-SPEC.md#5-scan-scope-and-safety-envelope-mvp).

## Responsible use

Only check websites and domains you own or are authorized to assess. Monitoring and detailed evidence require proving ownership via DNS, an uploaded file or a meta tag.

## Development

Requires [uv](https://docs.astral.sh/uv/) and Docker.

```bash
uv sync                                    # install workspace + dev tools
uv run corpsec-intel-sync --out intel.json # fetch vulnerability/product data (optional; see below)
uv run corpsec-scan example.com --intel intel.json   # scan from the command line, prints JSON
docker compose -f deploy/docker-compose.yml up --build   # front proxy (:8088), web (:3000), API (:8000), worker, Postgres, Redis, Mailpit (:8025)
```

```bash
curl -X POST localhost:8000/v1/scans -H 'content-type: application/json' -d '{"target":"example.com"}'
curl localhost:8000/v1/scans/<id>
```

Tests, lint and types (API tests need a Postgres URL; they are skipped without one):

```bash
CORPSEC_TEST_DATABASE_URL=postgresql+asyncpg://corpsec:corpsec@localhost:5432/corpsec uv run pytest
uv run ruff check . && uv run ruff format --check . && uv run mypy
```

### Email in development

The compose stack sends all email (sign-in links, alerts) to [Mailpit](https://mailpit.axllent.org/). Open http://localhost:8025 to read it. For real delivery set `CORPSEC_SMTP_HOST`, `CORPSEC_SMTP_PORT`, `CORPSEC_SMTP_USERNAME`, `CORPSEC_SMTP_PASSWORD` and `CORPSEC_MAIL_FROM`; set `CORPSEC_WEB_URL` to the public address of the web app so links point to it.

### Running in production

- Put CorpSEC behind a reverse proxy that **overwrites** `X-Forwarded-For` with the real client address (the included [Caddyfile](deploy/Caddyfile) does). Rate limits depend on it: the Next.js rewrite forwards whatever client header it receives and adds none of its own.
- `CORPSEC_TRUSTED_PROXIES`: JSON list of networks allowed to tell the API the client address (the web app's network).
- `CORPSEC_WEB_URL`: the public address; `CORPSEC_EXTRA_ORIGINS` for any other address the web app is served from. Writes from other origins are refused.
- `CORPSEC_SECRET_KEY`: long random value (signs opt-out records). The API logs a warning if it's left at the development default.
- Rate limits (`CORPSEC_ANON_SCANS_PER_HOUR`, `CORPSEC_USER_SCANS_PER_DAY`, `CORPSEC_MAX_SITES_PER_USER`, …) are shared across API processes through Redis.
- The privacy page and terms are drafts and must be reviewed by a lawyer; `security@corpsec.app` in `apps/web/public/.well-known/security.txt` is a placeholder.

### WordPress vulnerability data (Wordfence)

WordPress core and plugin vulnerabilities come from the [Wordfence Intelligence](https://www.wordfence.com/threat-intel/) feed, which is free for personal and commercial use but needs an API key:

1. Create a free account at wordfence.com and generate a key under **Account → Integrations**.
2. Put it in your environment or in `deploy/.env` (gitignored): `CORPSEC_WORDFENCE_API_KEY=…`
3. Re-run `corpsec-intel-sync` (or restart the compose stack).

Without a key the sync skips this source and WordPress vulnerability checks stay silent. The licence requires showing a link to each Wordfence record and the Defiant (and, for CVEs, MITRE) copyright notices wherever the data is displayed; findings carry them in their evidence.

### Layout

| Path | What |
|---|---|
| `packages/scanner` | Scan engine: check interface, dependency planner, SSRF-guarded rate-limited HTTP client, DNS, CLI |
| `packages/checks` | Check catalog: one module per check, grouped by area (`connection/`, `tls/`, `website/`, `software/`, `exposure/`, `mail/`), registered via the `corpsec.checks` entry point |
| `packages/grader` | Grading model: score, A+ to F letter, caps, stage grades, fix-first priority (spec §9) |
| `packages/intel` | `corpsec-intel-sync`: builds the vulnerability/product snapshot used by software checks |
| `apps/web` | Next.js web app: landing page, live scan progress, report with fix guides ([README](apps/web/README.md)) |
| `apps/api` | FastAPI app, SQLAlchemy models, Alembic migrations, arq worker |
| `deploy` | Dockerfile and docker-compose for local development |
| `deploy/lab` | Vulnerable lab: a broken and a hardened site on an isolated network, scanned end-to-end in CI |
| `schemas` | JSON Schemas shared with the frontend |

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
- [Finding JSON Schema](schemas/finding.schema.json)
