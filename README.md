# CorpSEC

**Website and email security checks that anyone can understand.**

CorpSEC checks a website or domain and returns an A–F grade, the three things to fix first, and step-by-step fix guides for the platform you actually use (WordPress, Shopify, Wix, Google Workspace, Microsoft 365, …). No security or IT knowledge required.

It is inspired by professional tools such as OWASP ZAP, Nmap, OpenVAS, Burp Suite, Qualys and Acunetix, but is built for small businesses, freelancers, schools and NGOs rather than security specialists.

> **Status:** pre-alpha — milestone M1 (check catalog). 55 checks, intel sync and a vulnerable test lab are in place; no web UI yet.

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
uv run corpsec-intel-sync --out intel.json # fetch vulnerability/product data (optional)
uv run corpsec-scan example.com --intel intel.json   # scan from the command line, prints JSON
docker compose -f deploy/docker-compose.yml up --build   # Postgres, Redis, API (:8000), worker
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

### Layout

| Path | What |
|---|---|
| `packages/scanner` | Scan engine: check interface, dependency planner, SSRF-guarded rate-limited HTTP client, DNS, CLI |
| `packages/checks` | Check catalog: one module per check, grouped by area (`connection/`, `tls/`, `website/`, `software/`, `exposure/`, `mail/`), registered via the `corpsec.checks` entry point |
| `packages/intel` | `corpsec-intel-sync`: builds the vulnerability/product snapshot used by software checks |
| `apps/api` | FastAPI app, SQLAlchemy models, Alembic migrations, arq worker |
| `deploy` | Dockerfile and docker-compose for local development |
| `deploy/lab` | Vulnerable lab: a broken and a hardened site on an isolated network, scanned end-to-end in CI |
| `schemas` | JSON Schemas shared with the frontend |

### Adding a check

1. Create `packages/checks/src/corpsec_checks/<area>/<id>.py` with a `Check` subclass (`id`, `version`, `stage`, optional `requires` / `uses` / `provides` facts, `async run(ctx)`).
2. Add it to `CHECKS` in `corpsec_checks/__init__.py`.
3. Add positive and negative tests with the `scan` fixture and `FakeSite` / `FakeDns` (no real network in unit tests).
4. If the lab can show it, add a case to `deploy/lab` and its expected finding to `deploy/lab/tests/test_lab.py`.

Checks must only use `ctx.http`, `ctx.tls`, `ctx.dns` and `ctx.external`; they enforce the safety limits in spec §5.

Vulnerable lab (what CI runs):

```bash
docker compose -f deploy/lab/compose.yml build
docker compose -f deploy/lab/compose.yml up -d --wait dns bad good
docker compose -f deploy/lab/compose.yml run --rm runner
docker compose -f deploy/lab/compose.yml down -v
```

## Documentation

- [MVP specification](docs/MVP-SPEC.md)
- [Finding JSON Schema](schemas/finding.schema.json)
