# CorpSEC

**Website and email security checks that anyone can understand.**

CorpSEC checks a website or domain and returns an A–F grade, the three things to fix first, and step-by-step fix guides for the platform you actually use (WordPress, Shopify, Wix, Google Workspace, Microsoft 365, …). No security or IT knowledge required.

It is inspired by professional tools such as OWASP ZAP, Nmap, OpenVAS, Burp Suite, Qualys and Acunetix, but is built for small businesses, freelancers, schools and NGOs rather than security specialists.

> **Status:** pre-alpha — milestone M0 (foundations). Scan engine, first checks, API and worker are in place; no web UI yet.

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
uv run corpsec-scan example.com            # scan from the command line, prints JSON
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
| `packages/checks` | Check catalog, one sub-package per check (registered via the `corpsec.checks` entry point) |
| `apps/api` | FastAPI app, SQLAlchemy models, Alembic migrations, arq worker |
| `deploy` | Dockerfile and docker-compose for local development |
| `schemas` | JSON Schemas shared with the frontend |

### Adding a check

1. Create `packages/checks/src/corpsec_checks/<id>/check.py` with a `Check` subclass (`id`, `version`, `stage`, optional `requires`/`provides` facts, `async run(ctx)`).
2. Add it to `CHECKS` in `corpsec_checks/__init__.py`.
3. Add positive and negative tests using the `mock_options` fixture (no real network in tests).

Checks must only use `ctx.http` and `ctx.dns`; they enforce the safety limits in spec §5.

## Documentation

- [MVP specification](docs/MVP-SPEC.md)
- [Finding JSON Schema](schemas/finding.schema.json)
