"""Helpers shared by checks: fact names, observation/evidence builders, redaction."""

from __future__ import annotations

import re
from typing import Any, Literal

from corpsec_scanner import Confidence, Evidence, Observation, Severity
from corpsec_scanner.http import HttpResponse

# Fact keys shared between checks.
FACT_HOMEPAGE = "http.homepage"  # HttpResponse for https://<host>/ (CONN-001)
FACT_PAGES = "http.pages"  # list[HttpResponse], homepage first (CRAWL-001)
FACT_SOFT404 = "http.soft404"  # HttpResponse | None for a random path (CRAWL-001)
FACT_TLS = "tls.info"  # TlsInfo (TLS-001)
FACT_FINGERPRINTS = "software.fingerprints"  # list[Fingerprint] (SW-001)
FACT_MX = "mail.mx"  # list[str] MX hostnames, empty = no email (MAIL-001)
FACT_MAIL_PROVIDER = "mail.provider"  # str | None (MAIL-001)

EvidenceKind = Literal["http", "tls", "dns", "rdap", "fingerprint"]

# Headers worth keeping as evidence; everything else is dropped to keep findings small.
_KEPT_HEADERS = (
    "location",
    "server",
    "x-powered-by",
    "content-type",
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "access-control-allow-origin",
    "access-control-allow-credentials",
)


def observe(
    host: str,
    severity: Severity,
    kind: EvidenceKind,
    *,
    observed: Any = None,
    expected: Any = None,
    request: dict[str, Any] | None = None,
    response: dict[str, Any] | None = None,
    query: str | None = None,
    confidence: Confidence = Confidence.CONFIRMED,
    dedupe_key: str = "",
    context: dict[str, str] | None = None,
    references: list[str] | None = None,
) -> Observation:
    return Observation(
        severity=severity,
        confidence=confidence,
        host=host,
        dedupe_key=dedupe_key,
        context=context or {},
        references=references or [],
        evidence=Evidence(
            kind=kind,
            observed=observed,
            expected=expected,
            request=request,
            response=response,
            query=query,
        ),
    )


def response_summary(resp: HttpResponse, *, extra_headers: tuple[str, ...] = ()) -> dict[str, Any]:
    keep = _KEPT_HEADERS + extra_headers
    return {
        "status": resp.status,
        "headers": {k: resp.headers[k] for k in keep if k in resp.headers},
    }


def redirect_chain(resp: HttpResponse) -> list[dict[str, Any]]:
    return [{"url": h.url, "status": h.status, "location": h.location} for h in resp.history]


def get_request(url: str, **headers: str) -> dict[str, Any]:
    req: dict[str, Any] = {"method": "GET", "url": url}
    if headers:
        req["headers"] = headers
    return req


def mask(value: str) -> str:
    """Keep the first and last 2 characters of a secret (spec §10.2)."""
    if len(value) <= 6:
        return "*" * len(value)
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


_ASSIGNMENT_RE = re.compile(
    r"""(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)(?P<sep>['"]?\s*(?:=|=>|:|,)\s*['"]?)(?P<value>[^'"\s;,)]+)"""
)


def redact(text: str, limit: int = 512) -> str:
    """Mask values in ``KEY=value`` / ``'KEY', 'value'`` style lines and truncate."""
    out = _ASSIGNMENT_RE.sub(lambda m: f"{m['key']}{m['sep']}{mask(m['value'])}", text[:limit])
    return out + ("…" if len(text) > limit else "")
