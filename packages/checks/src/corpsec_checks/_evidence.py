"""Helpers for building evidence from HTTP responses."""

from __future__ import annotations

from typing import Any

from corpsec_scanner.http import HttpResponse

# Headers worth keeping as evidence; everything else is dropped to keep findings small.
_KEPT_HEADERS = ("location", "server", "content-type", "strict-transport-security")


def response_summary(resp: HttpResponse) -> dict[str, Any]:
    return {
        "status": resp.status,
        "headers": {k: resp.headers[k] for k in _KEPT_HEADERS if k in resp.headers},
    }


def redirect_chain(resp: HttpResponse) -> list[dict[str, Any]]:
    return [{"url": h.url, "status": h.status, "location": h.location} for h in resp.history]
