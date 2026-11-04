"""Error tracking (Sentry protocol; works with a self-hosted GlitchTip too)."""

from __future__ import annotations

from typing import Any

import sentry_sdk

from corpsec_api.settings import Settings

_SECRET_KEYS = ("token", "password", "secret", "cookie", "authorization", "email")


def _scrub(event: Any, hint: Any) -> Any:
    """Drop request bodies, cookies and headers: reports must not carry personal data."""
    request = event.get("request")
    if isinstance(request, dict):
        request.pop("data", None)
        request.pop("cookies", None)
        request.pop("headers", None)
        if isinstance(request.get("query_string"), str) and any(
            k in request["query_string"].lower() for k in _SECRET_KEYS
        ):
            request["query_string"] = "[removed]"
    event.pop("user", None)
    return event


def init_error_tracking(settings: Settings, component: str) -> bool:
    if not settings.sentry_dsn:
        return False
    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        environment=settings.environment,
        server_name=component,
        send_default_pii=False,
        traces_sample_rate=0.0,
        before_send=_scrub,
    )
    return True
