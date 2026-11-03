"""CK-003 — login/session cookies set ``SameSite`` (and not ``None`` without ``Secure``)."""

from corpsec_checks.website._cookies import Cookie, CookieCheck
from corpsec_scanner import Severity


class CookieSameSite(CookieCheck):
    id = "CK-003"
    version = "1.0.0"
    severity = Severity.LOW
    expected = "SameSite=Lax or SameSite=Strict on session cookies"

    def is_ok(self, cookie: Cookie) -> bool:
        value = cookie.attrs.get("samesite")
        if value is None:
            return False
        return value.lower() != "none" or "secure" in cookie.attrs
