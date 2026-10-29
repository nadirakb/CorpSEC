"""CK-001 — login/session cookies are only sent over HTTPS (``Secure``)."""

from corpsec_checks.website._cookies import Cookie, CookieCheck
from corpsec_scanner import Severity


class CookieSecure(CookieCheck):
    id = "CK-001"
    version = "1.0.0"
    severity = Severity.MEDIUM
    expected = "Secure attribute on session cookies"
    https_only = True

    def is_ok(self, cookie: Cookie) -> bool:
        return "secure" in cookie.attrs
