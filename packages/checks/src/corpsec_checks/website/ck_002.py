"""CK-002 — login/session cookies can't be read by page scripts (``HttpOnly``)."""

from corpsec_checks.website._cookies import Cookie, CookieCheck
from corpsec_scanner import Severity


class CookieHttpOnly(CookieCheck):
    id = "CK-002"
    version = "1.0.0"
    severity = Severity.MEDIUM
    expected = "HttpOnly attribute on session cookies"

    def is_ok(self, cookie: Cookie) -> bool:
        return "httponly" in cookie.attrs
