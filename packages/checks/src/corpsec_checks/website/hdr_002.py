"""HDR-002 — the site can't be embedded in other sites' frames (clickjacking)."""

from corpsec_checks.website._headers import HeaderCheck, csp_directives
from corpsec_scanner import Severity
from corpsec_scanner.http import HttpResponse


class ClickjackingProtection(HeaderCheck):
    id = "HDR-002"
    version = "1.0.0"
    expected = "CSP frame-ancestors, or X-Frame-Options DENY / SAMEORIGIN"

    def evaluate(self, resp: HttpResponse) -> tuple[Severity, object]:
        csp = csp_directives(resp.headers.get("content-security-policy", ""))
        if "frame-ancestors" in csp:
            return Severity.PASS, {"frame-ancestors": csp["frame-ancestors"]}
        xfo = resp.headers.get("x-frame-options", "")
        if xfo.strip().upper() in ("DENY", "SAMEORIGIN"):
            return Severity.PASS, {"x-frame-options": xfo}
        return Severity.MEDIUM, {"x-frame-options": xfo or None, "frame-ancestors": None}
