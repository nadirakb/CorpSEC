"""HDR-003 — ``X-Content-Type-Options: nosniff``."""

from corpsec_checks.website._headers import HeaderCheck
from corpsec_scanner import Severity
from corpsec_scanner.http import HttpResponse


class NoSniff(HeaderCheck):
    id = "HDR-003"
    version = "1.0.0"
    expected = "X-Content-Type-Options: nosniff"

    def evaluate(self, resp: HttpResponse) -> tuple[Severity, object]:
        value = resp.headers.get("x-content-type-options")
        ok = (value or "").strip().lower() == "nosniff"
        return (Severity.PASS if ok else Severity.LOW), value
