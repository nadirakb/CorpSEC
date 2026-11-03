"""HDR-004 — a Referrer-Policy is set and doesn't leak full URLs to other sites."""

from corpsec_checks.website._headers import HeaderCheck
from corpsec_scanner import Severity
from corpsec_scanner.http import HttpResponse


class ReferrerPolicy(HeaderCheck):
    id = "HDR-004"
    version = "1.0.0"
    expected = "Referrer-Policy set, e.g. strict-origin-when-cross-origin"

    def evaluate(self, resp: HttpResponse) -> tuple[Severity, object]:
        value = resp.headers.get("referrer-policy")
        if not value:
            return Severity.LOW, None
        # The last recognised token wins when several are listed.
        last = value.split(",")[-1].strip().lower()
        return (Severity.LOW if last == "unsafe-url" else Severity.PASS), value
