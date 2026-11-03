"""HDR-005 — a Permissions-Policy is set (informational)."""

from corpsec_checks.website._headers import HeaderCheck
from corpsec_scanner import Severity
from corpsec_scanner.http import HttpResponse


class PermissionsPolicy(HeaderCheck):
    id = "HDR-005"
    version = "1.0.0"
    expected = "A Permissions-Policy header"

    def evaluate(self, resp: HttpResponse) -> tuple[Severity, object]:
        value = resp.headers.get("permissions-policy")
        return (Severity.PASS if value else Severity.INFO), value
