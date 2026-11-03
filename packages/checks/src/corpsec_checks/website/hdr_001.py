"""HDR-001 — a Content-Security-Policy is set (and isn't fully permissive for scripts)."""

from corpsec_checks.website._headers import HeaderCheck, csp_directives
from corpsec_scanner import Severity
from corpsec_scanner.http import HttpResponse


class ContentSecurityPolicy(HeaderCheck):
    id = "HDR-001"
    version = "1.0.0"
    expected = "A Content-Security-Policy header"

    def evaluate(self, resp: HttpResponse) -> tuple[Severity, object]:
        policy = resp.headers.get("content-security-policy")
        if not policy:
            return Severity.MEDIUM, "No Content-Security-Policy header"
        directives = csp_directives(policy)
        scripts = directives.get("script-src", directives.get("default-src", []))
        if "'unsafe-inline'" in scripts and "'unsafe-eval'" in scripts:
            return Severity.LOW, {"policy": policy, "weakness": "unsafe-inline and unsafe-eval"}
        return Severity.PASS, {"policy": policy}
