"""EXP-002 — the ``.env`` file (passwords, API keys) is not downloadable."""

import re

from corpsec_checks.exposure._probe import ExposedFileCheck
from corpsec_scanner import Severity

_LINE = re.compile(rb"^[A-Z][A-Z0-9_]*=", re.M)


class EnvFileExposed(ExposedFileCheck):
    id = "EXP-002"
    version = "1.0.0"
    paths = ("/.env", "/.env.production", "/.env.local")
    severity = Severity.CRITICAL

    def signature(self, body: bytes) -> bool:
        return b"<html" not in body[:500].lower() and len(_LINE.findall(body)) >= 2
