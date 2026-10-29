"""EXP-001 — the ``.git`` folder (full source code history) is not downloadable."""

import re

from corpsec_checks.exposure._probe import ExposedFileCheck
from corpsec_scanner import Severity


class GitExposed(ExposedFileCheck):
    id = "EXP-001"
    version = "1.0.0"
    paths = ("/.git/HEAD",)
    severity = Severity.CRITICAL
    pattern = re.compile(rb"^ref: refs/|^[0-9a-f]{40}\s*$")
