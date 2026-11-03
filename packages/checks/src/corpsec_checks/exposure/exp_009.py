"""EXP-009 — PHP debug logs (paths, sometimes data) are not downloadable."""

import re

from corpsec_checks.exposure._probe import ExposedFileCheck
from corpsec_scanner import Severity


class DebugLogExposed(ExposedFileCheck):
    id = "EXP-009"
    version = "1.0.0"
    paths = ("/debug.log", "/wp-content/debug.log", "/error_log")
    severity = Severity.MEDIUM
    pattern = re.compile(rb"^\[\d{2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2}[^\]]*\] PHP ", re.M)
