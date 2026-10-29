"""EXP-007 — Apache ``server-status`` (shows visitors and internal URLs) is not public."""

import re

from corpsec_checks.exposure._probe import ExposedFileCheck
from corpsec_scanner import Severity


class ServerStatusExposed(ExposedFileCheck):
    id = "EXP-007"
    version = "1.0.0"
    paths = ("/server-status",)
    severity = Severity.MEDIUM
    show_excerpt = False
    pattern = re.compile(rb"Apache Server Status for")
