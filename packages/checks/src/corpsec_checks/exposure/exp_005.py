"""EXP-005 — no public ``phpinfo()`` page (reveals server configuration)."""

import re

from corpsec_checks.exposure._probe import ExposedFileCheck
from corpsec_scanner import Severity


class PhpInfoExposed(ExposedFileCheck):
    id = "EXP-005"
    version = "1.0.0"
    paths = ("/phpinfo.php", "/info.php")
    severity = Severity.HIGH
    show_excerpt = False
    pattern = re.compile(rb"<title>phpinfo\(\)</title>|PHP Version \d")
