"""EXP-003 — backup copies of ``wp-config.php`` (database password) are not downloadable."""

import re

from corpsec_checks.exposure._probe import ExposedFileCheck
from corpsec_scanner import Severity


class WpConfigBackupExposed(ExposedFileCheck):
    id = "EXP-003"
    version = "1.0.0"
    paths = ("/wp-config.php.bak", "/wp-config.php~", "/wp-config.old", "/wp-config.php.save")
    severity = Severity.CRITICAL
    pattern = re.compile(rb"DB_PASSWORD")
