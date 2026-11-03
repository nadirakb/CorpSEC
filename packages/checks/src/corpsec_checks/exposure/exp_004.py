"""EXP-004 — website/database backup archives are not downloadable."""

import re

from corpsec_checks.exposure._probe import ExposedFileCheck
from corpsec_scanner import Severity

_SQL = re.compile(rb"(CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump)", re.I)


class BackupArchiveExposed(ExposedFileCheck):
    id = "EXP-004"
    version = "1.0.0"
    paths = ("/backup.zip", "/backup.sql", "/db.sql", "/site.tar.gz", "/backup.tar.gz")
    severity = Severity.CRITICAL
    show_excerpt = False

    def signature(self, body: bytes) -> bool:
        return (
            body.startswith(b"PK\x03\x04")  # zip
            or body.startswith(b"\x1f\x8b")  # gzip
            or bool(_SQL.search(body))
        )
