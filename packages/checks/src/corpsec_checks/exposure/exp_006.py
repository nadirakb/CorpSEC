"""EXP-006 — no ``.DS_Store`` file (lists the folder's file names)."""

from corpsec_checks.exposure._probe import ExposedFileCheck
from corpsec_scanner import Severity


class DsStoreExposed(ExposedFileCheck):
    id = "EXP-006"
    version = "1.0.0"
    paths = ("/.DS_Store",)
    severity = Severity.LOW
    show_excerpt = False

    def signature(self, body: bytes) -> bool:
        return body.startswith(b"\x00\x00\x00\x01Bud1")
