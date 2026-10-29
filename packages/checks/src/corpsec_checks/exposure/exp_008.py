"""EXP-008 — Subversion / Mercurial folders are not downloadable."""

from corpsec_checks.exposure._probe import ExposedFileCheck
from corpsec_scanner import Severity


class OtherVcsExposed(ExposedFileCheck):
    id = "EXP-008"
    version = "1.0.0"
    paths = ("/.svn/entries", "/.svn/wc.db", "/.hg/requires")
    severity = Severity.HIGH
    show_excerpt = False

    def signature(self, body: bytes) -> bool:
        return (
            body.startswith(b"SQLite format 3")  # .svn/wc.db
            or body.strip().isdigit()  # .svn/entries (format number) for svn >= 1.7
            or body.startswith(b"10\n\ndir")  # legacy .svn/entries
            or b"revlogv1" in body[:200]  # .hg/requires
        )
