"""CorpSEC check catalog (spec §6). One sub-package per check."""

from corpsec_checks.conn_001.check import HttpsReachable
from corpsec_checks.conn_002.check import HttpRedirectsToHttps
from corpsec_scanner import Check

CHECKS: tuple[type[Check], ...] = (
    HttpsReachable,
    HttpRedirectsToHttps,
)

__all__ = ["CHECKS"]
