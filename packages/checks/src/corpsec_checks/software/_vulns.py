"""Turn intel vulnerability matches into observations."""

from __future__ import annotations

from corpsec_checks._common import observe
from corpsec_scanner import Confidence, Observation, Severity
from corpsec_scanner.intel import IntelSnapshot, Vulnerability


def vuln_severity(intel: IntelSnapshot, vulns: list[Vulnerability]) -> Severity:
    if any(intel.in_kev(v) for v in vulns):
        return Severity.CRITICAL
    if any(v.severity == "critical" or (v.cvss or 0) >= 9.0 for v in vulns):
        return Severity.CRITICAL
    return Severity.HIGH


def vuln_observation(
    host: str,
    intel: IntelSnapshot,
    product: str,
    version: str,
    vulns: list[Vulnerability],
    *,
    confidence: Confidence,
    source: str,
    severity: Severity | None = None,
) -> Observation:
    return observe(
        host,
        severity or vuln_severity(intel, vulns),
        "fingerprint",
        confidence=confidence,
        observed={
            "product": product,
            "version": version,
            "version_source": source,
            "vulnerabilities": [
                {
                    "ids": v.ids[:5],
                    "severity": v.severity,
                    "cvss": v.cvss,
                    "known_exploited": intel.in_kev(v),
                    "summary": v.summary[:200],
                }
                for v in vulns[:20]
            ],
            "total": len(vulns),
        },
        expected="No known vulnerabilities in the installed version",
        dedupe_key=product,
        references=[
            f"https://nvd.nist.gov/vuln/detail/{i}"
            for v in vulns[:5]
            for i in v.ids
            if i.startswith("CVE-")
        ][:5],
    )
