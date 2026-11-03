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
    # Worst first: known-exploited, then highest score, so the report leads with what matters.
    shown = sorted(vulns, key=lambda v: (not intel.in_kev(v), -(v.cvss or 0.0)))[:20]
    # Licences of some sources (Wordfence/Defiant, MITRE) require their notice and licence
    # to travel with every copy of the data, so the evidence carries them.
    holders = sorted({h for v in shown for h in v.copyright if h in intel.attributions})
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
                    "url": v.url,
                    "copyright": [
                        intel.attributions[h].notice for h in v.copyright if h in intel.attributions
                    ],
                }
                for v in shown
            ],
            "total": len(vulns),
            "attributions": {h: intel.attributions[h].model_dump() for h in holders},
        },
        expected="No known vulnerabilities in the installed version",
        dedupe_key=product,
        references=[v.url for v in shown[:5] if v.url]
        + [
            f"https://nvd.nist.gov/vuln/detail/{i}"
            for v in shown[:5]
            for i in v.ids
            if i.startswith("CVE-")
        ][:5],
    )
