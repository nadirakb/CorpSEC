"""Evidence redaction (spec §10.2).

Anyone can scan any public site, so a report must not hand a stranger a map to someone
else's leaked files. Until the viewer has proved they own the site, findings that point
at a specific exposed location keep their title and fix steps but lose the location and
the content we saw.
"""

from __future__ import annotations

from corpsec_scanner.models import Evidence, Finding, Severity

HIDDEN = "Hidden until you verify that you own this site."


def needs_redaction(check_id: str) -> bool:
    return check_id.startswith("EXP-") or check_id in ("DIR-001", "ERR-001")


def redact(finding: Finding) -> Finding:
    # A pass ("none of these paths were exposed") reveals nothing about a weakness.
    if not needs_redaction(finding.check_id) or finding.severity in (Severity.PASS, Severity.INFO):
        return finding
    return finding.model_copy(
        update={
            "dedupe_key": "",
            "evidence": Evidence(
                kind=finding.evidence.kind,
                captured_at=finding.evidence.captured_at,
                observed=HIDDEN,
            ),
        }
    )
