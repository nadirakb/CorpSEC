"""Template lint (spec §8.2): coverage, structure, placeholders, reading level, jargon."""

import re
from datetime import UTC, datetime

import pytest

from corpsec_checks import CHECKS
from corpsec_checks.explain import SiteContext, explain, load_templates
from corpsec_checks.explain.render import placeholders
from corpsec_scanner.models import Evidence, Finding, Severity

TEMPLATES = load_templates("en")
PUBLIC_CHECKS = sorted(c.id for c in CHECKS if not c.internal)
INFO_ONLY = {"SW-001", "MAIL-001"}
GLOBAL_VARS = {
    "domain",
    "host",
    "item",
    "platform_name",
    "email_provider_name",
    "dns_provider_name",
}
MAX_GRADE = 8.0
MAX_STEPS = 5

# Not allowed in user-facing text unless explained in brackets right there,
# e.g. "an email protection rule (DMARC)". Case-sensitive for acronyms.
JARGON = [
    "CVE", "CVSS", "XSS", "CSRF", "SQL", "TLS", "SSL", "HSTS", "CSP", "CORS", "SPF", "DKIM",
    "DMARC", "DNSSEC", "CNAME", "MX", "RDAP", "HTTP", "HTTPS", "API", "PHP",
    "header", "headers", "cipher", "ciphers", "exploit", "exploits", "vulnerability",
    "vulnerabilities", "payload", "endpoint",
]  # fmt: skip
_JARGON_RE = re.compile(r"\b(" + "|".join(map(re.escape, JARGON)) + r")\b")


def plain_fields(tid: str) -> list[str]:
    t = TEMPLATES[tid]
    return [t.title, t.pass_title, t.summary, t.analogy or "", *t.why_it_matters]


def readable_text(tid: str) -> str:
    t = TEMPLATES[tid]
    parts = [*plain_fields(tid), *t.fix.get("default", [])]
    text = " ".join(p if p.rstrip().endswith((".", "!", "?")) else p + "." for p in parts if p)
    text = re.sub(r"`[^`]*`", "it", text)  # DNS values etc. aren't prose
    return re.sub(r"\{\{[^}]*\}\}", "it", text)


def syllables(word: str) -> int:
    w = re.sub(r"[^a-z]", "", word.lower())
    if not w:
        return 0
    count = len(re.findall(r"[aeiouy]+", w))
    if w.endswith("e") and not w.endswith(("le", "ee")) and count > 1:
        count -= 1
    return max(count, 1)


def fk_grade(text: str) -> float:
    sentences = max(1, len(re.findall(r"[.!?]+(\s|$)", text)))
    words = re.findall(r"[A-Za-z][A-Za-z'\-]*", text)
    syl = sum(syllables(w) for w in words)
    return 0.39 * len(words) / sentences + 11.8 * syl / max(1, len(words)) - 15.59


def test_every_public_check_has_a_template() -> None:
    assert sorted(TEMPLATES) == PUBLIC_CHECKS


@pytest.mark.parametrize("tid", PUBLIC_CHECKS)
def test_structure(tid: str) -> None:
    t = TEMPLATES[tid]
    if tid in INFO_ONLY:
        return
    steps = t.fix.get("default", [])
    assert 1 <= len(steps) <= MAX_STEPS, "default fix needs 1-5 steps"
    for key, variant in t.fix.items():
        assert 1 <= len(variant) <= MAX_STEPS, f"fix.{key} needs 1-5 steps"
    assert t.effort_minutes > 0
    assert t.who_can_fix
    assert t.why_it_matters


@pytest.mark.parametrize("tid", PUBLIC_CHECKS)
def test_placeholders_are_known(tid: str) -> None:
    t = TEMPLATES[tid]
    texts = [
        t.title,
        t.pass_title,
        t.summary,
        t.analogy or "",
        t.who_can_fix,
        t.technical,
        *t.why_it_matters,
        *(s for v in t.fix.values() for s in v),
    ]
    used = set().union(*(placeholders(x) for x in texts))
    assert used <= GLOBAL_VARS | set(t.variables), used - GLOBAL_VARS - set(t.variables)


@pytest.mark.parametrize("tid", PUBLIC_CHECKS)
def test_reading_level(tid: str) -> None:
    grade = fk_grade(readable_text(tid))
    assert grade <= MAX_GRADE, f"Flesch-Kincaid grade {grade:.1f} > {MAX_GRADE}"


@pytest.mark.parametrize("tid", PUBLIC_CHECKS)
def test_no_unexplained_jargon(tid: str) -> None:
    for text in plain_fields(tid):
        outside_brackets = re.sub(r"\([^)]*\)", "", text)
        outside_brackets = re.sub(r"\{\{[^}]*\}\}", "", outside_brackets)
        found = _JARGON_RE.findall(outside_brackets)
        assert not found, f"jargon {found} in: {text!r}"


@pytest.mark.parametrize("tid", PUBLIC_CHECKS)
def test_renders_without_leftover_placeholders(tid: str) -> None:
    now = datetime(2026, 10, 29, tzinfo=UTC)
    for severity in (Severity.HIGH, Severity.PASS):
        finding = Finding(
            check_id=tid, check_version="1.0.0", scan_id="scn_x", host="www.example.com",
            severity=severity, confidence="confirmed", evidence=Evidence(kind="http"),
            first_seen=now, last_seen=now,
        )  # fmt: skip
        site = SiteContext(domain="example.com", host="www.example.com")
        e = explain(finding, site)
        assert e is not None
        blob = " ".join(
            [
                e.title,
                e.summary,
                e.analogy or "",
                *e.why_it_matters,
                *e.fix_steps,
                e.who_can_fix,
                e.technical,
            ]
        )
        assert "{{" not in blob and "}}" not in blob
        assert "  " not in e.title, f"empty placeholder left a gap: {e.title!r}"
