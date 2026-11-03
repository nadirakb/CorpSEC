"""Template model, loading and rendering."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from corpsec_scanner.models import Finding, Severity

TEMPLATE_DIR = Path(__file__).parent
HOSTED_PLATFORMS = frozenset({"shopify", "wix", "squarespace", "webflow"})
"""Platforms where the provider, not the site owner, controls servers and certificates."""

PLATFORM_NAMES = {
    "wordpress": "WordPress",
    "joomla": "Joomla",
    "drupal": "Drupal",
    "ghost": "Ghost",
    "shopify": "Shopify",
    "wix": "Wix",
    "squarespace": "Squarespace",
    "webflow": "Webflow",
    "google_workspace": "Google Workspace",
    "microsoft_365": "Microsoft 365",
    "zoho": "Zoho Mail",
    "cloudflare": "Cloudflare",
    "php": "PHP",
    "nginx": "nginx",
    "apache-http-server": "Apache",
    "iis": "IIS",
    "jquery": "jQuery",
}


def pretty_product(value: str) -> str:
    """``wordpress-plugin:contact-form-7`` -> ``contact-form-7``; ``php`` -> ``PHP``."""
    if value.startswith("wordpress-plugin:"):
        return value.split(":", 1)[1]
    return PLATFORM_NAMES.get(value, value)


_PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-z_]+)\s*(?:\|([^}]*))?\}\}")


class Template(BaseModel):
    model_config = ConfigDict(extra="forbid")

    check_id: str
    title: str
    """Shown when the check found a problem (or for info-only checks, what it found)."""
    pass_title: str
    """Shown in the "Passed" list."""
    summary: str
    analogy: str | None = None
    why_it_matters: list[str] = Field(default_factory=list)
    fix: dict[str, list[str]] = Field(default_factory=dict)
    """Steps per platform key; ``default`` is required unless the check never fails."""
    effort_minutes: int = 0
    who_can_fix: str = ""
    technical: str
    """For the IT person; may use jargon."""
    variables: list[str] = Field(default_factory=list)
    """Placeholders beyond the global ones (domain, host, item, platform names)."""

    @property
    def steps(self) -> int:
        return len(self.fix.get("default", []))


@dataclass(frozen=True, slots=True)
class SiteContext:
    """What we know about the site from the whole scan, used to pick fix guides."""

    domain: str
    host: str
    platform: str | None = None
    email_provider: str | None = None
    dns_provider: str | None = None

    @classmethod
    def from_findings(cls, domain: str, host: str, findings: list[Finding]) -> SiteContext:
        ctx: dict[str, str] = {}
        for f in findings:
            for key in ("platform", "email_provider", "dns_provider"):
                if f.context.get(key):
                    ctx.setdefault(key, f.context[key])
        return cls(domain=domain, host=host, **ctx)


class Explanation(BaseModel):
    check_id: str
    title: str
    summary: str
    analogy: str | None
    why_it_matters: list[str]
    fix_steps: list[str]
    fix_for: str
    """Which variant was chosen: a platform key or ``default``."""
    effort: str
    who_can_fix: str
    technical: str


def effort_text(minutes: int) -> str:
    if minutes <= 0:
        return ""
    if minutes < 60:
        return f"about {minutes} minutes"
    hours = round(minutes / 60)
    return "about 1 hour" if hours == 1 else f"about {hours} hours"


@cache
def load_templates(lang: str = "en") -> dict[str, Template]:
    out: dict[str, Template] = {}
    for path in sorted((TEMPLATE_DIR / lang).glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        tpl = Template.model_validate(data)
        if tpl.check_id != path.stem:
            raise ValueError(f"{path.name}: check_id {tpl.check_id} doesn't match file name")
        out[tpl.check_id] = tpl
    return out


def template_for(check_id: str, lang: str = "en") -> Template | None:
    return load_templates(lang).get(check_id)


def variables_for(finding: Finding, site: SiteContext) -> dict[str, str]:
    values: dict[str, str] = {
        "domain": site.domain,
        "host": finding.host,
        "item": finding.dedupe_key,
    }
    for key in ("platform", "email_provider", "dns_provider"):
        raw = getattr(site, key)
        if raw:
            values[f"{key}_name"] = PLATFORM_NAMES.get(raw, raw.replace("_", " ").title())
    observed = finding.evidence.observed
    if isinstance(observed, dict):
        for k, v in observed.items():
            if isinstance(v, str | int | float) and not isinstance(v, bool):
                values[k] = str(v)
    values.update({k: v for k, v in finding.context.items() if v})
    for key in ("product", "item"):
        if key in values:
            values[key] = pretty_product(values[key])
    return values


def render(text: str, values: dict[str, str]) -> str:
    def sub(m: re.Match[str]) -> str:
        return values.get(m.group(1)) or (m.group(2) or "").strip()

    return _PLACEHOLDER_RE.sub(sub, text)


def choose_fix(tpl: Template, finding: Finding, site: SiteContext) -> str:
    candidates = [
        finding.context.get("email_provider"),
        site.email_provider if finding.check_id.startswith("MAIL-") else None,
        finding.context.get("platform"),
        site.platform,
        site.email_provider,
        site.dns_provider,
        "hosted" if site.platform in HOSTED_PLATFORMS else None,
    ]
    for key in candidates:
        if key and key in tpl.fix:
            return key
    return "default"


def explain(finding: Finding, site: SiteContext, lang: str = "en") -> Explanation | None:
    tpl = template_for(finding.check_id, lang)
    if tpl is None:
        return None
    values = variables_for(finding, site)
    passed = finding.severity == Severity.PASS
    fix_for = choose_fix(tpl, finding, site)
    return Explanation(
        check_id=finding.check_id,
        title=render(tpl.pass_title if passed else tpl.title, values),
        summary=render(tpl.summary, values),
        analogy=render(tpl.analogy, values) if tpl.analogy else None,
        why_it_matters=[render(s, values) for s in tpl.why_it_matters],
        fix_steps=[] if passed else [render(s, values) for s in tpl.fix.get(fix_for, [])],
        fix_for=fix_for,
        effort=effort_text(tpl.effort_minutes),
        who_can_fix=render(tpl.who_can_fix, values),
        technical=render(tpl.technical, values),
    )


def placeholders(text: str) -> set[str]:
    return {m.group(1) for m in _PLACEHOLDER_RE.finditer(text)}


def template_text(tpl: Template) -> dict[str, Any]:
    """All user-facing text of a template, for linting."""
    return {
        "title": tpl.title,
        "pass_title": tpl.pass_title,
        "summary": tpl.summary,
        "analogy": tpl.analogy or "",
        "why_it_matters": tpl.why_it_matters,
        "fix": tpl.fix,
        "who_can_fix": tpl.who_can_fix,
    }
