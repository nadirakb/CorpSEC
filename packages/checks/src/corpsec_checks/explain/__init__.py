"""Plain-language explanations for findings (spec §8.2).

Each check has one YAML template per language in ``explain/<lang>/<CHECK-ID>.yaml``. The
template is the source of truth for everything a non-technical user reads: what the
problem is, why it matters, and how to fix it on *their* platform. Templates are linted in
CI for reading level and jargon (``tests/test_explain.py``).
"""

from corpsec_checks.explain.render import (
    HOSTED_PLATFORMS,
    Explanation,
    SiteContext,
    Template,
    explain,
    load_templates,
    template_for,
)

__all__ = [
    "HOSTED_PLATFORMS",
    "Explanation",
    "SiteContext",
    "Template",
    "explain",
    "load_templates",
    "template_for",
]
