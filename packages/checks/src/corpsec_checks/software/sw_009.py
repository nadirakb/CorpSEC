"""SW-009 — the WordPress theme seen on the site has no known vulnerabilities."""

from __future__ import annotations

import re

from corpsec_checks.software._components import WordPressComponentCheck


class VulnerableThemes(WordPressComponentCheck):
    id = "SW-009"
    version = "1.0.0"
    prefix = "wordpress-theme:"
    folder = "themes"
    version_file = "style.css"
    # The theme header comment at the top of style.css: "Version: 2.4.1"
    version_re = re.compile(r"^\s*\*?\s*Version:\s*([\d.]+)\s*$", re.I | re.M)
