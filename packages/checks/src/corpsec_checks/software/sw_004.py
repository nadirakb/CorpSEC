"""SW-004 — WordPress plugins seen on the site have no known vulnerabilities."""

from __future__ import annotations

import re

from corpsec_checks.software._components import WordPressComponentCheck


class VulnerablePlugins(WordPressComponentCheck):
    id = "SW-004"
    version = "1.0.0"
    prefix = "wordpress-plugin:"
    folder = "plugins"
    version_file = "readme.txt"
    version_re = re.compile(r"^\s*Stable tag:\s*([\d.]+)\s*$", re.I | re.M)
