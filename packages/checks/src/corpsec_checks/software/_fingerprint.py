"""Passive technology fingerprinting (spec §6.4): CMS, server software, WordPress plugins."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

from corpsec_checks._html import HtmlDoc, is_html, parse_html
from corpsec_scanner import Confidence
from corpsec_scanner.http import HttpResponse

CMS_PRODUCTS = (
    "wordpress",
    "joomla",
    "drupal",
    "ghost",
    "shopify",
    "wix",
    "squarespace",
    "webflow",
)
ADDON_PREFIXES = ("wordpress-plugin:", "wordpress-theme:")
"""Fingerprints of WordPress plugins/themes; matched by SW-004/SW-009, not SW-003."""
VERSIONED_CMS = ("wordpress", "joomla", "drupal", "ghost")


@dataclass(frozen=True, slots=True)
class Fingerprint:
    product: str
    """``wordpress``, ``php``, ``nginx``, ``wordpress-plugin:<slug>``, ..."""
    version: str | None
    confidence: Confidence
    source: str

    @property
    def is_cms(self) -> bool:
        return self.product in CMS_PRODUCTS

    def label(self) -> str:
        return f"{self.product} {self.version}" if self.version else self.product


_GENERATOR_RE = {
    "wordpress": re.compile(r"^WordPress\s*([\d.]+)?", re.I),
    "joomla": re.compile(r"^Joomla!?\s*([\d.]+)?", re.I),
    "drupal": re.compile(r"^Drupal\s*([\d.]+)?", re.I),
    "ghost": re.compile(r"^Ghost\s*([\d.]+)?", re.I),
    "wix": re.compile(r"^Wix\.com", re.I),
    "squarespace": re.compile(r"^Squarespace", re.I),
    "webflow": re.compile(r"^Webflow", re.I),
}
_BODY_MARKERS = {
    "wordpress": ("/wp-content/", "/wp-includes/"),
    "joomla": ("/media/system/js/", "/media/jui/"),
    "drupal": ("Drupal.settings", "/sites/default/files/", "data-drupal-"),
    "shopify": ("cdn.shopify.com", "Shopify.theme"),
    "wix": ("static.wixstatic.com",),
    "squarespace": ("static1.squarespace.com",),
    "webflow": ("data-wf-site",),
}
_HEADER_MARKERS = {
    "shopify": ("x-shopid", "x-shopify-stage"),
    "wix": ("x-wix-request-id",),
}
_SERVER_RE = re.compile(r"^(nginx|apache|microsoft-iis|litespeed|openresty)(?:/([\d.]+))?", re.I)
_SERVER_IDS = {"apache": "apache-http-server", "microsoft-iis": "iis"}
_POWERED_RE = re.compile(r"\b(PHP|ASP\.NET|Express)(?:/([\d.]+))?", re.I)
_WP_CORE_ASSET_RE = re.compile(r"/wp-includes/.+\?(?:.*&)?ver=([\d.]+)")
_WP_PLUGIN_RE = re.compile(r"/wp-content/plugins/([a-z0-9_\-]+)/")
_WP_THEME_RE = re.compile(r"/wp-content/themes/([a-z0-9_\-]+)/")
_DRUPAL_HEADER_RE = re.compile(r"Drupal\s*([\d.]+)?", re.I)


def fingerprint(pages: list[HttpResponse]) -> list[Fingerprint]:
    found: dict[str, Fingerprint] = {}

    def add(fp: Fingerprint) -> None:
        cur = found.get(fp.product)
        # prefer a fingerprint that has a version, then the more certain one
        if (
            cur is None
            or (fp.version and not cur.version)
            or (
                bool(fp.version) == bool(cur.version)
                and fp.confidence == Confidence.CONFIRMED
                and cur.confidence != Confidence.CONFIRMED
            )
        ):
            found[fp.product] = fp

    home = pages[0]
    for page in pages:
        h = page.headers
        if m := _SERVER_RE.match(h.get("server", "")):
            name = m.group(1).lower()
            add(
                Fingerprint(
                    _SERVER_IDS.get(name, name), m.group(2), Confidence.CONFIRMED, "Server header"
                )
            )
        for m in _POWERED_RE.finditer(h.get("x-powered-by", "")):
            add(
                Fingerprint(
                    m.group(1).lower(), m.group(2), Confidence.CONFIRMED, "X-Powered-By header"
                )
            )
        if m := _DRUPAL_HEADER_RE.search(h.get("x-generator", "")):
            add(Fingerprint("drupal", m.group(1), Confidence.CONFIRMED, "X-Generator header"))
        for product, names in _HEADER_MARKERS.items():
            if any(n in h for n in names):
                add(Fingerprint(product, None, Confidence.CONFIRMED, "response header"))

        if not is_html(h.get("content-type")):
            continue
        doc: HtmlDoc = parse_html(page.text, page.url)
        generator = doc.meta("generator") or ""
        for product, regex in _GENERATOR_RE.items():
            if m := regex.match(generator.strip()):
                version = m.group(1) if m.groups() else None
                add(Fingerprint(product, version, Confidence.CONFIRMED, "generator meta tag"))
        if page is home or len(found) < 3:
            for product, markers in _BODY_MARKERS.items():
                if any(mk in page.text for mk in markers):
                    add(Fingerprint(product, None, Confidence.LIKELY, "page content"))
        for url in doc.asset_urls():
            if m := _WP_CORE_ASSET_RE.search(url):
                add(Fingerprint("wordpress", m.group(1), Confidence.LIKELY, "core asset version"))
            if m := _WP_PLUGIN_RE.search(url):
                ver = parse_qs(urlsplit(url).query).get("ver", [None])[0]
                add(
                    Fingerprint(
                        f"wordpress-plugin:{m.group(1)}",
                        ver,
                        Confidence.POSSIBLE,
                        "plugin asset path",
                    )
                )
            if m := _WP_THEME_RE.search(url):
                ver = parse_qs(urlsplit(url).query).get("ver", [None])[0]
                add(
                    Fingerprint(
                        f"wordpress-theme:{m.group(1)}",
                        ver,
                        Confidence.POSSIBLE,
                        "theme asset path",
                    )
                )
    return list(found.values())


def platform(fps: list[Fingerprint]) -> str | None:
    for fp in fps:
        if fp.is_cms:
            return fp.product
    return None
