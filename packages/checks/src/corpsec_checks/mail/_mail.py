"""Email/DNS helpers: provider detection, SPF and DMARC parsing."""

from __future__ import annotations

from dataclasses import dataclass, field

from corpsec_scanner.dns import DnsClient, DnsError

PROVIDERS: dict[str, tuple[str, ...]] = {
    "google_workspace": ("google.com", "googlemail.com"),
    "microsoft_365": ("mail.protection.outlook.com",),
    "zoho": ("zoho.com", "zoho.eu", "zoho.in"),
    "proton": ("protonmail.ch",),
    "fastmail": ("messagingengine.com",),
    "yandex": ("yandex.net", "yandex.ru"),
    "ovh": ("ovh.net",),
    "gandi": ("gandi.net",),
    "ionos": ("ionos.com", "kundenserver.de", "perfora.net"),
    "godaddy": ("secureserver.net",),
    "namecheap": ("privateemail.com", "registrar-servers.com"),
    "icloud": ("mail.icloud.com",),
}

DKIM_SELECTORS: dict[str | None, tuple[str, ...]] = {
    "google_workspace": ("google",),
    "microsoft_365": ("selector1", "selector2"),
    "zoho": ("zmail", "zoho"),
    "proton": ("protonmail", "protonmail2", "protonmail3"),
    "fastmail": ("fm1", "fm2", "fm3"),
    "yandex": ("mail",),
    None: ("default", "dkim", "mail", "k1", "s1", "s2", "selector1", "google"),
}


def detect_provider(mx_hosts: list[str]) -> str | None:
    for host in mx_hosts:
        for provider, suffixes in PROVIDERS.items():
            if any(host == s or host.endswith("." + s) for s in suffixes):
                return provider
    return None


def parse_mx(records: list[str]) -> list[str]:
    """``["10 aspmx.l.google.com."]`` -> ``["aspmx.l.google.com"]``. Null MX (RFC 7505) -> []."""
    hosts = []
    for rec in records:
        parts = rec.split()
        if len(parts) == 2 and parts[1] != ".":
            hosts.append(parts[1].rstrip(".").lower())
    return hosts


def spf_records(txt: list[str]) -> list[str]:
    return [t for t in txt if t.lower().startswith("v=spf1") and (len(t) == 6 or t[6] == " ")]


_LOOKUP_MECHANISMS = ("include:", "a", "mx", "ptr", "exists:", "redirect=")
_KNOWN = ("all", "include:", "a", "mx", "ptr", "ip4:", "ip6:", "exists:", "redirect=", "exp=")


@dataclass(slots=True)
class SpfAnalysis:
    record: str
    lookups: int = 0
    all_qualifier: str | None = None
    """``-``, ``~``, ``?``, ``+`` or None when the record has no ``all``."""
    has_redirect: bool = False
    invalid_terms: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _mechanism(term: str) -> tuple[str, str]:
    qualifier = term[0] if term[0] in "+-~?" else "+"
    return qualifier, term.lstrip("+-~?").lower()


def _counts_lookup(mech: str) -> bool:
    return any(
        mech == m
        or mech.startswith(m if m.endswith((":", "=")) else m + ":")
        or (m in ("a", "mx") and mech.startswith(m + "/"))
        for m in _LOOKUP_MECHANISMS
    )


async def analyze_spf(dns: DnsClient, record: str, *, max_depth: int = 10) -> SpfAnalysis:
    """Parse the top-level record and count DNS lookups recursively (RFC 7208 §4.6.4)."""
    result = SpfAnalysis(record=record)
    for term in record.split()[1:]:
        qualifier, mech = _mechanism(term)
        if mech == "all":
            result.all_qualifier = qualifier
        elif mech.startswith("redirect="):
            result.has_redirect = True
        elif not any(
            mech == k or mech.startswith(k) or mech.startswith(k + "/") or mech.startswith(k + ":")
            for k in _KNOWN
        ):
            result.invalid_terms.append(term)
    result.lookups = await _count_lookups(dns, record, depth=0, max_depth=max_depth, seen=set())
    return result


async def _count_lookups(
    dns: DnsClient, record: str, *, depth: int, max_depth: int, seen: set[str]
) -> int:
    total = 0
    for term in record.split()[1:]:
        _q, mech = _mechanism(term)
        if not _counts_lookup(mech):
            continue
        total += 1
        if mech.startswith(("include:", "redirect=")) and depth < max_depth:
            target = mech.split(":", 1)[1] if mech.startswith("include:") else mech.split("=", 1)[1]
            if target in seen:
                continue
            seen.add(target)
            try:
                nested = spf_records(await dns.resolve(target, "TXT"))
            except DnsError:
                continue
            if nested:
                total += await _count_lookups(
                    dns, nested[0], depth=depth + 1, max_depth=max_depth, seen=seen
                )
    return total


def parse_tags(record: str) -> dict[str, str]:
    """``v=DMARC1; p=none; pct=100`` -> ``{"v": "DMARC1", "p": "none", "pct": "100"}``."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        key, sep, value = part.strip().partition("=")
        if sep:
            tags[key.strip().lower()] = value.strip()
    return tags


async def dmarc_record(dns: DnsClient, domain: str) -> str | None:
    records = [
        t for t in await dns.resolve(f"_dmarc.{domain}", "TXT") if t.lower().startswith("v=dmarc1")
    ]
    return records[0] if len(records) == 1 else None
