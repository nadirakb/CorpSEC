"""Proving a user controls a domain (spec §4.3): DNS TXT record, uploaded file or meta tag.

Runs in the worker, through the same SSRF-guarded, scope-locked clients as scans.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Literal

import httpx

from corpsec_checks._html import parse_html
from corpsec_scanner import ScanOptions
from corpsec_scanner.dns import DnsClient, DnsError
from corpsec_scanner.http import HttpPolicy, OutOfScopeError, SafeHttpClient
from corpsec_scanner.target import normalize_target

Method = Literal["dns", "file", "meta"]
METHODS: tuple[Method, ...] = ("dns", "file", "meta")
TXT_PREFIX = "corpsec-verify="
META_NAME = "corpsec-verification"


def as_method(value: str) -> Method:
    if value not in METHODS:
        raise ValueError(f"unknown verification method {value!r}")
    return value


def new_token() -> str:
    """160 random bits, base32: safe in DNS, URLs and file names."""
    return base64.b32encode(os.urandom(20)).decode().lower()


def file_path(token: str) -> str:
    return f"/.well-known/corpsec-{token}.txt"


@dataclass(frozen=True, slots=True)
class Instructions:
    txt_name: str
    txt_value: str
    file_url: str
    file_content: str
    meta_tag: str


def instructions(domain: str, token: str) -> Instructions:
    return Instructions(
        txt_name=domain,
        txt_value=f"{TXT_PREFIX}{token}",
        file_url=f"https://{domain}{file_path(token)}",
        file_content=token,
        meta_tag=f'<meta name="{META_NAME}" content="{token}">',
    )


@dataclass(frozen=True, slots=True)
class VerifyResult:
    verified: bool
    message: str
    """User-facing explanation, especially of what to try when it failed."""


async def check_ownership(
    domain: str, token: str, method: Method, options: ScanOptions | None = None
) -> VerifyResult:
    opts = options or ScanOptions()
    target = normalize_target(domain)
    if method == "dns":
        try:
            records = await (opts.dns or DnsClient()).resolve(target.registrable_domain, "TXT")
        except DnsError:
            return VerifyResult(False, "We couldn't look up your domain right now. Try again soon.")
        if any(r.strip() == f"{TXT_PREFIX}{token}" for r in records):
            return VerifyResult(True, "Found your DNS record.")
        return VerifyResult(
            False,
            "We couldn't find the TXT record yet. DNS changes can take up to an hour to show up.",
        )

    http = SafeHttpClient(
        target.in_scope,
        HttpPolicy(max_requests=12, max_body_bytes=500_000),
        net=opts.net,
        transport_factory=opts.transport_factory,
    )
    bases = [f"https://{target.registrable_domain}", f"https://www.{target.registrable_domain}"]
    try:
        for base in bases:
            try:
                if method == "file":
                    r = await http.get(base + file_path(token), verify=False, max_body=1024)
                    if r.status == 200 and not r.left_scope and token in r.text:
                        return VerifyResult(True, "Found your verification file.")
                else:
                    r = await http.get(base + "/", verify=False)
                    if r.status == 200 and not r.left_scope:
                        content = parse_html(r.text, r.url).meta(META_NAME)
                        if content and content.strip() == token:
                            return VerifyResult(True, "Found your verification tag.")
            except (httpx.TransportError, OutOfScopeError):
                continue
    finally:
        await http.aclose()
    if method == "file":
        return VerifyResult(
            False,
            "We couldn't find the verification file. Check the file name and that it is "
            "uploaded to the right folder.",
        )
    return VerifyResult(
        False,
        "We couldn't find the verification tag on your homepage. Make sure it is inside the "
        "<head> section and the page is published.",
    )
