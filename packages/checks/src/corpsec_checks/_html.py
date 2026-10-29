"""Minimal HTML extraction for checks (stdlib parser, tolerant of broken markup)."""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin


@dataclass(slots=True)
class Tag:
    name: str
    attrs: dict[str, str]


@dataclass(slots=True)
class HtmlDoc:
    base_url: str
    tags: list[Tag] = field(default_factory=list)
    title: str = ""

    def find(self, *names: str) -> list[Tag]:
        return [t for t in self.tags if t.name in names]

    def meta(self, name: str) -> str | None:
        for t in self.find("meta"):
            if t.attrs.get("name", "").lower() == name:
                return t.attrs.get("content")
        return None

    def links(self) -> list[str]:
        return [self.absolute(t.attrs["href"]) for t in self.find("a") if t.attrs.get("href")]

    def script_srcs(self) -> list[str]:
        return [self.absolute(t.attrs["src"]) for t in self.find("script") if t.attrs.get("src")]

    def asset_urls(self) -> list[str]:
        urls = self.script_srcs()
        urls += [self.absolute(t.attrs["href"]) for t in self.find("link") if t.attrs.get("href")]
        urls += [self.absolute(t.attrs["src"]) for t in self.find("img") if t.attrs.get("src")]
        return urls

    def absolute(self, url: str) -> str:
        return urljoin(self.base_url, url.strip())


class _Parser(HTMLParser):
    def __init__(self, doc: HtmlDoc) -> None:
        super().__init__(convert_charrefs=True)
        self.doc = doc
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.doc.tags.append(Tag(tag, {k.lower(): v or "" for k, v in attrs}))
        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and len(self.doc.title) < 200:
            self.doc.title += data


def parse_html(text: str, base_url: str) -> HtmlDoc:
    doc = HtmlDoc(base_url=base_url)
    parser = _Parser(doc)
    try:
        parser.feed(text)
        parser.close()
    except Exception:  # noqa: S110 - never let broken markup fail a check
        pass
    doc.title = doc.title.strip()
    return doc


def is_html(content_type: str | None) -> bool:
    return bool(content_type) and "html" in (content_type or "").lower()
