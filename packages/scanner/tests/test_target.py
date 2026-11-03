import pytest

from corpsec_scanner.target import InvalidTargetError, normalize_target


@pytest.mark.parametrize(
    ("raw", "host", "domain"),
    [
        ("example.com", "example.com", "example.com"),
        ("EXAMPLE.COM.", "example.com", "example.com"),
        ("https://www.example.com/path?x=1", "www.example.com", "example.com"),
        ("http://shop.example.co.uk", "shop.example.co.uk", "example.co.uk"),
        ("  bakı.az ", "xn--bak-lua.az", "xn--bak-lua.az"),
    ],
)
def test_normalizes(raw: str, host: str, domain: str) -> None:
    t = normalize_target(raw)
    assert (t.host, t.registrable_domain) == (host, domain)


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "127.0.0.1",
        "http://[::1]/",
        "localhost",
        "printer.local",
        "db.internal",
        "ftp://example.com",
        "https://user:pw@example.com",
        "com",
        "co.uk",
    ],
)
def test_rejects(raw: str) -> None:
    with pytest.raises(InvalidTargetError):
        normalize_target(raw)


def test_scope() -> None:
    t = normalize_target("www.example.com")
    assert t.in_scope("example.com")
    assert t.in_scope("API.example.com.")
    assert not t.in_scope("example.com.evil.net")
    assert not t.in_scope("notexample.com")
