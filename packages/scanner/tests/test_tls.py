import struct

from corpsec_scanner.testing import tls_server
from corpsec_scanner.tls import (
    COMMON_SUITES,
    TLS1_0,
    TLS1_2,
    WEAK_SUITES,
    TlsProber,
    build_client_hello,
    parse_server_response,
)


def test_client_hello_structure() -> None:
    hello = build_client_hello("example.com", TLS1_2, (0xC02F, 0x002F))
    assert hello[0] == 0x16
    assert struct.unpack("!H", hello[3:5])[0] == len(hello) - 5
    assert hello[5] == 0x01  # ClientHello
    assert struct.unpack("!H", hello[9:11])[0] == TLS1_2
    assert b"example.com" in hello


def test_parse_alert_and_server_hello() -> None:
    assert parse_server_response(b"\x15\x03\x03\x00\x02\x02\x28").alert == 0x28
    sh = b"\x02\x00\x00\x00" + struct.pack("!H", TLS1_2) + b"\x00" * 32 + b"\x00" + b"\xc0\x2f"
    result = parse_server_response(b"\x16\x03\x03" + struct.pack("!H", len(sh)) + sh)
    assert result.accepted
    assert (result.version, result.cipher) == (TLS1_2, 0xC02F)
    assert not parse_server_response(b"").accepted


async def test_handshake_trusted_cert() -> None:
    async with tls_server(["tls.example.com"]) as (port, net):
        r = await TlsProber(net).handshake("tls.example.com", port)
    assert r.verify_error is None
    assert r.version == "TLSv1.3"
    assert r.cert_der


async def test_handshake_self_signed_reports_error_but_returns_cert() -> None:
    async with tls_server(["tls.example.com"], trusted=False) as (port, net):
        r = await TlsProber(net).handshake("tls.example.com", port)
    assert r.verify_error and "self" in r.verify_error.lower()
    assert r.cert_der


async def test_handshake_hostname_mismatch() -> None:
    async with tls_server(["other.example.com"]) as (port, net):
        r = await TlsProber(net).handshake("tls.example.com", port)
    assert r.verify_error and "hostname" in r.verify_error.lower()


async def test_hello_probes() -> None:
    async with tls_server(["tls.example.com"]) as (port, net):
        prober = TlsProber(net)
        modern = await prober.hello("tls.example.com", TLS1_2, COMMON_SUITES, port)
        legacy = await prober.hello("tls.example.com", TLS1_0, COMMON_SUITES, port)
        rc4 = await prober.hello("tls.example.com", TLS1_2, WEAK_SUITES["RC4"], port)
    assert modern.accepted and modern.version == TLS1_2
    assert not legacy.accepted
    assert not rc4.accepted
