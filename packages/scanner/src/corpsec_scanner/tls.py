"""TLS probing (spec §6.2).

Two tools:

* :meth:`TlsProber.handshake` — a real handshake with Python's ``ssl`` to get the negotiated
  version, cipher, certificate and verification result.
* :meth:`TlsProber.hello` — a hand-built ClientHello that offers exactly the protocol version
  and cipher suites we choose, and reads which one the server picks from its ServerHello.
  Modern OpenSSL builds refuse to *offer* TLS 1.0 or RC4/3DES/EXPORT suites, so this is the
  only way to ask a server whether it would still accept them. No handshake is completed and
  no application data is sent.

All connections go through :func:`netguard.open_guarded_connection`.
"""

from __future__ import annotations

import asyncio
import os
import ssl
import struct
from dataclasses import dataclass

from corpsec_scanner.netguard import DEFAULT_NET, NetConfig, open_guarded_connection

TLS1_0 = 0x0301
TLS1_1 = 0x0302
TLS1_2 = 0x0303
VERSION_NAMES = {TLS1_0: "TLSv1.0", TLS1_1: "TLSv1.1", TLS1_2: "TLSv1.2", 0x0304: "TLSv1.3"}

# Cipher suites a modern server should accept over TLS 1.0-1.2 (used for version probes).
COMMON_SUITES: tuple[int, ...] = (
    0xC02F, 0xC030, 0xC02B, 0xC02C, 0xCCA8, 0xCCA9,  # ECDHE AEAD
    0xC013, 0xC014, 0xC009, 0xC00A,  # ECDHE CBC
    0x009C, 0x009D, 0x002F, 0x0035,  # RSA
    0x0033, 0x0039, 0x009E, 0x009F,  # DHE
    0x000A,  # RSA 3DES (last resort, only for version detection)
)  # fmt: skip

FORWARD_SECRET_SUITES: tuple[int, ...] = (
    0xC02F, 0xC030, 0xC02B, 0xC02C, 0xCCA8, 0xCCA9,
    0xC013, 0xC014, 0xC009, 0xC00A,
    0x009E, 0x009F, 0x0033, 0x0039,
)  # fmt: skip

# Insecure suites by category (IANA code points).
WEAK_SUITES: dict[str, tuple[int, ...]] = {
    "RC4": (0x0004, 0x0005, 0xC007, 0xC011, 0x0018),
    "3DES": (0x000A, 0x0016, 0xC008, 0xC012, 0x001B),
    "DES": (0x0009, 0x0015),
    "NULL": (0x0001, 0x0002, 0x003B, 0xC006, 0xC010),
    "EXPORT": (0x0003, 0x0006, 0x0008, 0x0011, 0x0014),
    "ANON": (0x0034, 0x00A6, 0xC018),
}
WEAK_SUITE_CATEGORY = {code: cat for cat, codes in WEAK_SUITES.items() for code in codes}

_GROUPS = (0x001D, 0x0017, 0x0018)  # x25519, secp256r1, secp384r1
_SIG_ALGS = (0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0201)


class ConnectionBudgetExceededError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class HandshakeResult:
    version: str
    cipher: str
    cert_der: bytes | None
    verify_error: str | None
    """``None`` when the certificate chain and hostname verified against the CA bundle."""


@dataclass(frozen=True, slots=True)
class HelloResult:
    accepted: bool
    version: int | None = None
    cipher: int | None = None
    alert: int | None = None


def build_client_hello(host: str, version: int, suites: tuple[int, ...]) -> bytes:
    def ext(kind: int, body: bytes) -> bytes:
        return struct.pack("!HH", kind, len(body)) + body

    name = host.encode("ascii")
    sni = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    groups = struct.pack(f"!H{len(_GROUPS)}H", len(_GROUPS) * 2, *_GROUPS)
    extensions = (
        ext(0x0000, sni)
        + ext(0x000A, groups)
        + ext(0x000B, b"\x01\x00")  # ec_point_formats: uncompressed
        + ext(0xFF01, b"\x00")  # renegotiation_info (empty)
    )
    if version >= TLS1_2:
        sigs = struct.pack(f"!H{len(_SIG_ALGS)}H", len(_SIG_ALGS) * 2, *_SIG_ALGS)
        extensions += ext(0x000D, sigs)

    body = (
        struct.pack("!H", version)
        + os.urandom(32)
        + b"\x00"  # empty session id
        + struct.pack(f"!H{len(suites)}H", len(suites) * 2, *suites)
        + b"\x01\x00"  # compression: null only
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    # Record layer version stays at TLS 1.0 for compatibility, as real clients do.
    return struct.pack("!BHH", 0x16, TLS1_0, len(handshake)) + handshake


def parse_server_response(data: bytes) -> HelloResult:
    """Parse the first TLS record the server sent back."""
    if len(data) < 5:
        return HelloResult(accepted=False)
    content_type = data[0]
    if content_type == 0x15 and len(data) >= 7:
        return HelloResult(accepted=False, alert=data[6])
    if content_type != 0x16 or len(data) < 5 + 4 + 2 + 32 + 1:
        return HelloResult(accepted=False)
    hs = data[5:]
    if hs[0] != 0x02:  # not a ServerHello
        return HelloResult(accepted=False)
    version = struct.unpack("!H", hs[4:6])[0]
    sid_len = hs[38]
    offset = 39 + sid_len
    if len(hs) < offset + 2:
        return HelloResult(accepted=False)
    cipher = struct.unpack("!H", hs[offset : offset + 2])[0]
    return HelloResult(accepted=True, version=version, cipher=cipher)


def _unverified_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Inspection must still work against servers with weak keys or old ciphers.
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    return ctx


class TlsProber:
    def __init__(
        self,
        net: NetConfig = DEFAULT_NET,
        *,
        max_connections: int = 40,
        timeout: float = 10.0,
        port: int = 443,
    ) -> None:
        self._net = net
        self._port = port
        self._max = max_connections
        self._timeout = timeout
        self._used = 0
        self._sems: dict[str, asyncio.Semaphore] = {}

    def _take(self, host: str) -> asyncio.Semaphore:
        if self._used >= self._max:
            raise ConnectionBudgetExceededError(f"limit of {self._max} TLS connections")
        self._used += 1
        return self._sems.setdefault(host, asyncio.Semaphore(2))

    async def handshake(self, host: str, port: int | None = None) -> HandshakeResult:
        """Handshake with verification; on failure, repeat without it to still get the cert."""
        port = port or self._port
        verify_error: str | None = None
        try:
            return await self._handshake(host, port, self._net.verifying_context(), None)
        except ssl.SSLCertVerificationError as exc:
            verify_error = exc.verify_message or str(exc)
        except ssl.SSLError as exc:
            # e.g. EE_KEY_TOO_SMALL: the chain is rejected by the default security level
            verify_error = exc.reason or str(exc)
        return await self._handshake(host, port, _unverified_context(), verify_error)

    async def _handshake(
        self, host: str, port: int, ctx: ssl.SSLContext, verify_error: str | None
    ) -> HandshakeResult:
        async with self._take(host):
            _reader, writer = await open_guarded_connection(
                self._net, host, port, ssl_context=ctx, timeout=self._timeout
            )
            try:
                sslobj = writer.get_extra_info("ssl_object")
                assert isinstance(sslobj, ssl.SSLObject)
                cipher = sslobj.cipher()
                return HandshakeResult(
                    version=sslobj.version() or "",
                    cipher=cipher[0] if cipher else "",
                    cert_der=sslobj.getpeercert(binary_form=True),
                    verify_error=verify_error,
                )
            finally:
                writer.close()

    async def hello(
        self, host: str, version: int, suites: tuple[int, ...], port: int | None = None
    ) -> HelloResult:
        port = port or self._port
        async with self._take(host):
            reader, writer = await open_guarded_connection(
                self._net, host, port, timeout=self._timeout
            )
            try:
                writer.write(build_client_hello(host, version, suites))
                await writer.drain()
                async with asyncio.timeout(self._timeout):
                    header = await reader.readexactly(5)
                    length = struct.unpack("!H", header[3:5])[0]
                    body = await reader.readexactly(min(length, 16384))
            except (asyncio.IncompleteReadError, ConnectionError, TimeoutError):
                # Many servers just close the connection instead of sending an alert.
                return HelloResult(accepted=False)
            finally:
                writer.close()
            return parse_server_response(header + body)
