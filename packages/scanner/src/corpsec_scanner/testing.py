"""Test helpers shared by the scanner, check and lab test suites. Not used at runtime."""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from corpsec_scanner.netguard import IpPolicy, NetConfig


@dataclass(frozen=True, slots=True)
class CertFiles:
    cert: Path
    key: Path
    der: bytes


def make_cert(
    hostnames: list[str],
    *,
    directory: Path,
    days_valid: int = 90,
    not_before_days_ago: int = 1,
    key: str = "ec256",
    issuer_cert: x509.Certificate | None = None,
    issuer_key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | None = None,
    is_ca: bool = False,
    name: str = "leaf",
) -> CertFiles:
    if key.startswith("rsa"):
        private: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey = rsa.generate_private_key(
            65537, int(key[3:])
        )
    else:
        private = ec.generate_private_key({"ec256": ec.SECP256R1(), "ec384": ec.SECP384R1()}[key])
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])])
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject if issuer_cert else subject)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=not_before_days_ago))
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if not is_ca:
        sans: list[x509.GeneralName] = []
        for h in hostnames:
            try:
                sans.append(x509.IPAddress(ipaddress.ip_address(h)))
            except ValueError:
                sans.append(x509.DNSName(h))
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    cert = builder.sign(issuer_key or private, hashes.SHA256())
    cert_path = directory / f"{name}.crt"
    key_path = directory / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return CertFiles(
        cert=cert_path, key=key_path, der=cert.public_bytes(serialization.Encoding.DER)
    )


def loopback_net(ca_file: str | None = None) -> NetConfig:
    """A NetConfig that resolves every host to 127.0.0.1 and allows loopback."""

    async def resolver(host: str, port: int) -> list[str]:
        return ["127.0.0.1"]

    return NetConfig(policy=IpPolicy(allow_loopback=True), resolver=resolver, ca_file=ca_file)


@asynccontextmanager
async def tls_server(
    hostnames: list[str],
    *,
    days_valid: int = 90,
    key: str = "ec256",
    minimum_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2,
    maximum_version: ssl.TLSVersion = ssl.TLSVersion.MAXIMUM_SUPPORTED,
    trusted: bool = True,
) -> AsyncIterator[tuple[int, NetConfig]]:
    """Serve TLS on 127.0.0.1. Yields (port, NetConfig). ``trusted`` signs with a test CA
    that the NetConfig trusts; otherwise the cert is self-signed and verification fails."""
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        ca_file: str | None = None
        if trusted:
            ca = make_cert(["CorpSEC Test CA"], directory=d, is_ca=True, name="ca", days_valid=3650)
            ca_cert = x509.load_pem_x509_certificate(ca.cert.read_bytes())
            ca_key = serialization.load_pem_private_key(ca.key.read_bytes(), None)
            assert isinstance(ca_key, ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey)
            leaf = make_cert(
                hostnames,
                directory=d,
                days_valid=days_valid,
                key=key,
                issuer_cert=ca_cert,
                issuer_key=ca_key,
            )
            ca_file = str(ca.cert)
        else:
            leaf = make_cert(hostnames, directory=d, days_valid=days_valid, key=key)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")  # allow deliberately weak test keys
        ctx.load_cert_chain(leaf.cert, leaf.key)
        ctx.minimum_version = minimum_version
        ctx.maximum_version = maximum_version

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            with suppress(ConnectionError, ssl.SSLError):
                await reader.read(1024)
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
        port = server.sockets[0].getsockname()[1]
        async with server:
            yield port, loopback_net(ca_file)
