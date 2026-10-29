"""Certificate parsing for TLS checks."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from corpsec_scanner.tls import HandshakeResult


@dataclass(frozen=True, slots=True)
class CertInfo:
    subject_cn: str | None
    issuer_cn: str | None
    sans: tuple[str, ...]
    not_before: datetime
    not_after: datetime
    key_type: str
    key_bits: int
    signature_hash: str | None

    def days_left(self, now: datetime | None = None) -> int:
        return (self.not_after - (now or datetime.now(UTC))).days

    def summary(self) -> dict[str, object]:
        return {
            "subject": self.subject_cn,
            "issuer": self.issuer_cn,
            "names": list(self.sans[:20]),
            "valid_from": self.not_before.isoformat(),
            "valid_until": self.not_after.isoformat(),
            "key": f"{self.key_type} {self.key_bits}",
            "signature_hash": self.signature_hash,
        }


@dataclass(frozen=True, slots=True)
class TlsInfo:
    handshake: HandshakeResult
    cert: CertInfo | None


def _cn(name: x509.Name) -> str | None:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else None


def parse_cert(der: bytes) -> CertInfo:
    cert = x509.load_der_x509_certificate(der)
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = tuple(san_ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        sans = ()
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_type, bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type, bits = "EC", key.curve.key_size
    elif isinstance(key, ed25519.Ed25519PublicKey):
        key_type, bits = "Ed25519", 256
    elif isinstance(key, ed448.Ed448PublicKey):
        key_type, bits = "Ed448", 448
    elif isinstance(key, dsa.DSAPublicKey):
        key_type, bits = "DSA", key.key_size
    else:
        key_type, bits = type(key).__name__, 0
    algo = cert.signature_hash_algorithm
    return CertInfo(
        subject_cn=_cn(cert.subject),
        issuer_cn=_cn(cert.issuer),
        sans=sans,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        key_type=key_type,
        key_bits=bits,
        signature_hash=algo.name if algo else None,
    )


def explain_verify_error(message: str) -> str:
    """Map OpenSSL's verify message to a short, stable reason code."""
    m = message.lower()
    if "expired" in m:
        return "expired"
    if "not yet valid" in m:
        return "not_yet_valid"
    if "hostname" in m or "ip address mismatch" in m:
        return "hostname_mismatch"
    if "self-signed" in m or "self signed" in m:
        return "self_signed"
    if "unable to get local issuer" in m or "unable to get issuer" in m:
        return "untrusted_or_incomplete_chain"
    if "key_too_small" in m or "key too small" in m or "key too weak" in m:
        return "weak_key"
    if "revoked" in m:
        return "revoked"
    return "untrusted"
