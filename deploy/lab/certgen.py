"""Create the lab CA and site certificates: ``python certgen.py /certs``."""

import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from corpsec_scanner.testing import make_cert

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
if (out / "ca.crt").exists():
    # compose re-runs this one-shot service whenever a dependent starts; keep the certs
    # nginx already loaded.
    print("certificates already present in", out)
    sys.exit(0)
ca = make_cert(["CorpSEC Lab CA"], directory=out, is_ca=True, name="ca", days_valid=3650)
ca_cert = x509.load_pem_x509_certificate(ca.cert.read_bytes())
ca_key = serialization.load_pem_private_key(ca.key.read_bytes(), None)

# Hardened site: lab-CA signed, EC P-256, 90 days.
make_cert(
    ["corpsec-lab-good.com", "www.corpsec-lab-good.com"],
    directory=out,
    name="good",
    issuer_cert=ca_cert,
    issuer_key=ca_key,  # type: ignore[arg-type]
)
# Broken site: self-signed, RSA-1024, expires in 2 days. www is listed so DNS-004 sees it.
make_cert(
    ["corpsec-lab-bad.com", "www.corpsec-lab-bad.com"],
    directory=out,
    name="bad",
    key="rsa1024",
    days_valid=2,
)
for f in out.iterdir():
    f.chmod(0o644)  # nginx workers read the keys; lab only
print("certificates written to", out)
