# Vulnerable lab

An isolated network with two websites, used to check that the scanner finds real problems
and stays quiet on a well-configured site (MVP exit criterion M1).

| Host | What it is |
|---|---|
| `corpsec-lab-bad.com` | Deliberately broken: legacy TLS, weak cert, no security headers, exposed files, old WordPress/PHP/jQuery, CORS reflection, no email protection, dangling `www` CNAME |
| `corpsec-lab-good.com` | Hardened: redirect to HTTPS, lab-CA certificate, TLS 1.2+, all headers, SPF/DKIM/DMARC, CAA, DNSSEC (DS) |

CoreDNS (`172.30.0.53`) is authoritative for both domains; the scanner uses it instead of
public DNS and allows the lab network (`172.30.0.0/24`) explicitly. Nothing leaves the
lab network (it is `internal`).

```bash
docker compose -f deploy/lab/compose.yml build
docker compose -f deploy/lab/compose.yml up -d --wait dns bad good
docker compose -f deploy/lab/compose.yml run --rm runner
docker compose -f deploy/lab/compose.yml down -v
```
