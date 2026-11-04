# CorpSEC — MVP Specification

| | |
|---|---|
| Status | Draft v0.1 |
| Date | 2026-10-29 |
| Owner | Nadir Akbarov |

---

## 1. Summary

CorpSEC is a security checker for people who are not IT or security experts. A user enters their website or domain, presses one button, and gets:

- a single **A–F grade**,
- a short list of **what to fix first**, written in plain language,
- **step-by-step fix guides** for the platform they actually use (WordPress, Shopify, Wix, cPanel, Cloudflare, Google Workspace, Microsoft 365, …),
- **weekly monitoring** with an email when something gets worse.

It is inspired by professional tools (OWASP ZAP, Nmap, OpenVAS/Greenbone, Burp Suite, Qualys, Acunetix/Invicti) but deliberately trades depth for clarity and safety. Under the hood CorpSEC runs the same categories of checks; on the surface it hides CVE IDs, CVSS vectors and HTTP internals unless the user asks for "technical details".

### 1.1 Inspiration map

What CorpSEC borrows from each tool (from public documentation and product behaviour — no proprietary code or binaries are used):

| Source | Idea borrowed | Where in CorpSEC |
|---|---|---|
| OWASP ZAP | Passive-first scanning; "baseline scan" that never attacks | Entire MVP is passive (§5) |
| Nmap | Service fingerprinting → version → known issues | Tech-stack detection (§6.3) |
| OpenVAS / Greenbone | Large, versioned feed of checks; scheduled re-scans | Check catalog with versions (§6), monitoring (§7.4) |
| Burp Suite | Every finding has background + remediation text; issue definitions are reusable | Finding templates (§8) |
| Qualys (SSL Labs, VMDR) | **A–F grade** with "capped" grades for critical issues; one risk number | Grading model (§9) |
| Acunetix / Invicti | Proof/evidence attached to findings → fewer false positives; compliance-style report | Evidence field (§8), PDF report (§7.5) |

---

## 2. Goals and non-goals

### 2.1 Goals (MVP)

1. A non-technical user gets a useful result in **under 2 minutes** from landing on the site.
2. **Zero risk to the target**: MVP checks only read publicly available information with normal, low-volume requests.
3. Every finding is **actionable**: it says what to do, for the user's platform, in ≤ 5 steps.
4. **Low false-positive rate**: a finding is only shown when evidence is captured (§8.3).
5. Users can **track progress** over time (grade history, "fixed" findings).

### 2.2 Non-goals (MVP)

- No active/intrusive testing (SQL injection, XSS payloads, brute force, fuzzing). → v2, behind ownership verification.
- No authenticated scanning (logging into the user's site/app).
- No local/home network scanning (desktop agent). → v3.
- No scanning of IP ranges, arbitrary IPs, or hosts the user does not claim.
- No mobile apps.
- No penetration-testing workflow (proxy, repeater, intruder). CorpSEC is not a Burp replacement.

---

## 3. Users

| Persona | Description | Main question |
|---|---|---|
| **Small business owner** ("Leyla, runs a bakery site on WordPress") | Pays a freelancer to build the site, never looked at security | "Is my website safe? Can customers trust it?" |
| **Freelancer / small agency** ("Murad, builds Shopify/WP sites for clients") | Semi-technical, manages 5–30 client sites | "Which of my clients' sites need attention?" |
| **NGO / school admin** | Runs a domain + email, no IT staff | "Can someone send fake emails in our name?" |

Design rule: **every screen must make sense to Leyla.** Technical details are opt-in for Murad.

---

## 4. User flows

### 4.1 First scan (anonymous)

```
Landing page
  └─ input: "Your website or domain"  [example.com]  [Check my security]
       └─ normalize input → show "Checking example.com…" with live progress
            (5 stages: Connection • Encryption • Website settings • Software • Email)
            └─ Result page:
                 Grade card (A–F) + one-sentence verdict
                 "Fix these first" (max 3)
                 All findings grouped: Critical / Important / Good to fix / Passed
                 CTA: "Create a free account to monitor this site weekly"
```

- Anonymous scans are rate-limited (§10.3) and kept for 7 days via an unguessable share link.
- Anonymous users never see raw evidence that could help an attacker (e.g. exposed file contents) — only "an exposed file was found; verify ownership to see details" (§10.2).

### 4.2 Sign up & add site

1. Sign up with email magic link (no password to manage) or Google/Microsoft OAuth.
   *Implemented (M4):* magic link (single-use, 15 min, hashed tokens, silent rate limit, open-redirect-safe `next`); sessions in an HttpOnly/Secure/SameSite=Lax cookie with server-side storage; cross-site writes refused by an Origin check. Google/Microsoft sign-in uses OpenID Connect (authorization code + PKCE, `state`/`nonce`, ID token validated against the provider's discovery document and JWKS) and links accounts only by provider-verified email (Google `email_verified`; Microsoft personal accounts or `xms_edov`), remembering the provider subject so email changes don't break sign-in. Each provider is switched on only when its client id and secret are configured (`CORPSEC_GOOGLE_CLIENT_ID`/`_SECRET`, `CORPSEC_MICROSOFT_CLIENT_ID`/`_SECRET`; registration steps in the README); the web app shows buttons only for enabled providers.
2. Onboarding asks **one question**: "Where is your website built?" (WordPress / Shopify / Wix / Squarespace / Webflow / Custom / I don't know). Auto-detected value is preselected. Used to tailor fix guides.
3. Optional: "Where is your email hosted?" (Google Workspace / Microsoft 365 / Zoho / Other / I don't know) — also auto-detected from MX records.

### 4.3 Ownership verification

Required to: enable weekly monitoring, see sensitive evidence, (v2) run active tests.

Methods (user picks one; wizard with screenshots per DNS provider / platform):

| Method | How | Good for |
|---|---|---|
| DNS TXT | Add `corpsec-verify=<token>` TXT record on apex domain | Anyone with DNS access |
| HTML file | Upload `/.well-known/corpsec-<token>.txt` containing token | Custom/WordPress sites |
| Meta tag | `<meta name="corpsec-verification" content="<token>">` on homepage | Wix, Shopify, Squarespace (theme header editors) |

- Token: 32 random bytes, base32. One token per (user, domain).
- Verification is re-checked on every scheduled scan; if it fails 2 times in a row, monitoring pauses and the user is emailed.
- Verified ownership covers the apex domain and its subdomains.

### 4.4 Fix & re-check

Each finding has a **"I fixed it — check again"** button that re-runs only that check (cheap, ≤ 10 s). On success the finding moves to "Fixed" with a date, and the grade updates.

### 4.5 Monitoring

- Weekly full scan for each verified site (day/time randomized per site to spread load).
- Daily lightweight check: certificate expiry, domain expiry, site reachable.
- Email alert when: grade drops, a new Critical/Important finding appears, certificate expires in ≤ 14 days, domain expires in ≤ 30 days.
- Weekly digest email is opt-in.

*Implemented (gap closing):* the digest is a Monday-morning email with each site's latest grade and open-problem count, switched on from the Account page (`PATCH /v1/me {"weekly_digest": true}`) and sent at most once a week per person.

---

## 5. Scan scope and safety envelope (MVP)

The MVP scanner is **passive** in the ZAP sense: it behaves like a normal visitor plus public DNS/registry lookups.

Hard limits enforced in the worker (not just in the UI):

| Limit | Value |
|---|---|
| Hosts per scan | Apex + `www` + up to 5 subdomains discovered via certificate SANs / CT logs (shown, but only HTTP-checked if they resolve) |
| HTTP requests per scan | ≤ 150 |
| Concurrency per target host | 2 |
| Request rate per target host | ≤ 5 req/s |
| Pages crawled | ≤ 20 same-origin HTML pages, depth ≤ 2 |
| Ports | 80, 443 only (HTTP); DNS over resolver; no port scanning in MVP |
| Request methods | `GET`, `HEAD`, `OPTIONS` only |
| Payloads | None. No query-string tampering, no form submission |
| Sensitive-path probes | Fixed list of ≤ 25 paths (§6.5), `HEAD`/`GET`, body read capped at 4 KB |
| User-Agent | `CorpSEC/0.1 (+https://corpsec.app/bot)` — identifiable, documented bot page |
| Robots | Crawler respects `robots.txt` for crawling. Fixed sensitive-path probes do not (they are single requests to well-known locations, documented on the bot page) |
| Timeouts | 10 s per request; 120 s total scan budget |
| Target restrictions | Refuse private/reserved IPs (RFC1918, loopback, link-local, CGNAT, multicast, IPv6 ULA) after DNS resolution — SSRF guard, re-checked on every redirect |
| Redirects | Follow ≤ 5; leaving the registered domain stops the scan of that branch |

---

## 6. Check catalog (MVP)

Each check has a stable ID, a version, a category, a default severity, and a plain-language template (§8). Checks are grouped into the five progress stages shown to the user.

Internal collector checks (e.g. `CRAWL-001`, which crawls pages and records robots.txt and the soft-404 baseline for other checks) produce no findings and are hidden in the UI.

Severity levels (user-facing label in brackets):

- `critical` [Fix now] — actively exploitable or exposes secrets/data.
- `high` [Important] — significant weakness that attackers commonly use.
- `medium` [Should fix] — weakens protection.
- `low` [Good to fix] — best-practice gap.
- `info` [Good to know] — not a problem, shown for transparency.
- `pass` — check succeeded (shown in "Passed" list; builds confidence).

### 6.1 Stage 1 — Connection

| ID | Check | Severity if failed |
|---|---|---|
| `CONN-001` | Site reachable over HTTPS | critical |
| `CONN-002` | HTTP (port 80) redirects to HTTPS | high |
| `CONN-003` | `www` and apex both work and agree on a canonical host | low |
| `CONN-004` | No mixed content on homepage (HTTP sub-resources on HTTPS page) | medium |

### 6.2 Stage 2 — Encryption (TLS)

| ID | Check | Severity if failed |
|---|---|---|
| `TLS-001` | Certificate valid (chain trusted, hostname matches, not expired) | critical |
| `TLS-002` | Certificate expires in > 14 days (≤ 14 → high, ≤ 3 → critical) | high/critical |
| `TLS-003` | TLS 1.0 / 1.1 disabled | medium |
| `TLS-004` | TLS 1.2 or 1.3 supported (1.3 → bonus pass) | high |
| `TLS-005` | No weak cipher suites (RC4, 3DES, NULL, EXPORT, anon) | high |
| `TLS-006` | Forward secrecy supported | low |
| `TLS-007` | HSTS header present, `max-age` ≥ 15552000 (180 d) | medium |
| `TLS-008` | Certificate key strength (RSA ≥ 2048 / EC ≥ 256) | high |

### 6.3 Stage 3 — Website settings (headers, cookies, exposure)

| ID | Check | Severity if failed |
|---|---|---|
| `HDR-001` | `Content-Security-Policy` present (any policy → pass with note; `unsafe-inline` + `unsafe-eval` → low) | medium |
| `HDR-002` | Clickjacking protection: `frame-ancestors` in CSP or `X-Frame-Options` | medium |
| `HDR-003` | `X-Content-Type-Options: nosniff` | low |
| `HDR-004` | `Referrer-Policy` set and not `unsafe-url` | low |
| `HDR-005` | `Permissions-Policy` present | info |
| `HDR-006` | Server/version banner disclosure (`Server`, `X-Powered-By` with version numbers) | low |
| `CK-001` | Session-like cookies have `Secure` | medium |
| `CK-002` | Session-like cookies have `HttpOnly` | medium |
| `CK-003` | Cookies set `SameSite` | low |
| `CORS-001` | `Access-Control-Allow-Origin: *` together with `Allow-Credentials: true`, or origin reflected for an arbitrary `Origin` header | high |
| `DIR-001` | Directory listing enabled on any crawled path | medium |
| `ERR-001` | Verbose error/stack trace observed on crawled pages | medium |
| `SEC-001` | `/.well-known/security.txt` present | info |

### 6.4 Stage 4 — Software (fingerprint → known issues)

Nmap-style fingerprinting adapted to the web: identify technologies and versions from passive signals, then look them up.

| ID | Check | Severity if failed |
|---|---|---|
| `SW-001` | CMS detected (WordPress, Joomla, Drupal, Shopify, Wix, Squarespace, Webflow, …) | info |
| `SW-002` | CMS core version outdated (≥ 1 major/minor behind latest stable) | medium |
| `SW-003` | Detected version has known vulnerabilities (CVE match, KEV-listed → critical) | high/critical |
| `SW-004` | WordPress plugins/themes with known vulnerabilities (detected passively from asset paths `?ver=`, readme exposure) | high/critical |
| `SW-005` | Outdated client-side JS libraries with known vulns (jQuery, Bootstrap, Angular.js, Lodash, Moment) | medium |
| `SW-006` | End-of-life server software (e.g. PHP version from headers) | high |
| `SW-007` | WordPress user enumeration via `/wp-json/wp/v2/users` | low |
| `SW-008` | WordPress `xmlrpc.php` enabled | low |

Data sources: NVD CVE API 2.0, CISA KEV catalog, OSV.dev, WordPress.org API (core/plugin latest versions), Wordfence Intelligence / WPScan vulnerability DB (license to confirm, §14), retire.js repository (for JS libs). Synced nightly into a local snapshot; scans never call third-party APIs inline.

*Implemented (M1):* the snapshot is a JSON file written atomically by `corpsec-intel-sync` (packages/intel) rather than database tables, so scan workers need no database credentials (§15). Sources wired up: WordPress.org (latest core), endoflife.date (PHP, nginx, Apache, WordPress, Drupal, Joomla release lines), retire.js, CISA KEV, IANA RDAP bootstrap, and **Wordfence Intelligence v3 production feed** for WordPress core and plugin vulnerabilities (decided in §17 Q1). Wordfence needs an API key from a free Wordfence.com account (`CORPSEC_WORDFENCE_API_KEY`); without it that source is skipped. "Informational" records are not imported; themes are matched by SW-009 (added after M5).

**Attribution (licence requirement, applies to M3 UI and M5 reports):** Wordfence data is licensed by Defiant on condition that every copy includes a hyperlink to the vulnerability record and reproduces Defiant's copyright notice and licence; CVE data additionally requires MITRE's notice to be shown to end users. Each finding's evidence therefore carries `vulnerabilities[].url`, `vulnerabilities[].copyright` and an `attributions` map (notice, licence, licence URL). The results page and PDF must display them next to the finding.

Version matching rule: only report `SW-003/004/005` when a **specific version** was observed. "WordPress detected, version unknown" never produces a vulnerability finding (false-positive control).

### 6.5 Stage 4b — Exposed files (fixed probe list)

Single `GET` per path, body capped at 4 KB, finding raised only when content signature matches (not just HTTP 200 — many sites return 200 for everything).

| ID | Path(s) | Signature | Severity |
|---|---|---|---|
| `EXP-001` | `/.git/HEAD` | starts with `ref: refs/` | critical |
| `EXP-002` | `/.env` | `^[A-Z_]+=` lines, ≥ 2 | critical |
| `EXP-003` | `/wp-config.php.bak`, `/wp-config.php~`, `/wp-config.old` | contains `DB_PASSWORD` | critical |
| `EXP-004` | `/backup.zip`, `/backup.sql`, `/db.sql`, `/site.tar.gz` | magic bytes (PK, SQL keywords, gzip) | critical |
| `EXP-005` | `/phpinfo.php`, `/info.php` | contains `phpinfo()` / `PHP Version` table | high |
| `EXP-006` | `/.DS_Store` | magic `\x00\x00\x00\x01Bud1` | low |
| `EXP-007` | `/server-status` (Apache) | `Apache Server Status` | medium |
| `EXP-008` | `/.svn/entries`, `/.hg/requires` | VCS signatures | high |
| `EXP-009` | `/debug.log`, `/wp-content/debug.log` | PHP log line pattern | medium |

Soft-404 guard: before probing, request a random path (`/corpsec-<random>`). If it returns 200, compare probe bodies against that baseline (similarity > 0.9 → ignore).

### 6.6 Stage 5 — Email & domain

| ID | Check | Severity if failed |
|---|---|---|
| `DNS-001` | Domain registration expires in > 30 days (RDAP) | high (≤ 30 d), critical (≤ 7 d) |
| `DNS-002` | DNSSEC enabled | low |
| `DNS-003` | CAA record restricts certificate issuers | low |
| `DNS-004` | Dangling CNAME on discovered subdomains → unclaimed cloud resource (subdomain takeover candidate: S3, Azure, Heroku, GitHub Pages, … fingerprints) | high |
| `MAIL-001` | MX records exist (if none and no email usage → `info`, skip MAIL checks) | info |
| `MAIL-002` | SPF record exists, single record, syntactically valid, ≤ 10 DNS lookups | high |
| `MAIL-003` | SPF ends with `-all` or `~all` (not `+all`/`?all`) | high (`+all` → critical) |
| `MAIL-004` | DMARC record exists | high |
| `MAIL-005` | DMARC policy `quarantine` or `reject` (not `none`) | medium |
| `MAIL-006` | DKIM key found for common selectors of detected provider (`google`, `selector1/2`, `k1`, `default`, …) | medium (absence is "not found", not "missing" — §8.3) |
| `MAIL-007` | Non-sending domain (no MX) has `v=spf1 -all` and `p=reject` DMARC | medium |
| `MAIL-008` | MTA-STS / TLS-RPT present | info |
| `MAIL-009` | BIMI record (brand logo in inboxes) *(added after MVP)* | info |
| `DNS-005` | Certificate Transparency (crt.sh): sub-addresses listed in public certificate logs; dev/test/staging/old-looking names that still resolve. Feeds `DNS-004`. *(added after MVP)* | low |
| `DNS-006` | Registered look-alike domains (other endings, look-alike letters, typos, `-login`/`-secure` suffixes; wildcard endings skipped; same name servers → "probably yours"). Never affects the grade. *(added after MVP)* | info |
| `REP-001` | Domain/host on the Spamhaus Domain Block List (phishing, malware, botnet → high; spam → medium). Refused answers (`127.255.255.x`) are inconclusive, never "clean". *(added after MVP)* | high/medium |
| `REP-002` | Self-hosted mail server IPs on Spamhaus ZEN (SBL/CSS/XBL/DROP; PBL ignored; hosted providers skipped) *(added after MVP)* | medium |

*Blocklist licensing:* Spamhaus's public mirrors are free only for low-volume, non-commercial use and refuse queries arriving through large public resolvers. A commercial deployment sets `CORPSEC_SPAMHAUS_DQS_KEY` (Data Query Service); the key is never written into evidence.

**Plain-language framing for Stage 5:** "Can someone send fake emails pretending to be you?" → Yes / Partly / No.

### 6.6b Third-party code and open services *(added after MVP)*

| ID | Check | Severity if failed |
|---|---|---|
| `SCR-001` | Scripts/stylesheets from public CDNs (cdnjs, jsDelivr, unpkg, code.jquery.com, …) without Subresource Integrity. Dynamic third parties (analytics, chat) are listed but not flagged: they can't be pinned. | low |
| `SCR-002` | Scripts from code hosts known to have been taken over (polyfill.io and the same operator's bootcss/bootcdn/staticfile, 2024) | high |
| `PORT-001` | Risky services open to the internet (databases, RDP, SMB, VNC, Telnet, Docker, …) read from Shodan InternetDB — CorpSEC never probes ports itself. Off unless `CORPSEC_INTERNETDB_ENABLED=true` (confirm the data's terms for your offering). Confidence "likely": the data can be days old. | high (Docker → critical, FTP → medium) |

### 6.7 Check versioning

- Each check has `id` + `version` (semver). Findings store both.
- Changing detection logic → bump minor; changing severity → bump major and note in changelog.
- Grade history shows a marker when the catalog version changed between scans ("we added new checks").

---

## 7. Functional requirements

### 7.1 Input normalization

- Accept: `example.com`, `https://www.example.com/path?x=1`, `EXAMPLE.COM`, IDN (`bakı.az` → punycode).
- Extract registrable domain using the Public Suffix List; scan target = registrable domain + the exact host entered.
- Reject: IP literals, localhost, `.local`, `.internal`, reserved TLDs, anything resolving only to non-public IPs. Error copy: "CorpSEC can only check public websites."

### 7.2 Scan lifecycle

States: `queued → running → completed | partial | failed`.

- `partial` when some stages time out; grade still computed, with banner "Some checks couldn't finish."
- Live progress via Server-Sent Events: stage started/finished, findings count.
- Scan record is immutable once completed; re-checks create a new `check_run` linked to the scan.

### 7.3 Results page

- Grade card: letter, colour, one-sentence verdict, scan date, "What does this grade mean?" popover.
- "Fix these first": top 3 by priority (§9.3).
- Groups: Fix now / Important / Should fix / Good to fix / Good to know / Passed (collapsed).
- Finding card (collapsed): icon, title, one-line "why it matters".
- Finding card (expanded): **What is it / Why it matters / How to fix (for your platform) / Technical details (toggle) / I fixed it — check again / Not relevant (dismiss with reason)**.
- Language: English at launch; all user-facing text in i18n catalogs (Azerbaijani, Russian, Turkish planned).

### 7.4 Dashboard (signed-in)

- List of sites with current grade, trend arrow, last scan, verification status.
- Site page: grade history chart (last 12 scans), open findings, fixed findings timeline.
- Agency view (Murad): ≥ 2 sites → table sorted by worst grade.

### 7.5 Reports

- *Implemented (M5):* the PDF is a print-optimised page (`/scan/{id}/print`) saved with the browser's "Save as PDF", so the server needs no headless browser; "Send to my IT person" emails a read-only share link valid for 30 days (scans of monitored sites) or the public link (anonymous scans).
- **PDF report** (signed-in, verified sites): cover with grade, executive summary in plain language, then technical appendix (evidence, references, check IDs) for the user's IT person.
- **"Send to my IT person"**: emails the technical report (or share link) to an address the user types. The user clicks Send; CorpSEC never auto-sends to third parties.
- **JSON export** of findings (schema in `schemas/finding.schema.json`).

### 7.6 Dismissals

- User can mark a finding "Not relevant" with a reason (`accepted_risk`, `false_positive`, `not_applicable`). Dismissed findings don't affect the grade except `critical` ones, which cap the grade regardless and can only be dismissed as `false_positive` (logged, reviewed for check quality).

---

## 8. Finding model & explanation layer

### 8.1 Finding object

See `schemas/finding.schema.json`. Key fields:

```json
{
  "id": "fnd_01J…",
  "check_id": "MAIL-004",
  "check_version": "1.0.0",
  "scan_id": "scn_01J…",
  "site_id": "site_01J…",
  "host": "example.com",
  "severity": "high",
  "confidence": "confirmed",
  "status": "open",
  "evidence": {
    "kind": "dns",
    "query": "_dmarc.example.com TXT",
    "observed": "NXDOMAIN",
    "captured_at": "2026-10-29T10:12:03Z"
  },
  "context": { "email_provider": "google_workspace" },
  "references": ["https://www.rfc-editor.org/rfc/rfc7489"],
  "first_seen": "2026-10-29T10:12:03Z",
  "last_seen": "2026-10-29T10:12:03Z"
}
```

Findings are de-duplicated across scans by `(site_id, check_id, host, dedupe_key)`, so history shows when a problem appeared and when it was fixed.

### 8.2 Explanation templates (Burp-style issue definitions, rewritten for non-experts)

Each check ships a template file `packages/checks/src/corpsec_checks/explain/<lang>/<ID>.yaml` (one folder per language, so translators work in one place). *Implemented (M2):* besides the fields below, templates have `pass_title` (shown in the Passed list), `effort_minutes` (number, used by the fix-first priority) and `variables` (placeholders beyond the global `domain`, `host`, `item`, `*_name`). Placeholders support fallbacks: `{{days_left|a few}}`. Fix variants are chosen by email provider, website platform, DNS provider (detected from NS records), then `hosted` for Shopify/Wix/Squarespace/Webflow, then `default`:

```yaml
title: "Anyone can send emails pretending to be you"
summary: "Your domain has no DMARC record, so email providers can't tell real emails from fakes."
analogy: "It's like a company letterhead anyone can print."
why_it_matters:
  - "Scammers can email your customers from an address that looks exactly like yours."
  - "Your real emails are more likely to land in spam."
fix:
  default:
    - "Log in to where your domain's DNS is managed."
    - "Add a TXT record with name `_dmarc` and value `v=DMARC1; p=none; rua=mailto:{{report_email}}`."
    - "After 2–4 weeks with no problems, change `p=none` to `p=quarantine`."
  google_workspace:
    - "…"
  cloudflare_dns:
    - "…"
effort: "15 minutes"
who_can_fix: "Whoever manages your domain (often your web designer or IT provider)."
technical: "No DMARC TXT record at _dmarc.{{domain}} (RFC 7489)."
```

Rules:

- Reading level target: **Flesch-Kincaid grade ≤ 8** for `title`, `summary`, `why_it_matters`, `fix`. Enforced by a CI lint.
- No jargon in non-technical fields without an inline explanation. CI lint has a jargon denylist (`CVE`, `CVSS`, `XSS`, `header`, `cipher`, …) for those fields.
- Fix guides per platform; fallback to `default`.
- **Optional AI rewrite (off by default in MVP, feature-flagged)**: an LLM may rephrase the template for the user's chosen language/level. It receives only the template + evidence, must not add findings or severity, and output is validated (same check_id, same steps count ±1, no new URLs). Template text is always the source of truth.

### 8.3 False-positive policy

- A finding requires captured evidence. No evidence → no finding.
- `confidence`: `confirmed` (direct observation, e.g. `.git/HEAD` content) / `likely` (version-based CVE match) / `possible` (heuristic). `possible` findings are shown only under "Good to know" and never affect the grade.
- Absence checks that can't be proven (e.g. DKIM selectors are not enumerable) are phrased as "We couldn't find …" and capped at `medium`.

---

## 9. Grading model

Inspired by SSL Labs: start from a score, subtract per finding, then apply caps.

### 9.1 Score

```
score = 100
for each open, non-dismissed finding with confidence in {confirmed, likely}:
    score -= weight[severity]
weight = { critical: 40, high: 15, medium: 6, low: 2, info: 0 }
score = max(score, 0)
```

Diminishing returns: within one category, the 3rd+ finding of the same severity counts half.

### 9.2 Letter & caps

| Score | Letter |
|---|---|
| ≥ 90 | A |
| 80–89 | B |
| 65–79 | C |
| 50–64 | D |
| < 50 | F |

Caps (applied after score):

- Any `critical` → max **F**.
- Any `high` → max **C**.
- `TLS-001` failed (no valid HTTPS) → **F** regardless.
- `A+`: score ≥ 95, no findings above `low`, HSTS + CSP + DMARC `reject` present.

Sub-grades per stage (Connection, Encryption, Website, Software, Email) using the same formula, shown as small badges.

### 9.3 "Fix these first" priority

```
priority = weight[severity] × confidence_factor × (1 / effort_minutes^0.3) × kev_boost
confidence_factor = { confirmed: 1.0, likely: 0.8 }
kev_boost = 2 if CVE in CISA KEV else 1
```

Top 3 open findings by priority. Ties → fewer steps first.

---

## 10. Safety, abuse & legal

### 10.1 Principles

1. MVP never sends attack payloads (§5).
2. Anything that reveals sensitive information is shown only to verified owners.
3. CorpSEC is identifiable and contactable by site operators.

### 10.2 Evidence redaction

| Viewer | Sees |
|---|---|
| Anonymous / unverified | Finding title, severity, generic fix. Exposed-file findings show "A sensitive file is publicly accessible" without path or contents. |
| Verified owner | Full evidence; secrets in evidence (e.g. `.env` values) are masked except first/last 2 chars — CorpSEC never stores full secrets. |

### 10.3 Rate limits & abuse

| Actor | Limit |
|---|---|
| Anonymous (per IP) | 5 scans / hour, 20 / day |
| Free account | 3 sites, 10 on-demand scans / day |
| Same target domain (global) | 1 full scan / 10 min across all users; cached result served within that window |
| Opt-out | Domains on the opt-out list (requested via bot page, verified by DNS TXT) are never scanned |

- Bot page `https://corpsec.app/bot` documents scanner IPs, UA, what is requested, and opt-out.
- Scan egress from fixed, published IP ranges.
- Blocklist of sensitive TLDs/sectors (e.g. `.gov`, `.mil`) for anonymous scans; allowed for verified owners.
- Audit log: who scanned what, when, from which IP; retained 1 year.

### 10.4 Legal

- Terms of Service: user may only add sites they own or are authorized to assess; monitoring requires verification.
- Privacy policy: GDPR-aligned. Store minimal personal data (email, sites). Scan data retention: anonymous 7 d, accounts until deletion.
- Engine licensing: see §14.

---

## 11. Architecture

```
            ┌───────────────────────────┐
 Browser ──▶│ Web (Next.js, SSR + SSE)  │
            └────────────┬──────────────┘
                         │ REST/JSON
            ┌────────────▼──────────────┐       ┌─────────────┐
            │ API (FastAPI, Python 3.12)│──────▶│ PostgreSQL  │
            │ auth, sites, scans, grade │       └─────────────┘
            └────────────┬──────────────┘
                         │ enqueue
            ┌────────────▼──────────────┐       ┌─────────────┐
            │ Queue (Redis + arq)       │◀─────▶│ Scheduler   │ weekly/daily jobs
            └────────────┬──────────────┘       └─────────────┘
                         │
     ┌───────────────────▼────────────────────┐
     │ Scan workers (Python, asyncio, httpx)  │  sandboxed containers, egress-only,
     │  stage runners → check plugins         │  fixed egress IPs, SSRF guard
     └───────────────────┬────────────────────┘
                         │ normalized findings
            ┌────────────▼──────────────┐
            │ Grader + Explainer        │ templates (+ optional LLM, flagged)
            └───────────────────────────┘

 Intel sync (nightly): NVD, CISA KEV, OSV, WordPress.org, retire.js, PSL → Postgres
```

### 11.1 Check plugin interface

```python
class Check(Protocol):
    id: str                 # "MAIL-004"
    version: str            # "1.0.0"
    stage: Stage            # Stage.EMAIL
    requires: set[str]      # facts needed, e.g. {"dns.mx"}
    provides: set[str]      # facts produced, e.g. {"mail.dmarc"}

    async def run(self, ctx: ScanContext) -> list[Observation]: ...
```

- `ScanContext` exposes a rate-limited, SSRF-guarded HTTP client, a DNS resolver, shared facts (fingerprints, crawled pages), and the time budget.
- Checks are pure with respect to the outside world except via `ctx`. This makes them unit-testable with recorded fixtures (VCR-style cassettes).
- A dependency resolver orders checks by `requires/provides`; independent checks run concurrently.
- `Observation` → `Finding` conversion (severity, dedupe key, evidence) happens in the framework, not in checks.

### 11.2 Tech choices

| Area | Choice | Why |
|---|---|---|
| Backend & workers | Python 3.12, FastAPI, httpx, dnspython, cryptography | Best ecosystem for network/security checks; one language for API + checks |
| TLS probing | Python `ssl` + custom ClientHello probes for legacy protocols/ciphers; `sslyze` evaluated (AGPL, see §14) | Avoid shipping copyleft engines by default |
| Queue | Redis + arq | Simple async jobs, retries, cron |
| DB | PostgreSQL 16 | JSONB for evidence, solid migrations (Alembic) |
| Frontend | Next.js (App Router), TypeScript, Tailwind | SSR for fast first result, SEO for landing |
| Auth | Magic link + OAuth (Google, Microsoft) | No passwords for non-technical users |
| Email | Transactional provider (Postmark/Resend) | Alerts, magic links |
| PDF | Server-side HTML → PDF (Playwright/Chromium) | Reuse result page components |
| Deploy | Docker Compose for dev; containers on a single cloud region for MVP | Keep ops minimal |
| Observability | OpenTelemetry → logs/metrics; Sentry for errors | |

### 11.3 Repository layout

```
CorpSEC/
├── apps/
│   ├── web/                 # Next.js frontend
│   └── api/                 # FastAPI app
├── packages/
│   ├── scanner/             # scan engine, ScanContext, stages
│   ├── checks/              # one module per check, grouped by area (connection/, tls/, …)
│   ├── grader/              # scoring & caps
│   └── intel/               # vuln-data sync (writes the intel snapshot)
├── schemas/                 # JSON Schemas (finding, scan, check manifest)
├── docs/                    # specs, ADRs
├── deploy/                  # docker-compose, IaC
└── .github/workflows/       # CI: lint, tests, template readability lint
```

---

## 12. Data model (MVP)

```
users(id, email, created_at, locale, deleted_at)
sites(id, owner_id → users, domain, platform, email_provider,
      verification_method, verification_token, verified_at, monitoring_enabled)
scans(id, site_id → sites NULL for anonymous, target, status, catalog_version,
      started_at, finished_at, score, grade, stage_grades JSONB, requested_by_ip)
findings(id, site_id, scan_id, check_id, check_version, host, dedupe_key,
         severity, confidence, status, evidence JSONB, first_seen, last_seen,
         fixed_at, dismissed_reason)
check_runs(id, finding_id, scan_id, result, ran_at)          -- "check again"
alerts(id, site_id, kind, payload JSONB, sent_at)
audit_log(id, actor_user_id, actor_ip, action, target, at)
intel_cves(cve_id, cpe/purl, affected_ranges, cvss, kev, published_at)
intel_products(product, latest_version, eol_date, source)
optouts(domain, verified_at)
```

## 13. API (MVP)

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/scans` | `{target}` → `{scan_id}`; anonymous or authed |
| `GET` | `/v1/scans/{id}` | status, grade, findings (redacted per §10.2) |
| `GET` | `/v1/scans/{id}/events` | SSE progress |
| `POST` | `/v1/findings/{id}/recheck` | re-run single check |
| `POST` | `/v1/findings/{id}/dismiss` | `{reason}` |
| `POST` | `/v1/sites` | add site |
| `GET` | `/v1/sites` / `/v1/sites/{id}` | dashboard data, history |
| `POST` | `/v1/sites/{id}/verify` | trigger verification check |
| `PATCH` | `/v1/sites/{id}` | platform, monitoring on/off |
| `GET` | `/v1/sites/{id}/report.pdf` | verified only |
| `POST` | `/v1/sites/{id}/share` | send report to an email the user entered |
| `POST` | `/v1/auth/magic-link` / `GET /v1/auth/callback` | auth |

All responses JSON; errors use RFC 9457 problem details with a user-friendly `title`.

---

## 14. Third-party engines, data & licensing

| Component | License | MVP decision |
|---|---|---|
| OWASP ZAP | Apache-2.0 | Not embedded in MVP (passive checks implemented natively). Candidate for v2 active web scanning. |
| Nuclei (+ templates) | MIT | Candidate for v2 safe active checks; template licensing to review. |
| Nmap | NPSL (restricts commercial redistribution) | Not used. v3 desktop agent needs an OEM license or MIT alternatives (naabu). |
| OpenVAS / Greenbone feed | GPL / feed terms | Not used; feed terms restrict commercial use — revisit only with a commercial agreement. |
| sslyze | AGPL-3.0 | Evaluate; only if CorpSEC itself is AGPL or used as a separate service with legal review. |
| testssl.sh | GPL-2.0 | Possible as an isolated subprocess tool; legal review. |
| NVD, CISA KEV, OSV | Public / CC | Use. |
| WordPress.org API | Public | Use for latest versions. |
| Wordfence Intelligence (v3 feed) | Free for personal and commercial use; [WTI Community Edition terms](https://www.wordfence.com/wti-community-edition-terms-and-conditions/) — link to each record + Defiant notice/licence; MITRE notice for CVEs | **Used** (needs API key). |
| WPScan DB | Commercial API is paid | Not used. |
| retire.js repo | Apache-2.0 | Use. |
| Public Suffix List | MPL-2.0 | Use. |

Commercial tools (Burp Suite, Qualys, Acunetix/Invicti) are used **only as product inspiration from public documentation and observed public behaviour** (e.g. SSL Labs grading criteria). Their EULAs generally prohibit reverse engineering; CorpSEC does not decompile or copy them.

---

## 15. Non-functional requirements

| Area | Requirement |
|---|---|
| Speed | p50 full scan ≤ 45 s, p95 ≤ 120 s; first progress event ≤ 2 s |
| Availability | 99.5 % monthly for web/API (MVP) |
| Scale (MVP) | 2,000 scans/day, 500 monitored sites |
| Security of CorpSEC itself | OWASP ASVS L2 target; workers have no DB credentials (results via API/queue); secrets in a vault; dependency scanning in CI; CorpSEC scans itself weekly (dogfooding, must be A+). *Implemented:* the web app sends a per-request nonce CSP (`script-src 'nonce-…' 'strict-dynamic'`, no `unsafe-inline` for scripts or style elements) from `apps/web/src/proxy.ts`; pages render per request so every script carries the nonce |
| Accessibility | WCAG 2.2 AA; grade never conveyed by colour alone |
| Privacy | GDPR: export & delete account; no third-party trackers on result pages. *Implemented:* `GET /v1/me/export` (JSON download of account, sites, scans, findings, alerts, share links and the person's activity log) and `DELETE /v1/me` (typed email confirmation; removes the account, its sites and their scans so old report links stop working) on the Account page |
| i18n | All strings externalized; RTL-safe layout |
| Testability | Every check has ≥ 1 positive and ≥ 1 negative fixture test; CI runs the whole catalog against a local "vulnerable lab" (docker-compose of intentionally misconfigured nginx/WordPress/DNS) |

---

## 16. MVP milestones

| # | Milestone | Contents | Exit criteria |
|---|---|---|---|
| M0 | Foundations (1 wk) | Monorepo, CI, docker-compose, DB migrations, check plugin framework, SSRF-guarded client | Framework runs a dummy check end-to-end with tests |
| M1 | Checks (2–3 wk) | Stages 1–5 catalog (§6), soft-404 guard, intel sync, vulnerable lab | All checks pass fixture tests; lab scan yields expected findings, clean site yields none |
| M2 | Grade & explain (1 wk) | Grader, templates for all checks (EN), readability/jargon lint | Template lint green; grading unit tests incl. caps |
| M3 | Web app (2 wk) | Landing, live scan, results page, finding cards, re-check | 5 non-technical testers complete scan + understand top fix without help (§18) |
| M4 | Accounts & monitoring (1–2 wk) | Auth, sites, verification wizard, scheduler, alerts, dashboard | Verified site gets weekly scan + alert on simulated regression |
| M5 | Reports & hardening (1 wk) | PDF, share, rate limits, audit log, bot page, opt-out, ToS/privacy | Abuse tests pass (§10.3); CorpSEC scores A+ on itself |
| — | **MVP launch** | | §18 metrics instrumented |

## 17. Open questions

1. ~~WordPress plugin vulnerability data source~~ — **decided 2026-10-29: Wordfence Intelligence** (free, attribution required, see §6.4).
2. Project license: proprietary SaaS, open-core, or AGPL (which would allow sslyze)?
3. Pricing for v1 paid tier (agency multi-site, PDF white-label)?
4. Hosting region (EU for GDPR simplicity?).
5. Launch languages beyond English.

## 18. Success metrics (first 90 days after launch)

- **Comprehension**: ≥ 80 % of usability testers correctly state their top problem and next step after reading the result page.
- **Action**: ≥ 30 % of signed-up users mark ≥ 1 finding fixed (verified by re-check) within 14 days.
- **Activation**: ≥ 25 % of anonymous scanners create an account.
- **Trust**: false-positive reports < 2 % of shown findings.
- **Safety**: zero valid abuse complaints about scan traffic.

## 19. Beyond MVP (for context only)

- **v2**: Safe active web checks for verified owners (ZAP/Nuclei, gentle policy), authenticated scan of login pages, Slack/Teams alerts.
- **v3**: Desktop agent (Tauri) for home/office network: device discovery on the local subnet only, risky ports, router firmware age; account breach check (HIBP k-anonymity).
- **v4**: Agency plan, white-label reports, compliance mappings (ISO 27001 Annex A, Cyber Essentials, NIS2 basics).
