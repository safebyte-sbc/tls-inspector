# TLS Inspector

A modern, on-demand TLS security scanner for [Burp Suite](https://portswigger.net/burp), built on the Montoya API.

TLS Inspector replaces the unmaintained **SSL Scanner** BApp (last updated 2021, Jython, no TLS 1.3 support) with a ground-up rewrite in Kotlin. It bundles **28 probes** covering historical and modern TLS attacks, full X.509 certificate inspection, four compliance baselines, and post-quantum readiness detection — all wired into Burp's native Issue Tracker.

> **Status:** initial public release. Tested against the Mozilla SSL test suite, [badssl.com](https://badssl.com), and a custom OpenSSL 1.0.1f / 1.0.2u Docker stack covering Heartbleed, POODLE, FREAK, Sweet32, ROBOT, Logjam, DROWN, and CCS Injection.

---

## Features

### Vulnerability probes (17)

| Era       | Probe |
|-----------|-------|
| Vintage   | Heartbleed (CVE-2014-0160), POODLE on SSLv3 (CVE-2014-3566), FREAK (CVE-2015-0204), Sweet32 (CVE-2016-2183), DROWN (CVE-2016-0800), BEAST (CVE-2011-3389), Lucky13 (CVE-2013-0169), CRIME (CVE-2012-4929), CCS Injection (CVE-2014-0224), Logjam Export (CVE-2015-4000), Logjam Common Prime |
| Modern    | ROBOT (CVE-2017-13099) — distinguishes WEAK vs STRONG oracles, Raccoon DHE Key Reuse (CVE-2020-1968), ALPACA Cross-Protocol Confusion (CVE-2021-3618), TLS 1.3 0-RTT Replay Risk, TLS 1.3 HRR Binding Regression |
| Defense   | TLS_FALLBACK_SCSV honoured |

### Infrastructure & PKI checks (11)

- **Protocol enumeration** — SSLv2 / SSLv3 / TLS 1.0–1.3 (raw `ClientHello` for legacy versions, since BCTLS silently disables them)
- **Cipher suite enumeration** — every protocol, with grade (`SECURE` / `WEAK` / `INSECURE`)
- **Certificate validation** — full X.509 parse, hostname matching (RFC 6125), 19+ anomaly checks (expired, self-signed, weak keys, CA:TRUE on leaf, SHA-1 signature, broad wildcards, missing SANs, pre-certificate detection, negative serial, etc.)
- **OCSP / CRL revocation** — full chain
- **OCSP stapling** — RFC 6066 status_request extension
- **CT log discovery** — queries crt.sh, injects discovered subdomains into Burp's Site Map
- **CAA DNS** — RFC 8659 with parent-zone tree-walk
- **HSTS preload** — header parse + Chromium preload list lookup
- **Post-Quantum hybrid KEM** — X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024
- **Compliance profile evaluator** — runs the active baseline and reports each violation

### Compliance baselines (4)

- **Mozilla SSL Configuration** — Old / Intermediate / Modern
- **PCI DSS 4.0** §4.2.1
- **NIST SP 800-52r2**
- **ENISA + ETSI TS 119 312** (EU banking baseline)
- **ALL** — runs every baseline and reports separately

---

## Install

### Pre-built JAR

1. Download the latest `tls-inspector-<version>.jar` from the [Releases page](../../releases).
2. In Burp: **Extensions → Add → Extension type: Java → Select file** → pick the JAR.
3. A new top-level **TLS Inspector** tab appears.

### Build from source

```bash
git clone https://github.com/safebyte-sbc/tls-inspector.git
cd tls-inspector
./gradlew shadowJar
# Output: build/libs/tls-inspector-1.0.0.jar
```

Requires JDK 17+ (Burp 2024+ ships with JRE 21).

---

## Usage

### Tab mode

1. Click the **TLS Inspector** tab.
2. Enter host and port (e.g. `example.com` : `443`).
3. Pick a **Speed** (`FAST` / `NORMAL` / `THOROUGH`) and **Compliance** baseline.
4. Click **Run Scan**.
5. Probe verdicts appear live in the results panel; vulnerability findings are also pushed into **Target → Issues** with full HTML descriptions, references, and CWE/CVE links.

### Context menu

Right-click any HTTPS request anywhere in Burp (Proxy, Repeater, Site Map…) and pick **Send to TLS Inspector**. The current host:port is pre-filled in the input row.

### Save report

The **Save HTML** button (enabled after a scan completes) writes the rendered results panel to a standalone HTML file — handy for sharing or attaching to engagement notes.

---

## Design notes

- **Burp-native integration.** Findings reach the Issue Tracker through `siteMap().add(auditIssue)`. CT-discovered subdomains are added to the Site Map. Nothing leaves Burp.
- **HTML whitelist.** Issue descriptions go through a whitelist sanitiser (`p, b, i, em, strong, code, pre, ul, ol, li, br, a[href]`) — nothing else, no inline `<style>`, no `<script>`, no `<table>`.
- **BCTLS hard limits.** BouncyCastle 1.79 silently refuses to compose SSLv2/SSLv3 client hellos. TLS Inspector ships its own `ClientHelloBuilder` + raw-socket post-handshake probing path so legacy protocols can be detected without depending on BCTLS.
- **External queries are opt-out.** OCSP, CRL, CT (crt.sh), and CAA DNS lookups can be disabled from the input row for air-gapped engagements.
- **Threading.** All long-running work runs on a dedicated worker pool. The extension installs an unloading handler that cancels in-flight scans and shuts the pool down — Burp can be reloaded cleanly without leaking threads.

---

## Why a new extension and not an SSL Scanner update?

[SSL Scanner](https://github.com/PortSwigger/ssl-scanner) (2021) was written in Jython 2.7 against the legacy Burp API. Adding TLS 1.3, modern attacks, certificate inspection, compliance evaluation, and Montoya-API integration would have meant rewriting essentially every file. TLS Inspector is the result of that rewrite — same problem domain, fully modern code, and nearly twice the probe coverage.

---

## License

GPL v3 — see [LICENSE](LICENSE).

Copyright © 2026 Safebyte Consulting S.R.L.
