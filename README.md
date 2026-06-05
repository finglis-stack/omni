# OmniScan v4.0 (Stealth)

*Made by Félix Inglis-Chevarie, Marie-Anne High School*

OmniScan is an **Advanced Web Vulnerability Scanner and Auto-Exploitation Framework**, engineered for maximum stealth, speed, and offensive capabilities.

Built with an asynchronous core, a dynamic plugin architecture, and a centralized **Stealth Session Engine** (TLS fingerprint spoofing, browser impersonation, timing jitter, proxy chains), OmniScan goes beyond passive scanning. It actively discovers vulnerabilities, attempts exploitation, and automatically generates concrete Proof of Concept (PoC) files — all while appearing as normal browser traffic to WAFs and IDS.

---

## ⚡ Key Features

- **Stealth Session Engine**: Centralized HTTP engine that intercepts ALL requests across every module. Features:
  - **JA3/TLS Fingerprint Spoofing** via `curl_cffi` — impersonates Chrome, Firefox, Safari, or Edge at the TLS handshake level
  - **Browser Fingerprint Rotation** — realistic User-Agent + full header profiles (Sec-CH-UA, Sec-Fetch-*, Accept-Language, etc.) rotated every N requests
  - **Gaussian Timing Jitter** — 4 profiles (`none`, `light`, `normal`, `paranoid`) with human-like delays and random long pauses
  - **Proxy Chain / Tor Support** — single proxy, proxy list rotation, SOCKS5 (Tor-compatible)
  - **Session Persistence** — shared TCP pool, cookie persistence, dynamic Referer
- **Asynchronous Crawling Engine**: Built on `asyncio` and `aiohttp` with exponential backoff retry logic
- **Dynamic Plugin Architecture**: Drop-in module support — new exploits in `modules/` are auto-discovered and executed
- **Advanced WAF Evasion**: 7 obfuscation techniques — URL encode, double encode, unicode, case switching, SQL comment insertion, null bytes, hex encoding. Auto-calibrates against detected WAF
- **Deep WordPress Analysis**: User enumeration, XML-RPC, Elementor DOM XSS, known CVE exploitation
- **Autonomous Weaponization**: Chains vulnerabilities (LFI → RCE via Log Poisoning, XSS → Cookie Theft → Admin Takeover)
- **PoC Generation**: Jinja2-templated HTML pages proving Clickjacking, CORS misconfigurations, and XSS

---

## 🏗️ Project Structure

```text
OmniScan/
├── omniscan.py             # Main entry point — CLI, dynamic loader, session injection
├── requirements.txt        # Project dependencies
├── README.md               # This documentation
├── core/
│   ├── stealth_session.py  # ★ Centralized stealth engine (JA3, UA rotation, timing, proxies)
│   ├── crawler.py          # Asynchronous web crawler & endpoint discoverer
│   ├── reporter.py         # Automated scan report generator
│   ├── waf_evasion.py      # WAF detection + 7 payload obfuscation techniques
│   └── smart_fuzzer.py     # Context-aware XSS fuzzing logic
├── modules/                # Dynamically loaded attack & recon plugins (all use StealthSession)
│   ├── recon.py            # Security headers & sensitive file fuzzing
│   ├── sqli.py             # SQL Injection detection (WAF evasion enabled)
│   ├── xss.py              # Cross-Site Scripting detection (WAF evasion enabled)
│   ├── lfi.py              # Local File Inclusion
│   ├── cors_misconfig.py   # CORS misconfiguration testing
│   ├── open_redirect.py    # Open Redirect detection
│   ├── header_audit.py     # HTTP security headers audit
│   ├── info_disclosure.py  # Sensitive file & information leakage
│   ├── dns_recon.py        # DNS records, SPF/DMARC, zone transfers, crt.sh OSINT
│   ├── wp_scanner.py       # WordPress core fingerprinting
│   ├── wp_enum.py          # WP users, plugins, themes enumeration
│   ├── xmlrpc_exploit.py   # XML-RPC method enumeration & SSRF
│   ├── iis_exploit.py      # IIS CVEs, shortname, WebDAV, HTTP methods
│   ├── elementor_exploit.py # Elementor plugin CVEs & DOM XSS
│   ├── wp_cve_exploit.py   # WordPress CVE active exploitation
│   └── auto_exploit.py     # Autonomous weaponization & PoC generation
├── templates/              # Jinja2 HTML templates for PoC generation
│   ├── cors_exploit_poc.html
│   ├── xss_elementor_poc.html
│   ├── clickjacking_poc.html
│   └── attack_chain_full.html
├── proofs/                 # (Generated) PoCs, stolen credentials, data dumps
└── reports/                # (Generated) Final scan reports (HTML + JSON)
```

---

## ⚙️ Installation

OmniScan requires **Python 3.8+**.

1. Clone the repository:
   ```bash
   git clone https://github.com/finglis-stack/omni.git
   cd omni
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   *(Core: `curl_cffi`, `aiohttp`, `requests`, `beautifulsoup4`, `colorama`, `jinja2`, `dnspython`, `PySocks`)*

---

## 🚀 Usage

### Basic Scan
```bash
python omniscan.py -u http://target.com/ -t 10
```

### Stealth Mode (recommended for hardened targets)
```bash
python omniscan.py -u https://target.com/ -t 5 --stealth normal --impersonate chrome
```

### Full Stealth with Tor
```bash
python omniscan.py -u https://target.com/ -t 3 --stealth paranoid --impersonate chrome --proxy socks5://127.0.0.1:9050
```

### Proxy Rotation
```bash
python omniscan.py -u https://target.com/ --stealth normal --proxy-file proxies.txt --rotate-ua 15
```

### CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u` / `--url` | Target URL (required) | — |
| `-t` / `--threads` | Concurrent threads | `5` |
| `--stealth` | Timing profile: `none`, `light`, `normal`, `paranoid` | `light` |
| `--proxy` | Proxy URL (`http://`, `socks5://`) | None |
| `--proxy-file` | File with proxy list for rotation | None |
| `--rotate-ua` | Rotate browser profile every N requests | `25` |
| `--impersonate` | TLS fingerprint: `chrome`, `firefox`, `safari`, `edge` | Random |

### Scan Phases
1. **WAF Detection** — Identifies Cloudflare, AWS WAF, Sucuri, Wordfence, ModSecurity, Imperva
2. **Passive Recon** — DNS, security headers, information disclosure
3. **Async Crawling** — High-speed endpoint & form discovery
4. **Active Scanning** — SQLi, XSS, LFI, Open Redirects, CORS
5. **WordPress Deep Scan** — Users, plugins, themes, XML-RPC
6. **Active Exploitation** — IIS CVEs, Elementor CVEs, WP CVEs
7. **Auto-Exploitation** — Autonomous attack chaining & PoC generation
8. **Reporting** — HTML + JSON reports in `reports/`

---

## ⚠️ Disclaimer

**Educational and Authorized Use Only.**
OmniScan is an offensive security tool designed for penetration testers and security researchers. You are strictly prohibited from using this tool against infrastructure you do not own or do not have explicit, written authorization to test. The developers hold no liability for misuse.
