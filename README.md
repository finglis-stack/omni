# OmniScan v3.0

*Made by Félix Inglis-Chevarie, Marie-Anne High School*

OmniScan is an **Advanced Web Vulnerability Scanner and Auto-Exploitation Framework**, heavily optimized for speed, modularity, and offensive capabilities. 

Built with an asynchronous core and a dynamic plugin architecture, OmniScan goes beyond passive scanning. It actively discovers vulnerabilities, attempts exploitation, and automatically generates concrete Proof of Concept (PoC) HTML pages and data dumps to validate the impact of its findings.

---

## ⚡ Key Features

- **Asynchronous Crawling Engine**: Built on `asyncio` and `aiohttp`, the crawler maps out target applications at breakneck speeds while automatically evading basic WAF rate limits via exponential backoff.
- **Dynamic Plugin Architecture**: Drop-in modules support. New exploits and scanners placed in the `modules/` directory are automatically discovered and executed by the `ThreadPoolExecutor`.
- **WAF Evasion**: Integrates payload obfuscation to bypass common Web Application Firewalls during active injection testing.
- **Deep WordPress Analysis**: Specialized modules for enumerating users, analyzing XML-RPC, testing Elementor DOM XSS, and exploiting known WordPress Core/Plugin CVEs.
- **Autonomous Weaponization**: Automatically chains vulnerabilities (e.g., LFI to RCE via Log Poisoning, or XSS to Cookie Theft to Admin Takeover).
- **PoC Generation**: Uses `Jinja2` templating to cleanly generate attacker-ready HTML pages proving Clickjacking, CORS misconfigurations, and XSS vulnerabilities.

---

## 🏗️ Project Structure

```text
OmniScan/
├── omniscan.py             # Main entry point and dynamic module orchestrator
├── requirements.txt        # Project dependencies
├── README.md               # This documentation
├── core/
│   ├── crawler.py          # Asynchronous web crawler & endpoint discoverer
│   ├── reporter.py         # Automated scan report generator
│   ├── waf_evasion.py      # WAF detection and payload obfuscation engine
│   └── smart_fuzzer.py     # Intelligent fuzzing logic
├── modules/                # Dynamically loaded attack & recon plugins
│   ├── recon.py            # Security headers & sensitive file fuzzing
│   ├── sqli.py             # SQL Injection detection
│   ├── xss.py              # Cross-Site Scripting detection
│   ├── auto_exploit.py     # Weaponization & PoC generation engine
│   └── ...                 # 10+ other specialized modules (LFI, SSRF, IIS, etc.)
├── templates/              # Jinja2 HTML templates for PoC generation
│   ├── cors_exploit_poc.html
│   ├── clickjacking_poc.html
│   └── attack_chain_full.html
├── proofs/                 # (Generated) Stored PoCs, stolen credentials, and data dumps
└── reports/                # (Generated) Final scan reports
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
   *(Main dependencies: `aiohttp`, `requests`, `beautifulsoup4`, `colorama`, `tqdm`, `jinja2`, `dnspython`)*

---

## 🚀 Usage

Run the scanner by providing a target URL. You can also specify the number of concurrent threads to use for active scanning (the async crawler will scale automatically based on this limit).

```bash
python omniscan.py -u http://target-website.com/ -t 10
```

### Scan Phases:
1. **Passive Reconnaissance**: WAF detection, DNS recon, security headers audit.
2. **Async Crawling**: Highly concurrent crawling to map out endpoints, forms, and JavaScript files.
3. **Active Vulnerability Scanning**: SQLi, XSS, LFI, Open Redirects, CORS testing.
4. **WordPress Deep Scan**: Version fingerprinting, CVE exploitation, User Enumeration.
5. **Active Exploitation**: IIS shortname exploits, Elementor CVEs, etc.
6. **Auto-Exploitation (Weaponization)**: Generates HTML PoCs in the `proofs/` directory for confirmed vulnerabilities.
7. **Reporting**: Generates a consolidated summary and a detailed report in `reports/`.

---

## ⚠️ Disclaimer

**Educational and Authorized Use Only.**
OmniScan is an offensive security tool designed for penetration testers and security researchers. You are strictly prohibited from using this tool against infrastructure you do not own or do not have explicit, written authorization to test. The developers hold no liability for misuse.
