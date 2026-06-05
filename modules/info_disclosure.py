import requests
import re
from colorama import Fore, Style
from urllib.parse import urljoin

# Known CVEs per version range (subset — most critical RCE/Auth Bypass)
VERSION_CVES = {
    "php": {
        "7.2": [
            "CVE-2019-11043 (PHP-FPM RCE — critical if nginx + PHP-FPM)",
            "CVE-2019-11041 (Heap buffer over-read in exif_scan_thumbnail)",
            "CVE-2019-11042 (Heap buffer over-read in exif_process_IFD)"
        ],
        "7.3": ["CVE-2019-11043 (PHP-FPM RCE)"],
        "7.4": ["CVE-2020-7068 (Use-after-free in phar)"],
        "5.": ["CVE-2016-5385 (httpoxy)", "CVE-2012-1823 (CGI argument injection RCE)"]
    },
    "iis": {
        "10.0": [
            "CVE-2021-31166 (HTTP Protocol Stack RCE — wormable!)",
            "CVE-2022-21907 (HTTP.sys RCE — Critical)",
            "CVE-2021-34473 (ProxyShell — if Exchange is present)"
        ],
        "8.5": ["CVE-2017-7269 (WebDAV buffer overflow RCE)"],
        "7.5": ["CVE-2015-1635 (HTTP.sys integer overflow RCE)"]
    },
    "asp.net": {
        "": [
            "CVE-2020-1147 (.NET DataSet deserialization RCE)",
            "CVE-2017-8759 (.NET SOAP WSDL parser RCE)"
        ]
    }
}

# Error-inducing paths that may leak stack traces
ERROR_PATHS = [
    ("/%00/", "Null byte injection"),
    ("/~randomuser123/", "User enumeration via tilde"),
    ("/wp-content/debug.log", "WordPress debug log"),
    ("/elmah.axd", "ELMAH error log (ASP.NET)"),
    ("/trace.axd", "ASP.NET trace information"),
    ("/server-status", "Apache server-status"),
    ("/server-info", "Apache server-info"),
    ("/.well-known/security.txt", "Security contact info"),
    ("/crossdomain.xml", "Flash crossdomain policy"),
    ("/clientaccesspolicy.xml", "Silverlight access policy"),
    ("/web.config", "IIS web.config exposure"),
    ("/Global.asax", "ASP.NET Global.asax exposure"),
    ("/phpinfo.php", "PHP info page"),
    ("/info.php", "PHP info page (alt)"),
    ("/test.php", "PHP test page"),
    ("/i.php", "PHP info page (short)"),
    ("/.git/HEAD", "Git repository exposed"),
    ("/.svn/entries", "SVN repository exposed"),
    ("/.DS_Store", "macOS directory metadata"),
    ("/Thumbs.db", "Windows thumbnail cache"),
    ("/wp-config.php.bak", "WordPress config backup"),
    ("/wp-config.php.save", "WordPress config save file"),
    ("/wp-config.php.swp", "WordPress config vim swap"),
    ("/wp-config.php.old", "WordPress config old backup"),
    ("/wp-config.txt", "WordPress config as text"),
    ("/.env", "Environment variables file"),
    ("/.env.bak", "Environment variables backup"),
    ("/composer.json", "PHP Composer dependencies"),
    ("/composer.lock", "PHP Composer lock file"),
    ("/package.json", "Node.js package manifest"),
    ("/Gruntfile.js", "Grunt build file"),
    ("/gulpfile.js", "Gulp build file"),
    ("/Makefile", "Build Makefile"),
    ("/Dockerfile", "Docker configuration"),
    ("/docker-compose.yml", "Docker Compose config"),
]

# Patterns that indicate technology/info disclosure in error pages
ERROR_PATTERNS = [
    (r"Microsoft-IIS/[\d.]+", "IIS version in error page"),
    (r"PHP/[\d.]+", "PHP version in error page"),
    (r"Apache/[\d.]+", "Apache version in error page"),
    (r"nginx/[\d.]+", "nginx version in error page"),
    (r"ASP\.NET", "ASP.NET framework detected"),
    (r"X-Powered-By", "Framework disclosure in body"),
    (r"stack trace", "Stack trace exposed"),
    (r"at\s+\w+\.\w+\(", ".NET stack trace pattern"),
    (r"Fatal error:", "PHP fatal error"),
    (r"Warning:", "PHP warning"),
    (r"Notice:", "PHP notice"),
    (r"mysql_connect\(|mysqli_connect\(", "MySQL connection error"),
    (r"pg_connect\(|pg_query\(", "PostgreSQL error"),
    (r"ORA-\d{5}", "Oracle database error"),
    (r"ODBC\s+Driver", "ODBC driver error"),
    (r"org\.apache\.", "Java/Apache stack trace"),
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"\\\\[A-Za-z]:\\\\", "Windows file path disclosed"),
    (r"/var/www/|/home/\w+/|/usr/local/", "Linux file path disclosed"),
]


def _map_cves(tech, version):
    """Map a technology + version to known CVEs."""
    cve_list = VERSION_CVES.get(tech.lower(), {})
    matched = []
    for ver_prefix, cves in cve_list.items():
        if version.startswith(ver_prefix) or ver_prefix == "":
            matched.extend(cves)
    return matched


def _fingerprint_from_headers(response):
    """Extract technology fingerprints from HTTP headers."""
    findings = []
    headers = response.headers

    # Server header
    server = headers.get("Server", "")
    if server:
        findings.append(("server", server))
        # Extract IIS version
        iis_match = re.search(r"Microsoft-IIS/([\d.]+)", server)
        if iis_match:
            findings.append(("iis", iis_match.group(1)))

    # X-Powered-By
    powered_by = headers.get("X-Powered-By", "")
    if powered_by:
        findings.append(("framework", powered_by))
        php_match = re.search(r"PHP/([\d.]+)", powered_by)
        if php_match:
            findings.append(("php", php_match.group(1)))
        if "ASP.NET" in powered_by:
            findings.append(("asp.net", powered_by))

    # ASP.NET specific
    aspnet_ver = headers.get("X-AspNet-Version", "")
    if aspnet_ver:
        findings.append(("asp.net_version", aspnet_ver))
    
    aspnet_mvc = headers.get("X-AspNetMvc-Version", "")
    if aspnet_mvc:
        findings.append(("asp.net_mvc_version", aspnet_mvc))

    # Other headers
    via = headers.get("Via", "")
    if via:
        findings.append(("proxy_via", via))

    x_generator = headers.get("X-Generator", "")
    if x_generator:
        findings.append(("generator", x_generator))

    return findings


def _probe_error_pages(base_url, session):
    """Send requests designed to trigger error pages and extract info from them."""
    findings = []
    
    # Trigger various HTTP errors
    error_triggers = [
        (f"{base_url}/{'A' * 300}", "Long URL — may trigger 414/500"),
        (f"{base_url}/%00", "Null byte — may trigger IIS/PHP errors"),
        (f"{base_url}/non-existent-page-{hash('probe')}", "404 page analysis"),
    ]
    
    for url, desc in error_triggers:
        try:
            r = session.get(url, timeout=5)
            body = r.text
            
            for pattern, pattern_desc in ERROR_PATTERNS:
                matches = re.findall(pattern, body, re.IGNORECASE)
                if matches:
                    findings.append((pattern_desc, matches[0], url))
        except requests.RequestException:
            continue
    
    return findings


def _scan_sensitive_files(base_url, session):
    """Probe for sensitive files and directories."""
    findings = []
    
    for path, desc in ERROR_PATHS:
        url = base_url.rstrip('/') + path
        try:
            r = session.get(url, timeout=4)
            
            # Meaningful response check — avoid custom 404 pages
            if r.status_code == 200:
                content_type = r.headers.get("Content-Type", "").lower()
                content_length = len(r.text)
                
                # Skip HTML error pages (custom 404s)
                if content_length > 0:
                    # Strong indicators
                    if "phpinfo()" in r.text or "<title>phpinfo()</title>" in r.text:
                        findings.append(("phpinfo_exposed", f"phpinfo() page found: {url}", "Critical"))
                        continue
                    
                    if path == "/.git/HEAD" and r.text.startswith("ref:"):
                        findings.append(("git_exposed", f"Git repository exposed: {url}", "Critical"))
                        continue
                    
                    if path == "/.svn/entries" and ("dir" in r.text.lower() or r.text.strip().isdigit()):
                        findings.append(("svn_exposed", f"SVN repository exposed: {url}", "Critical"))
                        continue
                    
                    if path == "/.env" and ("=" in r.text and "html" not in content_type):
                        findings.append(("env_exposed", f"Environment file exposed: {url}", "Critical"))
                        continue

                    if path == "/web.config" and "<configuration" in r.text.lower():
                        findings.append(("webconfig_exposed", f"IIS web.config exposed: {url}", "Critical"))
                        continue

                    if path == "/wp-content/debug.log" and ("PHP" in r.text or "[" in r.text[:10]):
                        findings.append(("wp_debug_log", f"WordPress debug log exposed: {url}", "High"))
                        continue

                    if "json" in content_type and path in ["/composer.json", "/package.json"]:
                        findings.append(("dep_manifest", f"Dependency manifest exposed ({desc}): {url}", "Medium"))
                        continue
                    
                    if path in ["/elmah.axd", "/trace.axd"] and "error" in r.text.lower():
                        findings.append(("aspnet_logs", f"ASP.NET diagnostic logs exposed ({desc}): {url}", "Critical"))
                        continue

                    # Generic backup files — non-HTML content
                    if "html" not in content_type and path.endswith(('.bak', '.save', '.swp', '.old', '.txt')):
                        if "wp-config" in path and ("DB_" in r.text or "table_prefix" in r.text):
                            findings.append(("wp_config_leak", f"WordPress config backup exposed: {url}", "Critical"))
                            continue

        except requests.RequestException:
            continue

    return findings


def run_info_disclosure(target_url, endpoints=None, forms=None, session=None):
    """
    Aggressive information disclosure & fingerprinting module.
    Identifies server technologies, versions, and maps to known CVEs.
    """
    print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Running Information Disclosure & Fingerprinting Scan...")
    if session is None:
        import requests as session

    results = []
    base_url = target_url.rstrip('/')

    try:
        response = session.get(target_url, timeout=8)
    except requests.RequestException as e:
        print(f"  [{Fore.RED}!{Style.RESET_ALL}] Connection failed: {e}")
        return results

    # --- 1. Header Fingerprinting ---
    print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Fingerprinting from HTTP headers...")
    header_findings = _fingerprint_from_headers(response)
    
    tech_stack = {}
    for tech, value in header_findings:
        tech_stack[tech] = value
        res = f"Technology detected — {tech}: {value}"
        print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
        results.append({"type": "fingerprint", "desc": res, "severity": "Info"})

    # --- 2. CVE Mapping ---
    print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Mapping detected versions to known CVEs...")
    cve_found = False
    for tech, version in tech_stack.items():
        cves = _map_cves(tech, version)
        for cve in cves:
            cve_found = True
            res = f"Potential CVE for {tech} {version}: {cve}"
            print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
            results.append({"type": "cve_potential", "desc": res, "severity": "Critical"})
    
    if not cve_found:
        print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] No known CVEs mapped from detected versions.")

    # --- 3. Error Page Probing ---
    print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Probing error pages for info leaks...")
    error_findings = _probe_error_pages(base_url, session)
    for desc, match, url in error_findings:
        res = f"Error page leak — {desc}: '{match}' at {url}"
        print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
        results.append({"type": "error_disclosure", "desc": res, "severity": "Medium"})

    # --- 4. Sensitive File Scan ---
    print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Scanning for {len(ERROR_PATHS)} sensitive files/paths...")
    file_findings = _scan_sensitive_files(base_url, session)
    for ftype, desc, severity in file_findings:
        print(f"  [{Fore.RED}!{Style.RESET_ALL}] {desc}")
        results.append({"type": ftype, "desc": desc, "severity": severity})

    # --- 5. HTML Meta & Body Analysis ---
    print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Analyzing HTML body for technology fingerprints...")
    body = response.text
    
    # Generator meta tag
    gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](.*?)["\']', body, re.IGNORECASE)
    if gen_match:
        gen_val = gen_match.group(1)
        res = f"Generator meta tag found: {gen_val}"
        print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
        results.append({"type": "meta_generator", "desc": res, "severity": "Info"})

    # HTML comments with potential info
    comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
    for comment in comments[:20]:  # Limit
        comment_stripped = comment.strip()
        # Look for interesting patterns in comments
        if any(kw in comment_stripped.lower() for kw in ['version', 'build', 'todo', 'fixme', 'hack', 'password', 'key', 'secret', 'api', 'token', 'debug']):
            res = f"Interesting HTML comment found: {comment_stripped[:120]}"
            print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
            results.append({"type": "html_comment", "desc": res, "severity": "Info"})

    print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] Info disclosure scan complete: {len(results)} findings.")
    return results
