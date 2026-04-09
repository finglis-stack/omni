import requests
import re
from colorama import Fore, Style
from urllib.parse import urljoin

# Extended plugin list — top 50 most exploited WordPress plugins
PLUGINS = [
    "revslider", "akismet", "contact-form-7", "woocommerce", "wp-file-manager",
    "duplicator", "elementor", "wordfence", "updraftplus", "yoast-seo",
    "jetpack", "w3-total-cache", "wp-super-cache", "all-in-one-seo-pack",
    "wordpress-seo", "nextgen-gallery", "responsive-menu", "easy-wp-smtp",
    "wp-statistics", "wp-mail-smtp", "really-simple-ssl", "redirection",
    "google-sitemap-generator", "broken-link-checker", "loginizer",
    "sucuri-scanner", "limit-login-attempts-reloaded", "wp-smushit",
    "regenerate-thumbnails", "classic-editor", "advanced-custom-fields",
    "tinymce-advanced", "tablepress", "wp-migrate-db", "better-wp-security",
    "gravity-forms", "ninja-forms", "wpforms-lite", "formidable",
    "mailchimp-for-wp", "social-warfare", "the-events-calendar",
    "buddypress", "bbpress", "wp-graphql", "flavor", "simple-file-list",
    "file-manager", "coming-soon", "under-construction-page",
]

# Common WP themes to probe
THEMES = [
    "twentytwentyfive", "twentytwentyfour", "twentytwentythree",
    "twentytwentytwo", "twentytwentyone", "twentytwenty",
    "twentynineteen", "twentyeighteen", "twentyseventeen",
    "twentysixteen", "twentyfifteen", "astra", "flavstarter",
    "flavor-developer", "flavor-starter", "flavor",
    "flavstarter", "flavor-developer-starter",
    "flavor-developer-starter-developer",
    "flavor-starter-developer",
]

def _enum_users_rest(base):
    """Enumerate users via REST API."""
    users = []
    try:
        r = requests.get(f"{base}/wp-json/wp/v2/users", timeout=5)
        if r.status_code == 200:
            data = r.json()
            for u in data:
                if isinstance(u, dict):
                    users.append({"id": u.get("id"), "slug": u.get("slug"), "name": u.get("name")})
    except (requests.RequestException, ValueError):
        pass
    return users

def _enum_users_author(base):
    """Enumerate users via ?author=N brute-force."""
    users = []
    for i in range(1, 20):
        try:
            r = requests.get(f"{base}/?author={i}", timeout=5, allow_redirects=False)
            if r.status_code in [301, 302]:
                loc = r.headers.get("Location", "")
                match = re.search(r'/author/([^/]+)', loc)
                if match:
                    users.append({"id": i, "slug": match.group(1)})
            elif r.status_code == 200:
                match = re.search(r'author-(\w+)', r.text)
                if match:
                    users.append({"id": i, "slug": match.group(1)})
        except requests.RequestException:
            continue
    return users

def _enum_plugins(base):
    """Enumerate plugins via readme.txt and main PHP file probing."""
    found = []
    for plugin in PLUGINS:
        url = f"{base}/wp-content/plugins/{plugin}/readme.txt"
        try:
            r = requests.get(url, timeout=3)
            if r.status_code == 200 and ("==" in r.text or "Stable tag" in r.text or "Plugin Name" in r.text):
                version = "unknown"
                v_match = re.search(r'Stable tag:\s*([\d.]+)', r.text, re.IGNORECASE)
                if v_match:
                    version = v_match.group(1)
                found.append({"name": plugin, "version": version})
        except requests.RequestException:
            continue
    return found

def _enum_themes(base):
    """Enumerate themes via style.css probing."""
    found = []
    for theme in set(THEMES):
        url = f"{base}/wp-content/themes/{theme}/style.css"
        try:
            r = requests.get(url, timeout=3)
            if r.status_code == 200 and "Theme Name" in r.text:
                version = "unknown"
                v_match = re.search(r'Version:\s*([\d.]+)', r.text)
                if v_match:
                    version = v_match.group(1)
                found.append({"name": theme, "version": version})
        except requests.RequestException:
            continue
    return found

def _check_directory_listing(base):
    """Check for open directory listings in wp-content."""
    dirs_to_check = [
        "/wp-content/uploads/", "/wp-content/plugins/",
        "/wp-content/themes/", "/wp-content/uploads/" + "2026/",
        "/wp-includes/", "/wp-content/backup/",
        "/wp-content/backups/", "/wp-content/cache/",
    ]
    open_dirs = []
    for d in dirs_to_check:
        try:
            r = requests.get(f"{base}{d}", timeout=3)
            if r.status_code == 200 and ("Index of" in r.text or "Parent Directory" in r.text or "<title>Index" in r.text):
                open_dirs.append(f"{base}{d}")
        except requests.RequestException:
            continue
    return open_dirs

def _check_upload_vuln(base):
    """Check if uploads directory is browsable and contains interesting files."""
    findings = []
    url = f"{base}/wp-content/uploads/"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200 and ("Index of" in r.text or "Parent Directory" in r.text):
            findings.append(f"Uploads directory listing enabled: {url}")
            # Check for PHP files in uploads (webshell indicators)
            if ".php" in r.text.lower():
                findings.append(f"PHP files found in uploads directory (potential webshells!): {url}")
    except requests.RequestException:
        pass
    return findings

def _check_wp_version(base):
    """Extract WordPress core version."""
    indicators = [
        (f"{base}/feed/", r'<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>'),
        (f"{base}/", r'content="WordPress\s+([\d.]+)"'),
        (f"{base}/wp-links-opml.php", r'generator="WordPress/([\d.]+)"'),
        (f"{base}/readme.html", r'<br />\s*Version\s+([\d.]+)'),
    ]
    for url, pattern in indicators:
        try:
            r = requests.get(url, timeout=5)
            match = re.search(pattern, r.text)
            if match:
                return match.group(1)
        except requests.RequestException:
            continue
    return None


def run_wp_enum(target_url, endpoints=None, forms=None):
    """Advanced WordPress enumeration module."""
    print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Running Advanced WP Enumeration...")
    results = []
    base = target_url.rstrip('/')

    # --- 1. WP Core Version ---
    print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Detecting WordPress core version...")
    wp_ver = _check_wp_version(base)
    if wp_ver:
        res = f"WordPress version detected: {wp_ver}"
        print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
        results.append({"type": "wp_version", "desc": res, "severity": "Info"})
        # Flag old versions
        try:
            major, minor = int(wp_ver.split('.')[0]), int(wp_ver.split('.')[1])
            if major < 6 or (major == 6 and minor < 4):
                res = f"WordPress {wp_ver} is OUTDATED — multiple known CVEs apply"
                print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
                results.append({"type": "wp_outdated", "desc": res, "severity": "High"})
        except (ValueError, IndexError):
            pass

    # --- 2. User Enumeration ---
    print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Enumerating users via REST API...")
    users_rest = _enum_users_rest(base)
    if users_rest:
        slugs = [u['slug'] for u in users_rest]
        res = f"REST API user enumeration: {', '.join(slugs)}"
        print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
        results.append({"type": "wp_user_enum_rest", "desc": res, "severity": "High"})

    print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Enumerating users via author archives...")
    users_author = _enum_users_author(base)
    if users_author:
        slugs = [u['slug'] for u in users_author]
        res = f"Author archive user enumeration (IDs 1-19): {', '.join(slugs)}"
        print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
        results.append({"type": "wp_user_enum_author", "desc": res, "severity": "Medium"})

    # --- 3. Plugin Enumeration ---
    print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Enumerating plugins ({len(PLUGINS)} candidates)...")
    plugins = _enum_plugins(base)
    if plugins:
        for p in plugins:
            res = f"Plugin found: {p['name']} (version: {p['version']})"
            print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
            results.append({"type": "wp_plugin", "desc": res, "severity": "Info"})

    # --- 4. Theme Enumeration ---
    print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Enumerating themes...")
    themes = _enum_themes(base)
    if themes:
        for t in themes:
            res = f"Theme found: {t['name']} (version: {t['version']})"
            print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
            results.append({"type": "wp_theme", "desc": res, "severity": "Info"})

    # --- 5. Directory Listing ---
    print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Checking for open directory listings...")
    open_dirs = _check_directory_listing(base)
    for d in open_dirs:
        res = f"Directory listing enabled: {d}"
        print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
        results.append({"type": "wp_dir_listing", "desc": res, "severity": "Medium"})

    # --- 6. Upload Directory Analysis ---
    upload_findings = _check_upload_vuln(base)
    for f in upload_findings:
        print(f"  [{Fore.RED}!{Style.RESET_ALL}] {f}")
        sev = "Critical" if "webshell" in f.lower() or "php" in f.lower() else "Medium"
        results.append({"type": "wp_upload_vuln", "desc": f, "severity": sev})

    # --- 7. WP-Cron Abuse ---
    cron_url = f"{base}/wp-cron.php"
    try:
        r = requests.get(cron_url, timeout=5)
        if r.status_code == 200:
            res = f"wp-cron.php accessible — DDoS amplification vector: {cron_url}"
            print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
            results.append({"type": "wp_cron", "desc": res, "severity": "Medium"})
    except requests.RequestException:
        pass

    # --- 8. Registration & Login Pages ---
    reg_url = f"{base}/wp-login.php?action=register"
    try:
        r = requests.get(reg_url, timeout=5)
        if r.status_code == 200 and "registration" in r.text.lower():
            res = f"User registration is OPEN: {reg_url}"
            print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
            results.append({"type": "wp_registration_open", "desc": res, "severity": "High"})
    except requests.RequestException:
        pass

    # --- 9. Debug Mode ---
    debug_url = f"{base}/wp-content/debug.log"
    try:
        r = requests.get(debug_url, timeout=5)
        if r.status_code == 200 and len(r.text) > 50 and "html" not in r.headers.get("Content-Type", ""):
            res = f"WordPress debug.log exposed ({len(r.text)} bytes): {debug_url}"
            print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
            results.append({"type": "wp_debug_log", "desc": res, "severity": "High"})
    except requests.RequestException:
        pass

    print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] WP Enumeration complete: {len(results)} findings.")
    return results
