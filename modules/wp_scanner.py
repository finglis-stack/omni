import requests
from colorama import Fore, Style
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Un petit dictionnaire de plugins WP historiquement vulnérables ou très répandus
KNOWN_PLUGINS = [
    "revslider", "akismet", "contact-form-7", "woocommerce",
    "wp-file-manager", "duplicator", "elementor", "wordfence",
    "updraftplus", "wp-seo"
]

def check_wp_fingerprint(target_url):
    """
    Vérifie si le site tourne sous WordPress pour activer la payload agressive WP.
    """
    try:
        r = requests.get(target_url, timeout=5)
        if "wp-content" in r.text or "wp-includes" in r.text or "WordPress" in r.headers.get("X-Powered-By", ""):
            return True
        
        # Test du RSS
        rss_url = target_url.rstrip('/') + "/feed/"
        r_rss = requests.get(rss_url, timeout=5)
        if "wordpress" in r_rss.text.lower():
            return True
    except requests.RequestException:
        pass
    return False

def run_wp_scan(target_url, endpoints, forms):
    results = []
    print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Checking for WordPress footprint...")
    
    if not check_wp_fingerprint(target_url):
        print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] No strong WordPress signature found. Skipping Deep WP Scan.")
        # We can still force it if we want, but usually it's better to save thread power
        return results
        
    print(f"[{Fore.BLUE}*{Style.RESET_ALL}] WordPress detected! Launching WP Deep Scan...")
    
    base_url = target_url.rstrip('/')
    
    # 1. XML-RPC Exposure
    xmlrpc_url = f"{base_url}/xmlrpc.php"
    payload = "<?xml version='1.0' encoding='utf-8'?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>"
    try:
        r = requests.post(xmlrpc_url, data=payload, timeout=5)
        if "methodResponse" in r.text or "server error. requested method" in r.text:
            res = f"XML-RPC is active! Vulnerable to Pingback SSRF and Brute-Force amplifier: {xmlrpc_url}"
            print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
            results.append({"type": "wp_xmlrpc", "desc": res, "severity": "High"})
    except requests.RequestException:
        pass

    # 2. WP-Json API Users Enumeration
    api_url = f"{base_url}/wp-json/wp/v2/users"
    try:
        r = requests.get(api_url, timeout=5)
        if r.status_code == 200 and "id" in r.text and "name" in r.text:
            data = r.json()
            users = [u.get('slug') for u in data if isinstance(u, dict)]
            if users:
                res = f"REST API User Enumeration successful! Found users: {', '.join(users)}"
                print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
                results.append({"type": "wp_rest_users", "desc": res, "severity": "High"})
    except (requests.RequestException, ValueError):
        pass

    # 3. wp-cron.php Abuse
    cron_url = f"{base_url}/wp-cron.php"
    try:
        r = requests.get(cron_url, timeout=5)
        if r.status_code == 200:
            res = f"wp-cron.php is accessible. Potential vector for application DDoS: {cron_url}"
            print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
            results.append({"type": "wp_cron", "desc": res, "severity": "Medium"})
    except requests.RequestException:
        pass

    # 4. Multisite & Admin Interfaces
    ms_signup = f"{base_url}/wp-signup.php"
    try:
        r = requests.get(ms_signup, timeout=5)
        if r.status_code == 200 and "registration" in r.text.lower():
            res = "Possible WordPress Multisite (WPMU) configuration detected via wp-signup.php"
            print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
            results.append({"type": "wp_multisite", "desc": res, "severity": "Info"})
    except requests.RequestException:
        pass

    admin_url = f"{base_url}/wp-admin/"
    try:
        r = requests.get(admin_url, allow_redirects=False, timeout=5)
        if r.status_code in [200, 301, 302]:
            res = f"Admin panel is publicly exposed (no IP restriction): {admin_url}"
            print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
            results.append({"type": "wp_admin_exposed", "desc": res, "severity": "Low"})
    except requests.RequestException:
        pass

    # 5. Sensitive Backups / Configs
    backups = [
        "wp-config.php.bak", "wp-config.php.save", "wp-config.php.swp", 
        "wp-config.txt", "wp-config.php~", ".git/", "wp-content/debug.log"
    ]
    for backup in backups:
        b_url = f"{base_url}/{backup}"
        try:
            r = requests.get(b_url, timeout=3)
            # Avoid generic 200 OK from themes
            if r.status_code == 200 and "html" not in r.headers.get('Content-Type', ''):
                res = f"Critical information disclosure (Configuration/Backup): {b_url}"
                print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
                results.append({"type": "wp_config_leak", "desc": res, "severity": "Critical"})
        except requests.RequestException:
            pass

    # 6. Plugin Fuzzing
    print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Fuzzing for common WP plugins ({len(KNOWN_PLUGINS)} plugins)...")
    plugins_found = []
    for plugin in KNOWN_PLUGINS:
        p_url = f"{base_url}/wp-content/plugins/{plugin}/readme.txt"
        try:
            r = requests.get(p_url, timeout=3)
            if r.status_code == 200 and ("Plugin Name" in r.text or "Stable tag" in r.text):
                plugins_found.append(plugin)
        except requests.RequestException:
            pass
            
    if plugins_found:
        res = f"Discovered installed plugins via readme.txt: {', '.join(plugins_found)}"
        print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
        results.append({"type": "wp_plugins", "desc": res, "severity": "Info"})

    return results
