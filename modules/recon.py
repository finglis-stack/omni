import requests
from colorama import Fore, Style

def run_recon(target_url, session=None):
    if session is None:
        import requests as session
    print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Running Reconnaissance...")
    results = []
    
    # 1. Security Headers Analysis
    try:
        response = session.head(target_url, timeout=5)
        headers = response.headers
        
        critical_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options"
        ]
        
        missing_headers = [h for h in critical_headers if h not in headers]
        if missing_headers:
            res = f"Missing Security Headers: {', '.join(missing_headers)}"
            print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
            results.append({"type": "header_missing", "desc": res, "severity": "Low"})
            
        if "Server" in headers:
            res = f"Server software disclosed: {headers['Server']}"
            print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
            results.append({"type": "info_disclosure", "desc": res, "severity": "Info"})

        if "X-Powered-By" in headers:
            res = f"Framework disclosed: {headers['X-Powered-By']}"
            print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
            results.append({"type": "info_disclosure", "desc": res, "severity": "Info"})

    except requests.RequestException:
        print(f"  [{Fore.RED}!{Style.RESET_ALL}] Failed to connect for header analysis.")

    # 2. Sensitive Files Fuzzing (Basic)
    sensitive_files = [
        "robots.txt", ".git/config", ".env", "phpinfo.php", "backup.zip", ".htaccess"
    ]
    
    print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Fuzzing for sensitive files...")
    site_base = target_url if target_url.endswith('/') else target_url + '/'
    
    for file in sensitive_files:
        url = site_base + file
        try:
            r = session.get(url, timeout=3)
            if r.status_code == 200 and "html" not in r.headers.get("Content-Type", ""):
                # Basic check to avoid false positive 200s returning custom error pages
                res = f"Potential sensitive file found: {url}"
                print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
                results.append({"type": "sensitive_file", "desc": res, "severity": "High"})
        except requests.RequestException:
            continue
            
    return results
