import requests
import re
from colorama import Fore, Style
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

# Redirect parameter names commonly used
REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "returnTo", "return_to", "next", "next_url", "dest", "destination",
    "redir", "rurl", "target", "goto", "link", "forward", "forward_url",
    "continue", "callback", "ref", "referer", "out", "view", "login_url",
    "logout", "checkout_url", "image_url", "go", "jump", "to", "uri",
    "u", "r", "n", "ReturnUrl", "rUrl", "redirect_to",
]

# Payloads for testing open redirects
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "/\\evil.com",
    "////evil.com/%2f..",
    "https://evil.com%00.{domain}",
    "https://evil.com?.{domain}",
    "https://evil.com#{domain}",
    "https://{domain}@evil.com",
    "https://evil.com%23.{domain}",
    "//%09/evil.com",
    "https:///evil.com",
    "\\\\evil.com",
]


def _is_redirect_to_evil(location):
    """
    Check if the Location header actually redirects to evil.com.
    Must check the HOST/netloc of the destination, NOT just string matching.
    A URL like https://legit.com/?param=https://evil.com is NOT an open redirect.
    """
    try:
        parsed = urlparse(location)
        host = parsed.netloc.lower()
        
        # Check if the HOST is evil.com (not just in query params)
        if "evil.com" in host:
            return True
        
        # Protocol-relative redirects like //evil.com
        if location.strip().startswith("//"):
            after_slashes = location.strip()[2:].split("/")[0].split("?")[0]
            if "evil.com" in after_slashes.lower():
                return True
        
        # javascript: / data: URI schemes
        if parsed.scheme in ("javascript", "data") and "evil.com" in location.lower():
            return True
            
    except Exception:
        pass
    
    return False


def _test_redirect(url, timeout=5, session=None):
    """Send a request and check if we get redirected to evil.com."""
    try:
        r = session.get(url, timeout=timeout, allow_redirects=False)
        
        if r.status_code in [301, 302, 303, 307, 308]:
            location = r.headers.get("Location", "")
            if _is_redirect_to_evil(location):
                return True, location, r.status_code
        
        # Meta refresh check
        if r.status_code == 200:
            meta_match = re.search(
                r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*url=([^"\'>\s]+)',
                r.text, re.IGNORECASE
            )
            if meta_match and _is_redirect_to_evil(meta_match.group(1)):
                return True, meta_match.group(1), "meta-refresh"
            
            # JavaScript redirect check
            js_patterns = [
                r'window\.location\s*=\s*["\'](https?://[^"\']+)["\']',
                r'location\.href\s*=\s*["\'](https?://[^"\']+)["\']',
                r'window\.location\.replace\(["\'](https?://[^"\']+)["\']',
            ]
            for pattern in js_patterns:
                js_match = re.search(pattern, r.text, re.IGNORECASE)
                if js_match and _is_redirect_to_evil(js_match.group(1)):
                    return True, js_match.group(1), "js-redirect"
        
    except requests.RequestException:
        pass
    
    return False, "", 0


def _scan_known_redirect_paths(base_url, domain, session=None):
    """Test common WordPress/CMS redirect paths."""
    findings = []
    
    # WordPress-specific redirect vectors
    wp_paths = [
        f"{base_url}/wp-login.php?redirect_to=https://evil.com",
        f"{base_url}/wp-login.php?redirect_to=//evil.com",
        f"{base_url}/wp-login.php?action=logout&redirect_to=https://evil.com",
        f"{base_url}/?redirect_to=https://evil.com",
        f"{base_url}/wp-signup.php?redirect_to=https://evil.com",
    ]
    
    for path in wp_paths:
        is_vuln, location, status = _test_redirect(path, session=session)
        if is_vuln:
            findings.append({
                "url": path,
                "redirect_to": location,
                "status": status
            })
    
    return findings


def run_open_redirect_scan(target_url, endpoints=None, forms=None, session=None):
    """
    Open Redirect Detection Module.
    Tests URL parameters and known CMS paths for unvalidated redirects.
    """
    if session is None:
        import requests as session
    print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Running Open Redirect Scanner...")
    results = []
    base_url = target_url.rstrip('/')
    domain = urlparse(target_url).netloc
    
    # Build payloads with domain substitution
    payloads = [p.replace("{domain}", domain) for p in REDIRECT_PAYLOADS]

    # --- 1. Scan discovered endpoints for redirect params ---
    if endpoints:
        print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Testing {len(endpoints)} crawled endpoints...")
        
        for url in endpoints:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param_name in params:
                if param_name.lower() in [p.lower() for p in REDIRECT_PARAMS]:
                    for payload in payloads[:5]:  # Test first 5 payloads per param
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        new_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=new_query))
                        
                        is_vuln, location, status = _test_redirect(test_url, session=session)
                        if is_vuln:
                            res = f"Open Redirect via param '{param_name}' at {url} → {location} (HTTP {status})"
                            print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
                            results.append({"type": "open_redirect", "desc": res, "severity": "Medium"})
                            break  # One payload is enough

    # --- 2. Fuzz common redirect parameters on base URL ---
    print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Fuzzing {len(REDIRECT_PARAMS)} common redirect parameters on base URL...")
    
    for idx, param in enumerate(REDIRECT_PARAMS):
        if idx % 10 == 0 and idx > 0:
            print(f"    [{Fore.CYAN}-{Style.RESET_ALL}] Progress: fuzzed {idx}/{len(REDIRECT_PARAMS)} parameters")
            
        for payload in payloads[:2]:  # Top 2 payloads per param
            test_url = f"{base_url}/?{param}={payload}"
            
            is_vuln, location, status = _test_redirect(test_url, timeout=3, session=session)
            if is_vuln:
                res = f"Open Redirect via param '{param}' on base URL → {location} (HTTP {status})"
                print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
                results.append({"type": "open_redirect_fuzz", "desc": res, "severity": "Medium"})
                break  # Found one, skip other payloads for this param

    # --- 2b. Also fuzz the DOMAIN ROOT if target is in a subdirectory ---
    parsed_target = urlparse(target_url)
    domain_root = f"{parsed_target.scheme}://{parsed_target.netloc}"
    
    if domain_root.rstrip('/') != base_url:
        print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Target is in subdirectory — also fuzzing domain root {domain_root}...")
        
        # Key redirect params to test at root
        root_params = ["redirect_to", "redirect", "redirect_url", "return", "returnTo",
                       "next", "url", "goto", "dest", "forward", "rurl", "target"]
        
        for param in root_params:
            for payload in payloads[:3]:
                test_url = f"{domain_root}/?{param}={payload}"
                
                is_vuln, location, status = _test_redirect(test_url, timeout=3, session=session)
                if is_vuln:
                    res = f"Open Redirect via param '{param}' on DOMAIN ROOT → {location} (HTTP {status}) — URL: {test_url}"
                    print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
                    results.append({"type": "open_redirect_root", "desc": res, "severity": "High"})
                    break
        
        # WP login redirects at domain root
        root_wp_paths = [
            f"{domain_root}/wp-login.php?redirect_to=https://evil.com",
            f"{domain_root}/wp-login.php?redirect_to=//evil.com",
            f"{domain_root}/wp-login.php?action=logout&redirect_to=https://evil.com",
            f"{domain_root}/?redirect_to=https://evil.com",
        ]
        
        for path in root_wp_paths:
            is_vuln, location, status = _test_redirect(path, timeout=3, session=session)
            if is_vuln:
                res = f"Open Redirect at domain root: {path} → {location} (HTTP {status})"
                print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
                results.append({"type": "open_redirect_root_wp", "desc": res, "severity": "High"})

    # --- 3. WordPress/CMS Specific Redirect Paths ---
    print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Testing CMS-specific redirect vectors...")
    wp_findings = _scan_known_redirect_paths(base_url, domain, session=session)
    for f in wp_findings:
        res = f"CMS Open Redirect: {f['url']} → {f['redirect_to']} (HTTP {f['status']})"
        print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
        results.append({"type": "open_redirect_cms", "desc": res, "severity": "Medium"})

    # --- 4. Scan forms for redirect fields ---
    if forms:
        print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Checking {len(forms)} forms for hidden redirect fields...")
        for form in forms:
            for inp in form.get("inputs", []):
                name = inp.get("name", "").lower()
                if name in [p.lower() for p in REDIRECT_PARAMS]:
                    if inp.get("type") == "hidden":
                        res = f"Hidden redirect field '{inp['name']}' in form at {form['action']} — potential redirect manipulation"
                        print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
                        results.append({"type": "open_redirect_form", "desc": res, "severity": "Low"})

    if not results:
        print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] No open redirect vulnerabilities found.")
    else:
        print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] Open redirect scan complete: {len(results)} findings.")
    
    return results
