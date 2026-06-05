import requests
from colorama import Fore, Style
from urllib.parse import urlparse

# All critical security headers and their expected values / presence
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "High",
        "desc": "Missing HSTS — vulnerable to SSL stripping attacks (sslstrip/MITM)"
    },
    "Content-Security-Policy": {
        "severity": "High",
        "desc": "Missing CSP — no XSS mitigation at browser level, inline scripts allowed"
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "desc": "Missing X-Frame-Options — vulnerable to clickjacking attacks"
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "desc": "Missing X-Content-Type-Options — MIME-sniffing attacks possible"
    },
    "Referrer-Policy": {
        "severity": "Low",
        "desc": "Missing Referrer-Policy — sensitive URL data may leak via Referer header"
    },
    "Permissions-Policy": {
        "severity": "Low",
        "desc": "Missing Permissions-Policy — browser features (camera, mic, geolocation) not restricted"
    },
    "X-XSS-Protection": {
        "severity": "Info",
        "desc": "Missing X-XSS-Protection (legacy but still used by older browsers)"
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "Low",
        "desc": "Missing COOP — cross-origin window references not restricted"
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "Low",
        "desc": "Missing CORP — resources can be loaded by any origin"
    },
    "Cross-Origin-Embedder-Policy": {
        "severity": "Low",
        "desc": "Missing COEP — cross-origin resources not isolated"
    }
}

# Dangerous headers that should NOT be present
DANGEROUS_HEADERS = {
    "Server": {
        "severity": "Info",
        "desc": "Server version disclosed"
    },
    "X-Powered-By": {
        "severity": "Info",
        "desc": "Framework/runtime disclosed"
    },
    "X-AspNet-Version": {
        "severity": "Medium",
        "desc": "ASP.NET version disclosed — useful for targeted CVE exploitation"
    },
    "X-AspNetMvc-Version": {
        "severity": "Medium",
        "desc": "ASP.NET MVC version disclosed"
    }
}


def _check_hsts_quality(hsts_value):
    """Evaluate HSTS header quality."""
    issues = []
    if "max-age=" in hsts_value.lower():
        try:
            max_age = int(hsts_value.lower().split("max-age=")[1].split(";")[0].strip())
            if max_age < 31536000:  # Less than 1 year
                issues.append(f"HSTS max-age too short ({max_age}s) — recommended minimum is 31536000 (1 year)")
        except (ValueError, IndexError):
            pass
    if "includesubdomains" not in hsts_value.lower():
        issues.append("HSTS missing includeSubDomains directive")
    if "preload" not in hsts_value.lower():
        issues.append("HSTS missing preload directive — not eligible for browser preload lists")
    return issues


def _check_csp_quality(csp_value):
    """Evaluate CSP header for common bypasses."""
    issues = []
    csp_lower = csp_value.lower()

    if "'unsafe-inline'" in csp_lower:
        issues.append("CSP allows 'unsafe-inline' — XSS mitigation significantly weakened")
    if "'unsafe-eval'" in csp_lower:
        issues.append("CSP allows 'unsafe-eval' — eval() and similar APIs permitted")
    if "data:" in csp_lower:
        issues.append("CSP allows data: URIs — potential XSS via data: scheme injection")
    if "*" in csp_value:
        issues.append("CSP contains wildcard (*) — overly permissive policy")
    if "default-src" not in csp_lower and "script-src" not in csp_lower:
        issues.append("CSP missing both default-src and script-src — no effective script control")
    if "http:" in csp_lower:
        issues.append("CSP allows http: scheme — mixed content attacks possible")

    return issues


def _check_cookie_flags(response):
    """Audit Set-Cookie headers for security flags."""
    issues = []
    cookies = response.headers.get("Set-Cookie", "")
    
    if not cookies:
        return issues
    
    # Can be multiple Set-Cookie headers joined
    cookie_lines = cookies.split(",")
    for cookie in cookie_lines:
        cookie_lower = cookie.lower().strip()
        cookie_name = cookie.split("=")[0].strip() if "=" in cookie else "unknown"
        
        if "secure" not in cookie_lower:
            issues.append(f"Cookie '{cookie_name}' missing Secure flag — sent over HTTP")
        if "httponly" not in cookie_lower:
            issues.append(f"Cookie '{cookie_name}' missing HttpOnly flag — accessible via JavaScript (XSS)")
        if "samesite" not in cookie_lower:
            issues.append(f"Cookie '{cookie_name}' missing SameSite attribute — CSRF risk")

    return issues


def run_header_audit(target_url, endpoints=None, forms=None, session=None):
    """
    Comprehensive HTTP Security Header Audit.
    Tests presence, absence, and quality of all security-critical headers.
    """
    if session is None:
        import requests as session
    print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Running Deep Security Header Audit...")
    results = []

    try:
        # Use GET instead of HEAD to also capture Set-Cookie and full response
        response = session.get(target_url, timeout=8, allow_redirects=True)
        headers = response.headers
    except requests.RequestException as e:
        print(f"  [{Fore.RED}!{Style.RESET_ALL}] Connection failed for header audit: {e}")
        return results

    # --- 1. Missing Security Headers ---
    print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Checking {len(SECURITY_HEADERS)} security headers...")
    missing = []
    for header, info in SECURITY_HEADERS.items():
        if header not in headers:
            missing.append(header)
            res = f"{info['desc']}: {header}"
            print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
            results.append({"type": "header_missing", "desc": res, "severity": info["severity"]})

    if not missing:
        print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] All critical security headers are present!")

    # --- 2. Header Quality Analysis ---
    if "Strict-Transport-Security" in headers:
        hsts_issues = _check_hsts_quality(headers["Strict-Transport-Security"])
        for issue in hsts_issues:
            print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {issue}")
            results.append({"type": "header_weak_hsts", "desc": issue, "severity": "Medium"})

    if "Content-Security-Policy" in headers:
        csp_issues = _check_csp_quality(headers["Content-Security-Policy"])
        for issue in csp_issues:
            print(f"  [{Fore.RED}!{Style.RESET_ALL}] {issue}")
            results.append({"type": "header_weak_csp", "desc": issue, "severity": "High"})

    # --- 3. Dangerous Information Disclosure Headers ---
    print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Checking for information leakage headers...")
    for header, info in DANGEROUS_HEADERS.items():
        if header in headers:
            value = headers[header]
            res = f"{info['desc']}: {header}: {value}"
            print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
            results.append({"type": "info_disclosure", "desc": res, "severity": info["severity"]})

    # --- 4. Cookie Security Flags ---
    print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Auditing cookie security flags...")
    cookie_issues = _check_cookie_flags(response)
    for issue in cookie_issues:
        print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {issue}")
        results.append({"type": "cookie_insecure", "desc": issue, "severity": "Medium"})

    if not cookie_issues:
        print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] No insecure cookies found (or no cookies set).")

    # --- 5. HTTPS enforcement check ---
    parsed = urlparse(target_url)
    if parsed.scheme == "https":
        # Check if HTTP version also exists (no redirect)
        http_url = target_url.replace("https://", "http://", 1)
        try:
            r = session.get(http_url, timeout=5, allow_redirects=False)
            if r.status_code == 200:
                res = f"HTTP version responds with 200 instead of redirecting to HTTPS — HSTS not enforced at server level"
                print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
                results.append({"type": "no_https_redirect", "desc": res, "severity": "High"})
            elif r.status_code in [301, 302, 307, 308]:
                location = r.headers.get("Location", "")
                if not location.startswith("https://"):
                    res = f"HTTP redirects but NOT to HTTPS — redirect chain may be hijackable"
                    print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
                    results.append({"type": "weak_https_redirect", "desc": res, "severity": "Medium"})
        except requests.RequestException:
            pass

    # --- 6. Cache-Control for sensitive pages ---
    cache_control = headers.get("Cache-Control", "")
    if "no-store" not in cache_control.lower() and "no-cache" not in cache_control.lower():
        res = "Missing Cache-Control: no-store — sensitive responses may be cached by proxies/browsers"
        print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
        results.append({"type": "cache_control_missing", "desc": res, "severity": "Low"})

    print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] Header audit complete: {len(results)} findings.")
    return results
