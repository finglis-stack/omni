import requests
from colorama import Fore, Style
from urllib.parse import urlparse

# Dangerous CORS origins to test
TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",  # null origin — exploitable via sandboxed iframe
    "https://{domain}.evil.com",  # subdomain confusion
    "https://evil{domain}",  # prefix bypass
    "https://{domain}.attacker.com",  # suffix matching
]


def _test_cors_origin(target_url, origin):
    """Send a request with a specific Origin header and analyze CORS response."""
    try:
        r = requests.get(
            target_url,
            headers={"Origin": origin},
            timeout=5,
            allow_redirects=True
        )
        
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        acam = r.headers.get("Access-Control-Allow-Methods", "")
        acah = r.headers.get("Access-Control-Allow-Headers", "")
        
        return {
            "acao": acao,
            "credentials": acac == "true",
            "methods": acam,
            "headers": acah,
            "status": r.status_code
        }
    except requests.RequestException:
        return None


def run_cors_scan(target_url, endpoints=None, forms=None):
    """
    CORS Misconfiguration Scanner.
    Tests for: wildcard origins, origin reflection, null origin,
    credential leakage, and subdomain bypass patterns.
    """
    print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Running CORS Misconfiguration Scan...")
    results = []
    domain = urlparse(target_url).netloc
    
    # Build dynamic origins
    origins = []
    for o in TEST_ORIGINS:
        origins.append(o.replace("{domain}", domain))
    
    # Also add the actual origin for baseline
    parsed = urlparse(target_url)
    legit_origin = f"{parsed.scheme}://{parsed.netloc}"
    
    # --- 1. Check baseline (no Origin header) ---
    print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Checking baseline CORS configuration...")
    try:
        r_base = requests.get(target_url, timeout=5)
        base_acao = r_base.headers.get("Access-Control-Allow-Origin", "")
        
        if base_acao == "*":
            res = "CORS: Access-Control-Allow-Origin is wildcard (*) — any origin can read responses"
            print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
            results.append({"type": "cors_wildcard", "desc": res, "severity": "High"})
            
            if r_base.headers.get("Access-Control-Allow-Credentials", "").lower() == "true":
                res = "CORS: Wildcard + Allow-Credentials: true — CRITICAL! Cookies/auth tokens can be stolen by any site"
                print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
                results.append({"type": "cors_wildcard_creds", "desc": res, "severity": "Critical"})
    except requests.RequestException:
        pass

    # --- 2. Test each malicious origin ---
    print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Testing {len(origins)} malicious origins...")
    
    for origin in origins:
        result = _test_cors_origin(target_url, origin)
        if not result:
            continue
            
        acao = result["acao"]
        
        # Origin reflected back?
        if acao == origin:
            res = f"CORS: Origin '{origin}' is reflected back in ACAO — arbitrary origin accepted!"
            print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
            results.append({"type": "cors_reflection", "desc": res, "severity": "High"})
            
            if result["credentials"]:
                res = f"CORS: Origin reflection + credentials allowed for '{origin}' — full account takeover possible!"
                print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
                results.append({"type": "cors_reflection_creds", "desc": res, "severity": "Critical"})
        
        # Null origin accepted?
        elif origin == "null" and acao == "null":
            res = "CORS: 'null' origin is accepted — exploitable via sandboxed iframe"
            print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
            results.append({"type": "cors_null", "desc": res, "severity": "High"})

    # --- 3. Scan discovered endpoints too ---
    if endpoints:
        api_endpoints = [e for e in endpoints if any(kw in e for kw in ["api", "json", "rest", "graphql", "ajax"])]
        
        if api_endpoints:
            print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Testing {len(api_endpoints)} API endpoints...")
            
            for ep in api_endpoints[:10]:  # Limit to first 10
                result = _test_cors_origin(ep, "https://evil.com")
                if result and result["acao"] == "https://evil.com":
                    res = f"CORS reflection on API endpoint: {ep}"
                    print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
                    results.append({"type": "cors_api_reflection", "desc": res, "severity": "High"})

    # --- 4. Preflight check (OPTIONS) ---
    print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Testing preflight (OPTIONS) configuration...")
    try:
        r = requests.options(
            target_url,
            headers={
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "X-Custom-Header, Authorization"
            },
            timeout=5
        )
        
        allowed_methods = r.headers.get("Access-Control-Allow-Methods", "")
        allowed_headers = r.headers.get("Access-Control-Allow-Headers", "")
        
        if "PUT" in allowed_methods or "DELETE" in allowed_methods or "PATCH" in allowed_methods:
            if r.headers.get("Access-Control-Allow-Origin", "") in ["*", "https://evil.com"]:
                res = f"CORS preflight allows dangerous methods ({allowed_methods}) for arbitrary origins"
                print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
                results.append({"type": "cors_preflight_dangerous", "desc": res, "severity": "High"})
        
        if "Authorization" in allowed_headers:
            if r.headers.get("Access-Control-Allow-Origin", "") in ["*", "https://evil.com"]:
                res = "CORS preflight allows Authorization header for arbitrary origins — token theft possible"
                print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
                results.append({"type": "cors_preflight_auth", "desc": res, "severity": "High"})
    except requests.RequestException:
        pass

    if not results:
        print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] No CORS misconfigurations detected.")
    else:
        print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] CORS scan complete: {len(results)} findings.")
    
    return results
