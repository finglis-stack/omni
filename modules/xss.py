import requests
from colorama import Fore, Style
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

PAYLOADS = [
    "<script>alert('XSS')</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>"
]

def run_xss_scan(target_url, endpoints, forms):
    print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Running Cross-Site Scripting (XSS) Scan...")
    results = []

    # 1. Scan query parameters in endpoints
    for url in endpoints:
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        if not params:
            continue
            
        for param_name in params:
            for payload in PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed_url._replace(query=new_query))
                
                try:
                    r = requests.get(test_url, timeout=5)
                    # Check if payload is reflected in the source code
                    if payload in r.text:
                        res = f"Possible Reflected XSS on {test_url} [Param: {param_name}]"
                        print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
                        results.append({"type": "xss", "desc": res, "severity": "High"})
                except requests.RequestException:
                    continue

    # 2. Scan forms
    for form in forms:
        action = form["action"]
        method = form["method"]
        
        for payload in PAYLOADS:
            data = {}
            for input_field in form["inputs"]:
                data[input_field["name"]] = payload
                
            try:
                if method == 'post':
                    r = requests.post(action, data=data, timeout=5)
                else:
                    r = requests.get(action, params=data, timeout=5)
                    
                if payload in r.text:
                    res = f"Possible Reflected XSS in form {action} via {method.upper()}"
                    print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
                    results.append({"type": "xss", "desc": res, "severity": "High"})
            except requests.RequestException:
                continue

    return results
