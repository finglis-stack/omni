import argparse
import sys
import threading
import importlib
import inspect
import concurrent.futures
from urllib.parse import urlparse
from colorama import init, Fore, Style
from collections import defaultdict
from core.crawler import Crawler
from core.reporter import Reporter
from modules.auto_exploit import run_auto_exploit
from core.waf_evasion import WAFEngine

# Initialize colorama
init(autoreset=True)

class OmniScan:
    def __init__(self, target_url, threads=5):
        self.target_url = target_url
        self.threads = threads
        self.domain = urlparse(target_url).netloc
        self.results = defaultdict(list)
        self.waf = WAFEngine()
        self.lock = threading.Lock()
    
    def display_banner(self):
        banner = f"""
{Fore.CYAN}
   ____                  _  ____                  
  / __ \____ ___  ____  (_)/ __/_________ _____   
 / / / / __ `__ \/ __ \/ / \__ \/ ___/ __ `/ __ \ 
/ /_/ / / / / / / / / / / ___/ / /__/ /_/ / / / / 
\____/_/ /_/ /_/_/ /_/_/ /____/\___/\__,_/_/ /_/  
                                                  
{Style.RESET_ALL}
        {Fore.WHITE}Advanced Web Vulnerability Scanner v3.0 (Async/Threaded){Style.RESET_ALL}
        Target: {Fore.YELLOW}{self.target_url}{Style.RESET_ALL}
        Threads: {self.threads}
        """
        print(banner)

    def _execute_module(self, mod_name):
        try:
            mod = importlib.import_module(f"modules.{mod_name}")
            run_func = None
            for name, obj in inspect.getmembers(mod, inspect.isfunction):
                if name.startswith('run_') and mod.__name__ == obj.__module__:
                    run_func = obj
                    break
                    
            if not run_func:
                print(f"[{Fore.YELLOW}!{Style.RESET_ALL}] No run_* function found in {mod_name}")
                return
            
            sig = inspect.signature(run_func)
            kwargs = {}
            args = [self.target_url]
            
            # Map parameters based on signature
            if 'endpoints' in sig.parameters:
                args.append(self.results.get('endpoints', []))
            if 'forms' in sig.parameters:
                args.append(self.results.get('forms', []))
            if 'waf_engine' in sig.parameters:
                args.append(self.waf)
                
            res = run_func(*args)
            if res:
                with self.lock:
                    if isinstance(res, list):
                        self.results[mod_name].extend(res)
                    else:
                        self.results[mod_name].append(res)
        except Exception as e:
            print(f"[{Fore.RED}!{Style.RESET_ALL}] Error in module {mod_name}: {e}")

    def _run_phase(self, phase_name, module_names):
        print(f"\n{'='*60}")
        print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Phase: {phase_name}")
        print(f"{'='*60}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self._execute_module, module_names)

    def run(self):
        self.display_banner()

        # ========== PHASE 1: PASSIVE RECON ==========
        print(f"\n{'='*60}")
        print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Phase 1: WAF Detection")
        print(f"{'='*60}")
        detected_waf = self.waf.detect(self.target_url)
        if detected_waf:
            self.results["waf_detection"].append({"type": "waf_detected", "desc": f"WAF Detected: {detected_waf}", "severity": "Info"})

        self._run_phase("Passive Reconnaissance & Fingerprinting", 
                       ["recon", "dns_recon", "header_audit", "info_disclosure"])

        # ========== PHASE 2: CRAWLING ==========
        print(f"\n{'='*60}")
        print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Phase 2: Async Crawling & Endpoint Discovery")
        print(f"{'='*60}")
        
        crawler = Crawler(self.target_url, max_concurrent=self.threads * 4)
        crawler.crawl()
        self.results["endpoints"] = crawler.get_endpoints()
        self.results["forms"] = crawler.get_forms()

        # ========== PHASE 3: ACTIVE VULN SCANNING ==========
        self._run_phase("Active Vulnerability Scanning", 
                       ["sqli", "xss", "lfi", "cors_misconfig", "open_redirect"])

        # ========== PHASE 4: WORDPRESS SPECIFIC ==========
        self._run_phase("WordPress Deep Scan", 
                       ["wp_scanner", "xmlrpc_exploit", "wp_enum"])

        # ========== PHASE 5: EXPLOITATION ==========
        self._run_phase("Active Exploitation", 
                       ["iis_exploit", "elementor_exploit", "wp_cve_exploit"])

        # ========== PHASE 6: AUTO-EXPLOITATION ==========
        print(f"\n{'='*60}")
        print(f"[{Fore.RED}*{Style.RESET_ALL}] Phase 6: Auto-Exploitation (Weaponization)")
        print(f"{'='*60}")
        try:
            res = run_auto_exploit(
                self.target_url, self.results.get("endpoints", []), self.results.get("forms", []), self.results
            )
            if res:
                self.results["auto_exploit"] = res
        except Exception as e:
            print(f"[{Fore.RED}!{Style.RESET_ALL}] Error in auto-exploit: {e}")

        # ========== PHASE 7: REPORT ==========
        print(f"\n{'='*60}")
        print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Phase 7: Generating Report")
        print(f"{'='*60}")
        
        self._print_summary()
        
        reporter = Reporter(self.target_url, self.results)
        report_file = reporter.generate()
        
        print(f"\n[{Fore.GREEN}+{Style.RESET_ALL}] Scan complete! Report saved to {Fore.CYAN}{report_file}{Style.RESET_ALL}")

    def _print_summary(self):
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        total = 0
        
        for key, items in self.results.items():
            if key in ["endpoints", "forms"]:
                continue
            for item in items:
                sev = item.get("severity", "Info")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                total += 1
        
        print(f"\n  {'='*50}")
        print(f"  {Fore.WHITE}SCAN SUMMARY{Style.RESET_ALL}")
        print(f"  {'='*50}")
        print(f"  Endpoints crawled:  {len(self.results.get('endpoints', []))}")
        print(f"  Forms discovered:   {len(self.results.get('forms', []))}")
        print(f"  Total findings:     {total}")
        print(f"  {'─'*50}")
        print(f"  {Fore.RED}Critical:  {severity_counts['Critical']}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}High:      {severity_counts['High']}{Style.RESET_ALL}")
        print(f"  {Fore.LIGHTYELLOW_EX}Medium:    {severity_counts['Medium']}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Low:       {severity_counts['Low']}{Style.RESET_ALL}")
        print(f"  {Fore.BLUE}Info:      {severity_counts['Info']}{Style.RESET_ALL}")
        print(f"  {'='*50}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OmniScan - Advanced Web Vulnerability Scanner v3.0")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., http://example.com/)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads")
    
    args = parser.parse_args()
    
    if not args.url.startswith("http"):
        print(f"[{Fore.RED}!{Style.RESET_ALL}] URL must start with http:// or https://")
        sys.exit(1)

    scanner = OmniScan(args.url, args.threads)
    scanner.run()
