import argparse
import sys
import threading
from urllib.parse import urlparse
from colorama import init, Fore, Style
from core.crawler import Crawler
from core.reporter import Reporter
from modules.recon import run_recon
from modules.sqli import run_sqli_scan
from modules.xss import run_xss_scan
from modules.lfi import run_lfi_scan
from modules.wp_scanner import run_wp_scan
from modules.header_audit import run_header_audit
from modules.info_disclosure import run_info_disclosure
from modules.xmlrpc_exploit import run_xmlrpc_exploit
from modules.wp_enum import run_wp_enum
from modules.cors_misconfig import run_cors_scan
from modules.open_redirect import run_open_redirect_scan
from modules.xmlrpc_bruteforce import run_xmlrpc_bruteforce
from modules.iis_exploit import run_iis_exploit
from modules.elementor_exploit import run_elementor_exploit
from modules.wp_cve_exploit import run_wp_cve_exploit
from modules.auto_exploit import run_auto_exploit

# Initialize colorama
init(autoreset=True)

class OmniScan:
    def __init__(self, target_url, threads=5):
        self.target_url = target_url
        self.threads = threads
        self.domain = urlparse(target_url).netloc
        self.results = {
            "recon": [],
            "header_audit": [],
            "info_disclosure": [],
            "sqli": [],
            "xss": [],
            "lfi": [],
            "wp": [],
            "xmlrpc": [],
            "wp_enum": [],
            "cors": [],
            "open_redirect": [],
            "xmlrpc_bruteforce": [],
            "iis_exploit": [],
            "elementor_exploit": [],
            "wp_cve_exploit": [],
            "auto_exploit": [],
            "endpoints": [],
            "forms": []
        }
    
    def display_banner(self):
        banner = f"""
{Fore.CYAN}
   ____                  _  ____                  
  / __ \\____ ___  ____  (_)/ __/_________ _____   
 / / / / __ `__ \\/ __ \\/ / \\__ \\/ ___/ __ `/ __ \\ 
/ /_/ / / / / / / / / / / ___/ / /__/ /_/ / / / / 
\\____/_/ /_/ /_/_/ /_/_/ /____/\\___/\\__,_/_/ /_/  
                                                  
{Style.RESET_ALL}
        {Fore.WHITE}Advanced Web Vulnerability Scanner v3.0{Style.RESET_ALL}
        Target: {Fore.YELLOW}{self.target_url}{Style.RESET_ALL}
        Threads: {self.threads}
        Modules: 14 (recon, headers, info, sqli, xss, lfi, wp, xmlrpc, cors, redirect, bruteforce, iis, elementor, cve-exploit)
        """
        print(banner)

    def run(self):
        self.display_banner()

        # ========== PHASE 1: PASSIVE RECON ==========
        print(f"\n{'='*60}")
        print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Phase 1: Passive Reconnaissance & Fingerprinting")
        print(f"{'='*60}")
        
        # Recon + Header Audit + Info Disclosure (parallel)
        recon_threads = []
        t_recon = threading.Thread(target=self._run_module, args=("recon", run_recon))
        t_headers = threading.Thread(target=self._run_module, args=("header_audit", run_header_audit))
        t_info = threading.Thread(target=self._run_module, args=("info_disclosure", run_info_disclosure))
        
        recon_threads.extend([t_recon, t_headers, t_info])
        for t in recon_threads:
            t.start()
        for t in recon_threads:
            t.join()

        # ========== PHASE 2: CRAWLING ==========
        print(f"\n{'='*60}")
        print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Phase 2: Crawling & Endpoint Discovery")
        print(f"{'='*60}")
        
        crawler = Crawler(self.target_url)
        crawler.crawl()
        self.results["endpoints"] = crawler.get_endpoints()
        self.results["forms"] = crawler.get_forms()

        print(f"[{Fore.GREEN}+{Style.RESET_ALL}] Found {len(self.results['endpoints'])} endpoints and {len(self.results['forms'])} forms.")
        
        # ========== PHASE 3: ACTIVE VULN SCANNING ==========
        print(f"\n{'='*60}")
        print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Phase 3: Active Vulnerability Scanning")
        print(f"{'='*60}")
        
        scan_threads = []
        
        t_sqli = threading.Thread(target=self._run_module_with_data, args=("sqli", run_sqli_scan, self.results["endpoints"], self.results["forms"]))
        t_xss = threading.Thread(target=self._run_module_with_data, args=("xss", run_xss_scan, self.results["endpoints"], self.results["forms"]))
        t_lfi = threading.Thread(target=self._run_module_with_data, args=("lfi", run_lfi_scan, self.results["endpoints"], self.results["forms"]))
        t_cors = threading.Thread(target=self._run_module_with_data, args=("cors", run_cors_scan, self.results["endpoints"], self.results["forms"]))
        t_redirect = threading.Thread(target=self._run_module_with_data, args=("open_redirect", run_open_redirect_scan, self.results["endpoints"], self.results["forms"]))

        scan_threads.extend([t_sqli, t_xss, t_lfi, t_cors, t_redirect])

        for t in scan_threads:
            t.start()
        for t in scan_threads:
            t.join()

        # ========== PHASE 4: WORDPRESS SPECIFIC ==========
        print(f"\n{'='*60}")
        print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Phase 4: WordPress Deep Scan")
        print(f"{'='*60}")
        
        wp_threads = []
        t_wp = threading.Thread(target=self._run_module_with_data, args=("wp", run_wp_scan, self.results["endpoints"], self.results["forms"]))
        t_xmlrpc = threading.Thread(target=self._run_module_with_data, args=("xmlrpc", run_xmlrpc_exploit, self.results["endpoints"], self.results["forms"]))
        t_wpenum = threading.Thread(target=self._run_module_with_data, args=("wp_enum", run_wp_enum, self.results["endpoints"], self.results["forms"]))

        wp_threads.extend([t_wp, t_xmlrpc, t_wpenum])
        for t in wp_threads:
            t.start()
        for t in wp_threads:
            t.join()

        # ========== PHASE 5: EXPLOITATION ==========
        print(f"\n{'='*60}")
        print(f"[{Fore.RED}*{Style.RESET_ALL}] Phase 5: Active Exploitation")
        print(f"{'='*60}")
        
        exploit_threads = []
        t_bruteforce = threading.Thread(target=self._run_module_with_data, args=("xmlrpc_bruteforce", run_xmlrpc_bruteforce, self.results["endpoints"], self.results["forms"]))
        t_iis = threading.Thread(target=self._run_module_with_data, args=("iis_exploit", run_iis_exploit, self.results["endpoints"], self.results["forms"]))
        t_elementor = threading.Thread(target=self._run_module_with_data, args=("elementor_exploit", run_elementor_exploit, self.results["endpoints"], self.results["forms"]))
        t_cve = threading.Thread(target=self._run_module_with_data, args=("wp_cve_exploit", run_wp_cve_exploit, self.results["endpoints"], self.results["forms"]))

        exploit_threads.extend([t_bruteforce, t_iis, t_elementor, t_cve])
        for t in exploit_threads:
            t.start()
        for t in exploit_threads:
            t.join()

        # ========== PHASE 6: AUTO-EXPLOITATION ==========
        # Runs AFTER all scanning to weaponize confirmed vulns
        try:
            self.results["auto_exploit"] = run_auto_exploit(
                self.target_url, self.results["endpoints"], self.results["forms"]
            )
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

    def _run_module(self, name, func):
        """Run a module that only needs target_url."""
        try:
            res = func(self.target_url)
            self.results[name] = res
        except Exception as e:
            print(f"[{Fore.RED}!{Style.RESET_ALL}] Error in module {name}: {e}")

    def _run_module_with_data(self, name, func, endpoints, forms):
        """Run a module that needs target_url + crawled data."""
        try:
            res = func(self.target_url, endpoints, forms)
            self.results[name] = res
        except Exception as e:
            print(f"[{Fore.RED}!{Style.RESET_ALL}] Error in module {name}: {e}")

    def _print_summary(self):
        """Print a severity-based summary of all findings."""
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
        print(f"  Endpoints crawled:  {len(self.results['endpoints'])}")
        print(f"  Forms discovered:   {len(self.results['forms'])}")
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
    parser.add_argument("-w", "--wordlist", default=None, help="External wordlist file for brute-force (e.g., rockyou.txt)")
    
    args = parser.parse_args()
    
    if not args.url.startswith("http"):
        print(f"[{Fore.RED}!{Style.RESET_ALL}] URL must start with http:// or https://")
        sys.exit(1)

    # Set external wordlist for brute-force module
    if args.wordlist:
        import modules.xmlrpc_bruteforce as bf_module
        bf_module.EXTERNAL_WORDLIST = args.wordlist
        print(f"[{Fore.GREEN}+{Style.RESET_ALL}] External wordlist: {args.wordlist}")

    scanner = OmniScan(args.url, args.threads)
    scanner.run()
