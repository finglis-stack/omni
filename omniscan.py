import argparse
import sys
import threading
import asyncio
import importlib
import inspect
import concurrent.futures
from urllib.parse import urlparse
from colorama import init, Fore, Style
from collections import defaultdict
from core.crawler import Crawler
from core.reporter import Reporter
from core.stealth_session import StealthSession
from core.waf_evasion import WAFEngine
from modules.auto_exploit import run_auto_exploit

# Initialize colorama
init(autoreset=True)

class OmniScan:
    def __init__(self, target_url, threads=5, stealth="light", proxy=None,
                 proxy_file=None, rotate_ua=25, impersonate=None):
        self.target_url = target_url
        self.threads = threads
        self.domain = urlparse(target_url).netloc
        self.results = defaultdict(list)
        self.lock = threading.Lock()
        self.dashboard = None  # Set by DashboardServer when running in dashboard mode

        # ─── Stealth Engine ───
        self.waf = WAFEngine()
        self.session = StealthSession(
            stealth_level=stealth,
            proxy=proxy,
            proxy_file=proxy_file,
            rotate_ua_every=rotate_ua,
            impersonate=impersonate,
            waf_engine=self.waf,
        )
    
    def _emit(self, event_type, data):
        """Emit event to dashboard via WebSocket if dashboard mode is active."""
        if self.dashboard:
            try:
                loop = asyncio.new_event_loop()
                loop.run_until_complete(self.dashboard.emit_event(event_type, data))
                loop.close()
            except Exception:
                pass  # Don't let dashboard errors break the scan

    def _emit_finding(self, module, finding):
        """Emit a single finding to the dashboard."""
        self._emit("finding", {
            "module": module,
            "severity": finding.get("severity", "Info"),
            "type": finding.get("type", "unknown"),
            "desc": finding.get("desc", ""),
        })

    def display_banner(self):
        banner = f"""
{Fore.CYAN}
   ____                  _  ____                  
  / __ \____ ___  ____  (_)/ __/_________ _____   
 / / / / __ `__ \/ __ \/ / \__ \/ ___/ __ `/ __ \ 
/ /_/ / / / / / / / / / / ___/ / /__/ /_/ / / / / 
\____/_/ /_/ /_/_/ /_/_/ /____/\___/\__,_/_/ /_/  
                                                  
{Style.RESET_ALL}
        {Fore.WHITE}Advanced Web Vulnerability Scanner v4.0 (Stealth){Style.RESET_ALL}
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
            args = [self.target_url]
            
            # Inject parameters based on function signature
            params = list(sig.parameters.keys())
            if len(params) > 1 and params[1] == 'endpoints':
                args.append(self.results.get('endpoints', []))
            if len(params) > 2 and params[2] == 'forms':
                args.append(self.results.get('forms', []))
            
            # Inject session or waf_engine
            if 'session' in sig.parameters:
                args.append(self.session)
            elif 'waf_engine' in sig.parameters:
                args.append(self.session)
                
            res = run_func(*args)
            if res:
                with self.lock:
                    if isinstance(res, list):
                        self.results[mod_name].extend(res)
                        for finding in res:
                            self._emit_finding(mod_name, finding)
                    else:
                        self.results[mod_name].append(res)
                        self._emit_finding(mod_name, res)
        except Exception as e:
            print(f"[{Fore.RED}!{Style.RESET_ALL}] Error in module {mod_name}: {e}")

    def _run_phase(self, phase_name, module_names, phase_number=0):
        print(f"\n{'='*60}")
        print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Phase: {phase_name}")
        print(f"{'='*60}")
        
        self._emit("phase", {"name": phase_name, "number": phase_number})
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self._execute_module, module_names)

    def run(self):
        self.display_banner()

        # ========== PHASE 1: WAF DETECTION ==========
        self._emit("phase", {"name": "WAF Detection", "number": 1})
        print(f"\n{'='*60}")
        print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Phase 1: WAF Detection")
        print(f"{'='*60}")
        detected_waf = self.waf.detect(self.target_url, session=self.session)
        if detected_waf:
            finding = {"type": "waf_detected", "desc": f"WAF Detected: {detected_waf}", "severity": "Info"}
            self.results["waf_detection"].append(finding)
            self._emit_finding("waf_detection", finding)

        self._run_phase("Passive Reconnaissance & Fingerprinting", 
                       ["recon", "dns_recon", "header_audit", "info_disclosure"], phase_number=2)

        # ========== PHASE 2: CRAWLING ==========
        self._emit("phase", {"name": "Async Crawling", "number": 3})
        print(f"\n{'='*60}")
        print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Phase 3: Async Crawling & Endpoint Discovery")
        print(f"{'='*60}")
        
        crawler = Crawler(self.target_url, max_concurrent=self.threads * 4,
                          headers=self.session.get_headers(),
                          proxy=self.session.get_proxy_url())
        crawler.crawl()
        self.results["endpoints"] = crawler.get_endpoints()
        self.results["forms"] = crawler.get_forms()

        print(f"[{Fore.GREEN}+{Style.RESET_ALL}] Found {len(self.results['endpoints'])} endpoints and {len(self.results['forms'])} forms.")
        self._emit("discovery", {
            "endpoints": len(self.results['endpoints']),
            "forms": len(self.results['forms']),
        })

        # ========== PHASE 3: ACTIVE VULN SCANNING ==========
        self._run_phase("Active Vulnerability Scanning", 
                       ["sqli", "xss", "lfi", "cors_misconfig", "open_redirect"], phase_number=4)

        # ========== PHASE 4: WORDPRESS SPECIFIC ==========
        self._run_phase("WordPress Deep Scan", 
                       ["wp_scanner", "xmlrpc_exploit", "wp_enum"], phase_number=5)

        # ========== PHASE 5: EXPLOITATION ==========
        self._run_phase("Active Exploitation", 
                       ["iis_exploit", "elementor_exploit", "wp_cve_exploit"], phase_number=6)

        # ========== PHASE 6: AUTO-EXPLOITATION ==========
        self._emit("phase", {"name": "Auto-Exploitation", "number": 6})
        print(f"\n{'='*60}")
        print(f"[{Fore.RED}*{Style.RESET_ALL}] Phase 6: Auto-Exploitation (Weaponization)")
        print(f"{'='*60}")
        try:
            res = run_auto_exploit(
                self.target_url, self.results.get("endpoints", []), self.results.get("forms", []), self.results, self.session
            )
            if res:
                self.results["auto_exploit"] = res
                for finding in res:
                    self._emit_finding("auto_exploit", finding)
        except Exception as e:
            print(f"[{Fore.RED}!{Style.RESET_ALL}] Error in auto-exploit: {e}")

        # ========== PHASE 7: REPORT ==========
        self._emit("phase", {"name": "Report Generation", "number": 7})
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
        print(f"  {'-'*50}")
        print(f"  {Fore.RED}Critical:  {severity_counts['Critical']}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}High:      {severity_counts['High']}{Style.RESET_ALL}")
        print(f"  {Fore.LIGHTYELLOW_EX}Medium:    {severity_counts['Medium']}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Low:       {severity_counts['Low']}{Style.RESET_ALL}")
        print(f"  {Fore.BLUE}Info:      {severity_counts['Info']}{Style.RESET_ALL}")
        print(f"  {'='*50}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OmniScan - Advanced Web Vulnerability Scanner v4.0 (Stealth)")
    parser.add_argument("-u", "--url", required=False, help="Target URL (e.g., http://example.com/)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads")
    parser.add_argument("--stealth", choices=["none", "light", "normal", "paranoid"], default="light",
                        help="Stealth timing profile (default: light)")
    parser.add_argument("--proxy", help="Proxy URL (e.g., socks5://127.0.0.1:9050)")
    parser.add_argument("--proxy-file", help="File with proxy list (one per line) for rotation")
    parser.add_argument("--rotate-ua", type=int, default=25, help="Rotate User-Agent every N requests (default: 25)")
    parser.add_argument("--impersonate", choices=["chrome", "firefox", "safari", "edge"],
                        help="Browser TLS fingerprint to impersonate (JA3 spoofing)")
    parser.add_argument("--dashboard", action="store_true",
                        help="Launch the real-time web dashboard instead of CLI mode")
    parser.add_argument("--api-key", help="OpenRouter API key for AI analysis")
    parser.add_argument("--port", type=int, default=8888, help="Dashboard server port (default: 8888)")
    
    args = parser.parse_args()

    # ─── Dashboard Mode ───
    if args.dashboard:
        from dashboard.server import DashboardServer
        from core.ai_analyzer import AIAnalyzer

        server = DashboardServer(port=args.port)
        if args.api_key:
            server.ai_analyzer = AIAnalyzer(api_key=args.api_key)
        server.start(open_browser=True)
    else:
        # ─── CLI Mode ───
        if not args.url:
            print(f"[{Fore.RED}!{Style.RESET_ALL}] URL is required in CLI mode. Use -u or --dashboard.")
            sys.exit(1)
        if not args.url.startswith("http"):
            print(f"[{Fore.RED}!{Style.RESET_ALL}] URL must start with http:// or https://")
            sys.exit(1)

        scanner = OmniScan(
            args.url,
            threads=args.threads,
            stealth=args.stealth,
            proxy=args.proxy,
            proxy_file=args.proxy_file,
            rotate_ua=args.rotate_ua,
            impersonate=args.impersonate,
        )
        scanner.run()
