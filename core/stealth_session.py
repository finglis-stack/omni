"""
OmniScan Stealth Session Engine
Centralized HTTP session with browser fingerprint rotation, TLS spoofing,
intelligent timing, proxy chain support, and WAF evasion integration.

ALL modules route through this engine — one file controls the entire scanner's
network footprint.
"""
import time
import random
import math
import itertools
from urllib.parse import urlparse
from colorama import Fore, Style

# ─── Try curl_cffi for TLS/JA3 spoofing, fallback to requests ───
try:
    from curl_cffi import requests as stealth_requests
    CURL_CFFI_AVAILABLE = True
except ImportError:
    import requests as stealth_requests
    CURL_CFFI_AVAILABLE = False

import requests as raw_requests  # always available for fallback


# ============================================================
# BROWSER FINGERPRINT PROFILES
# ============================================================
BROWSER_PROFILES = [
    {
        "name": "Chrome 125 Windows",
        "impersonate": "chrome",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-CH-UA": '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        }
    },
    {
        "name": "Chrome 124 macOS",
        "impersonate": "chrome",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-CH-UA": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": '"macOS"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        }
    },
    {
        "name": "Firefox 126 Windows",
        "impersonate": "firefox",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "DNT": "1",
        }
    },
    {
        "name": "Firefox 125 Linux",
        "impersonate": "firefox",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        }
    },
    {
        "name": "Edge 125 Windows",
        "impersonate": "edge",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-CH-UA": '"Microsoft Edge";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        }
    },
    {
        "name": "Safari 17 macOS",
        "impersonate": "safari",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
        }
    },
    {
        "name": "Chrome 123 Android",
        "impersonate": "chrome",
        "user_agent": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-CH-UA": '"Google Chrome";v="123", "Chromium";v="123", "Not:A-Brand";v="8"',
            "Sec-CH-UA-Mobile": "?1",
            "Sec-CH-UA-Platform": '"Android"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        }
    },
    {
        "name": "Chrome 125 Windows FR",
        "impersonate": "chrome",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-CH-UA": '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        }
    },
]


# ============================================================
# TIMING PROFILES
# ============================================================
TIMING_PROFILES = {
    "none":     {"min_delay": 0,    "max_delay": 0,    "jitter_pct": 0,   "long_pause_chance": 0,    "long_pause_range": (0, 0)},
    "light":    {"min_delay": 0.3,  "max_delay": 0.8,  "jitter_pct": 0.3, "long_pause_chance": 0,    "long_pause_range": (0, 0)},
    "normal":   {"min_delay": 1.0,  "max_delay": 3.0,  "jitter_pct": 0.5, "long_pause_chance": 0.05, "long_pause_range": (5, 15)},
    "paranoid": {"min_delay": 3.0,  "max_delay": 8.0,  "jitter_pct": 0.7, "long_pause_chance": 0.12, "long_pause_range": (10, 30)},
}


class StealthSession:
    """
    Drop-in replacement for requests.Session with full stealth capabilities.
    
    Usage:
        session = StealthSession(stealth_level="normal", proxy="socks5://127.0.0.1:9050")
        r = session.get("https://target.com/path")
        r = session.post("https://target.com/form", data={...})
    """

    def __init__(self, stealth_level="light", proxy=None, proxy_file=None,
                 rotate_ua_every=25, impersonate=None, waf_engine=None):
        """
        Args:
            stealth_level: Timing profile — 'none', 'light', 'normal', 'paranoid'
            proxy: Single proxy URL (http://, socks5://)
            proxy_file: Path to file with one proxy per line for rotation
            rotate_ua_every: Rotate browser profile every N requests
            impersonate: Force a browser TLS fingerprint ('chrome', 'firefox', 'safari', 'edge')
            waf_engine: WAFEngine instance for payload evasion
        """
        self.stealth_level = stealth_level
        self.timing = TIMING_PROFILES.get(stealth_level, TIMING_PROFILES["light"])
        self.waf_engine = waf_engine
        self.impersonate = impersonate
        self.rotate_ua_every = rotate_ua_every

        # ─── Proxy Setup ───
        self.proxies = []
        if proxy:
            self.proxies = [proxy]
        elif proxy_file:
            try:
                with open(proxy_file, 'r') as f:
                    self.proxies = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(f"[{Fore.RED}!{Style.RESET_ALL}] Proxy file not found: {proxy_file}")
        self.proxy_cycle = itertools.cycle(self.proxies) if self.proxies else None

        # ─── Browser Profile Pool ───
        if impersonate:
            self.profiles = [p for p in BROWSER_PROFILES if p["impersonate"] == impersonate]
            if not self.profiles:
                self.profiles = BROWSER_PROFILES  # fallback
        else:
            self.profiles = BROWSER_PROFILES

        self.current_profile = random.choice(self.profiles)
        self.request_count = 0
        self.last_referer = None

        # ─── Internal Session (connection pooling + cookie persistence) ───
        if CURL_CFFI_AVAILABLE:
            self._session = stealth_requests.Session(impersonate=self.current_profile["impersonate"])
        else:
            self._session = raw_requests.Session()

        self._apply_profile()
        self._print_config()

    def _print_config(self):
        tls_engine = f"curl_cffi (JA3: {self.current_profile['impersonate']})" if CURL_CFFI_AVAILABLE else "requests (! detectable TLS)"
        proxy_status = f"{len(self.proxies)} proxies loaded" if self.proxies else "direct (no proxy)"
        print(f"  [{Fore.CYAN}*{Style.RESET_ALL}] Stealth Engine initialized:")
        print(f"      TLS Engine:  {tls_engine}")
        print(f"      Profile:     {self.current_profile['name']}")
        print(f"      Timing:      {self.stealth_level} (delay {self.timing['min_delay']}-{self.timing['max_delay']}s)")
        print(f"      Proxy:       {proxy_status}")
        print(f"      UA Rotation: every {self.rotate_ua_every} requests")

    def _apply_profile(self):
        """Apply current browser profile headers to the session."""
        self._session.headers.clear()
        self._session.headers.update(self.current_profile["headers"])
        self._session.headers["User-Agent"] = self.current_profile["user_agent"]

    def _rotate_profile(self):
        """Rotate to a new random browser profile."""
        old_name = self.current_profile["name"]
        self.current_profile = random.choice(self.profiles)
        self._apply_profile()

        # If using curl_cffi, recreate session with new impersonation
        if CURL_CFFI_AVAILABLE:
            cookies = self._session.cookies
            self._session = stealth_requests.Session(impersonate=self.current_profile["impersonate"])
            self._session.cookies = cookies
            self._apply_profile()

    def _get_proxy_dict(self):
        """Get next proxy from the rotation pool."""
        if not self.proxy_cycle:
            return None
        proxy_url = next(self.proxy_cycle)
        if proxy_url.startswith("socks"):
            return {"http": proxy_url, "https": proxy_url}
        else:
            return {"http": proxy_url, "https": proxy_url}

    def _apply_timing(self):
        """Apply human-like delay with gaussian jitter before a request."""
        if self.timing["min_delay"] == 0 and self.timing["max_delay"] == 0:
            return

        # Base delay with gaussian distribution (more natural than uniform)
        base = random.uniform(self.timing["min_delay"], self.timing["max_delay"])
        jitter = base * self.timing["jitter_pct"] * random.gauss(0, 1)
        delay = max(0.05, base + jitter)

        # Random long pause to break scanning patterns
        if random.random() < self.timing["long_pause_chance"]:
            lo, hi = self.timing["long_pause_range"]
            long_pause = random.uniform(lo, hi)
            delay += long_pause

        time.sleep(delay)

    def _prepare_request(self, url, kwargs):
        """Pre-process a request: rotate UA, set referer, set proxy."""
        self.request_count += 1

        # Rotate browser profile every N requests
        if self.request_count % self.rotate_ua_every == 0:
            self._rotate_profile()

        # Dynamic Referer (looks like natural browsing)
        if self.last_referer:
            self._session.headers["Referer"] = self.last_referer

        # Apply proxy
        if self.proxy_cycle and "proxies" not in kwargs:
            kwargs["proxies"] = self._get_proxy_dict()

        # Ensure timeout
        if "timeout" not in kwargs:
            kwargs["timeout"] = 10

        # Apply timing delay
        self._apply_timing()

        return kwargs

    def _post_request(self, url, response):
        """Post-process: update referer, handle rate limiting."""
        if response is not None:
            self.last_referer = url
            # Auto-handle 429 (Too Many Requests)
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 30))
                time.sleep(min(retry_after, 60))

    # ─── Public API (drop-in replacement for requests) ───

    def get(self, url, **kwargs):
        kwargs = self._prepare_request(url, kwargs)
        try:
            r = self._session.get(url, **kwargs)
            self._post_request(url, r)
            return r
        except Exception as e:
            return _EmptyResponse()

    def post(self, url, **kwargs):
        kwargs = self._prepare_request(url, kwargs)
        try:
            r = self._session.post(url, **kwargs)
            self._post_request(url, r)
            return r
        except Exception:
            return _EmptyResponse()

    def head(self, url, **kwargs):
        kwargs = self._prepare_request(url, kwargs)
        try:
            r = self._session.head(url, **kwargs)
            self._post_request(url, r)
            return r
        except Exception:
            return _EmptyResponse()

    def options(self, url, **kwargs):
        kwargs = self._prepare_request(url, kwargs)
        try:
            r = self._session.options(url, **kwargs)
            self._post_request(url, r)
            return r
        except Exception:
            return _EmptyResponse()

    def request(self, method, url, **kwargs):
        kwargs = self._prepare_request(url, kwargs)
        try:
            r = self._session.request(method, url, **kwargs)
            self._post_request(url, r)
            return r
        except Exception:
            return _EmptyResponse()

    def evade_payload(self, payload):
        """Obfuscate a payload through the WAF engine if available."""
        if self.waf_engine:
            return self.waf_engine.evade(payload)
        return payload

    def get_headers(self):
        """Return current browser headers (useful for async crawler)."""
        headers = dict(self._session.headers)
        return headers

    def get_proxy_url(self):
        """Return a single proxy URL for external use (e.g., aiohttp)."""
        if self.proxy_cycle:
            return next(self.proxy_cycle)
        return None


class _EmptyResponse:
    """Null-object pattern to avoid crashes when a request fails."""
    status_code = 0
    text = ""
    content = b""
    headers = {}

    def json(self):
        return {}
