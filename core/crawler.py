import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from colorama import Fore, Style
import re

class Crawler:
    def __init__(self, base_url, max_depth=3):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.visited = set()
        self.endpoints = set()
        self.forms = []
        self.js_files = set()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    def crawl(self):
        print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Starting crawler on {self.base_url} (depth={self.max_depth})")
        
        # Phase 1: Grab sitemap & robots for extra URLs
        self._parse_robots()
        self._parse_sitemap()
        
        # Phase 2: Crawl known WP paths first
        self._seed_wp_paths()
        
        # Phase 3: Recursive crawl
        self._crawl_recursive(self.base_url, 0)
        
        # Phase 4: Extract URLs from discovered JS files
        self._extract_from_js()
        
        print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] Crawl complete: {len(self.endpoints)} endpoints, {len(self.forms)} forms, {len(self.js_files)} JS files")
        
    def _crawl_recursive(self, url, depth):
        if depth > self.max_depth or url in self.visited:
            return
        
        # Skip non-interesting file extensions
        skip_ext = ('.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.woff', 
                    '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.pdf', '.zip')
        if any(url.lower().endswith(e) for e in skip_ext):
            return
            
        self.visited.add(url)
        self.endpoints.add(url)
        
        try:
            response = self.session.get(url, timeout=8, allow_redirects=True)
            if response.status_code != 200:
                return
            
            content_type = response.headers.get("Content-Type", "")
            if "html" not in content_type:
                return
                
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract forms
            self._extract_forms(url, soup)
            
            # Extract links from <a> tags
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                full_url = urljoin(url, href)
                full_url = full_url.split('#')[0]  # Remove fragments
                
                if urlparse(full_url).netloc == self.domain:
                    self._crawl_recursive(full_url, depth + 1)
            
            # Extract URLs from <script> src
            for script in soup.find_all('script', src=True):
                src = script.get('src')
                if src:
                    full_src = urljoin(url, src)
                    if urlparse(full_src).netloc == self.domain:
                        self.js_files.add(full_src)
                        self.endpoints.add(full_src)
            
            # Extract URLs from <link> href (CSS, etc)
            for link_tag in soup.find_all('link', href=True):
                href = link_tag.get('href')
                full_href = urljoin(url, href)
                if urlparse(full_href).netloc == self.domain:
                    self.endpoints.add(full_href)
            
            # Extract URLs from inline scripts
            for script in soup.find_all('script'):
                if script.string:
                    self._extract_urls_from_text(script.string, url)
            
            # Extract URLs from <iframe> src
            for iframe in soup.find_all('iframe', src=True):
                src = iframe.get('src')
                if src:
                    full_src = urljoin(url, src)
                    if urlparse(full_src).netloc == self.domain:
                        self.endpoints.add(full_src)
            
            # Extract action URLs from forms (even without full form parsing)
            for form in soup.find_all('form', action=True):
                action = form.get('action')
                if action:
                    full_action = urljoin(url, action)
                    if urlparse(full_action).netloc == self.domain:
                        self.endpoints.add(full_action)
                    
        except requests.RequestException:
            pass

    def _extract_forms(self, url, soup):
        for form in soup.find_all('form'):
            form_details = {
                "action": urljoin(url, form.get('action', url)),
                "method": form.get('method', 'get').lower(),
                "inputs": []
            }
            
            # Get all input types
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                if input_name:
                    form_details["inputs"].append({
                        "name": input_name, 
                        "type": input_type,
                        "value": input_tag.get('value', '')
                    })
            
            if form_details not in self.forms:
                self.forms.append(form_details)

    def _parse_robots(self):
        """Parse robots.txt for hidden paths."""
        try:
            r = self.session.get(f"{self.base_url}/robots.txt", timeout=5)
            if r.status_code == 200 and "html" not in r.headers.get("Content-Type", ""):
                for line in r.text.splitlines():
                    line = line.strip()
                    if line.startswith(("Disallow:", "Allow:", "Sitemap:")):
                        path = line.split(":", 1)[1].strip()
                        if path and not path.startswith("http"):
                            full_url = urljoin(self.base_url, path)
                            if urlparse(full_url).netloc == self.domain:
                                self.endpoints.add(full_url)
                        elif path.startswith("http"):
                            if urlparse(path).netloc == self.domain:
                                self.endpoints.add(path)
                                
                print(f"  [{Fore.CYAN}-{Style.RESET_ALL}] Parsed robots.txt")
        except requests.RequestException:
            pass
    
    def _parse_sitemap(self):
        """Parse sitemap.xml for all indexed URLs."""
        sitemap_urls = [
            f"{self.base_url}/sitemap.xml",
            f"{self.base_url}/sitemap_index.xml",
            f"{self.base_url}/wp-sitemap.xml",
        ]
        
        for sitemap_url in sitemap_urls:
            try:
                r = self.session.get(sitemap_url, timeout=5)
                if r.status_code == 200 and "xml" in r.headers.get("Content-Type", ""):
                    # Extract URLs from sitemap
                    urls = re.findall(r'<loc>(.*?)</loc>', r.text)
                    for url in urls:
                        if urlparse(url).netloc == self.domain:
                            self.endpoints.add(url)
                    
                    if urls:
                        print(f"  [{Fore.CYAN}-{Style.RESET_ALL}] Sitemap: found {len(urls)} URLs from {sitemap_url}")
                    
                    # Check for sub-sitemaps
                    sub_sitemaps = [u for u in urls if 'sitemap' in u.lower() and u.endswith('.xml')]
                    for sub in sub_sitemaps[:5]:  # Limit
                        try:
                            r2 = self.session.get(sub, timeout=5)
                            if r2.status_code == 200:
                                sub_urls = re.findall(r'<loc>(.*?)</loc>', r2.text)
                                for url in sub_urls:
                                    if urlparse(url).netloc == self.domain:
                                        self.endpoints.add(url)
                        except requests.RequestException:
                            continue
            except requests.RequestException:
                continue

    def _seed_wp_paths(self):
        """Add common WordPress paths to seed the crawler."""
        wp_paths = [
            "/", "/wp-login.php", "/wp-admin/", "/wp-json/",
            "/wp-json/wp/v2/posts", "/wp-json/wp/v2/pages",
            "/wp-json/wp/v2/users", "/wp-json/wp/v2/categories",
            "/wp-json/wp/v2/tags", "/wp-json/wp/v2/comments",
            "/feed/", "/feed/rss/", "/feed/atom/",
            "/?s=test", "/?p=1", "/?page_id=2",
            "/wp-content/", "/wp-includes/",
            "/xmlrpc.php", "/wp-cron.php",
            "/wp-signup.php", "/wp-trackback.php",
            "/wp-links-opml.php", "/readme.html",
        ]
        
        for path in wp_paths:
            url = self.base_url + path
            self.endpoints.add(url)

    def _extract_urls_from_text(self, text, base_url):
        """Extract URLs from JS/text content."""
        # Match quoted strings that look like paths or URLs
        patterns = [
            r'["\'](/[a-zA-Z0-9_\-/]+(?:\.[a-zA-Z]{2,4})?)["\']',
            r'["\'](\./[a-zA-Z0-9_\-/]+)["\']',
            r'["\'](https?://[^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                if match.startswith('http'):
                    if urlparse(match).netloc == self.domain:
                        self.endpoints.add(match)
                elif match.startswith('/') or match.startswith('./'):
                    full_url = urljoin(base_url, match)
                    if urlparse(full_url).netloc == self.domain:
                        self.endpoints.add(full_url)

    def _extract_from_js(self):
        """Download JS files and extract API endpoints from them."""
        if not self.js_files:
            return
            
        print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Extracting URLs from {len(self.js_files)} JS files...")
        
        for js_url in list(self.js_files)[:20]:  # Limit to 20 JS files
            try:
                r = self.session.get(js_url, timeout=5)
                if r.status_code == 200:
                    self._extract_urls_from_text(r.text, js_url)
            except requests.RequestException:
                continue

    def get_endpoints(self):
        return list(self.endpoints)
        
    def get_forms(self):
        return self.forms
