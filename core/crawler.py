import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style
import re

class Crawler:
    def __init__(self, base_url, max_depth=3, max_concurrent=20):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.max_concurrent = max_concurrent
        self.visited = set()
        self.endpoints = set()
        self.forms = []
        self.js_files = set()
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

    def crawl(self):
        print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Starting Async crawler on {self.base_url} (depth={self.max_depth})")
        asyncio.run(self._async_crawl())
        print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] Crawl complete: {len(self.endpoints)} endpoints, {len(self.forms)} forms, {len(self.js_files)} JS files")

    async def _fetch_with_retry(self, session, url, retries=3):
        for attempt in range(retries):
            try:
                async with session.get(url, timeout=8, allow_redirects=True) as response:
                    if response.status == 429:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    text = await response.text()
                    return response.status, response.headers, text
            except (aiohttp.ClientError, asyncio.TimeoutError):
                await asyncio.sleep(1)
        return None, None, None

    async def _async_crawl(self):
        async with aiohttp.ClientSession(headers=self.headers) as session:
            await self._parse_robots(session)
            await self._parse_sitemap(session)
            self._seed_wp_paths()
            
            queue = asyncio.Queue()
            queue.put_nowait((self.base_url, 0))
            
            workers = [asyncio.create_task(self._worker(session, queue)) for _ in range(self.max_concurrent)]
            await queue.join()
            for w in workers:
                w.cancel()
                
            await self._extract_from_js(session)

    async def _worker(self, session, queue):
        while True:
            url, depth = await queue.get()
            try:
                if depth <= self.max_depth and url not in self.visited:
                    await self._process_url(session, url, depth, queue)
            finally:
                queue.task_done()

    async def _process_url(self, session, url, depth, queue):
        skip_ext = ('.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.woff', 
                    '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.pdf', '.zip')
        if any(url.lower().endswith(e) for e in skip_ext):
            return
            
        self.visited.add(url)
        self.endpoints.add(url)
        
        status, headers, text = await self._fetch_with_retry(session, url)
        if status != 200 or not text:
            return
            
        content_type = headers.get("Content-Type", "")
        if "html" not in content_type:
            return
            
        soup = BeautifulSoup(text, 'html.parser')
        self._extract_forms(url, soup)
        
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            full_url = urljoin(url, href).split('#')[0]
            if urlparse(full_url).netloc == self.domain and full_url not in self.visited:
                queue.put_nowait((full_url, depth + 1))
                
        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src:
                full_src = urljoin(url, src)
                if urlparse(full_src).netloc == self.domain:
                    self.js_files.add(full_src)
                    self.endpoints.add(full_src)
                    
        for link_tag in soup.find_all('link', href=True):
            href = link_tag.get('href')
            full_href = urljoin(url, href)
            if urlparse(full_href).netloc == self.domain:
                self.endpoints.add(full_href)
                
        for script in soup.find_all('script'):
            if script.string:
                self._extract_urls_from_text(script.string, url)
                
        for iframe in soup.find_all('iframe', src=True):
            src = iframe.get('src')
            if src:
                full_src = urljoin(url, src)
                if urlparse(full_src).netloc == self.domain:
                    self.endpoints.add(full_src)
                    
        for form in soup.find_all('form', action=True):
            action = form.get('action')
            if action:
                full_action = urljoin(url, action)
                if urlparse(full_action).netloc == self.domain:
                    self.endpoints.add(full_action)

    def _extract_forms(self, url, soup):
        for form in soup.find_all('form'):
            form_details = {
                "action": urljoin(url, form.get('action', url)),
                "method": form.get('method', 'get').lower(),
                "inputs": []
            }
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

    async def _parse_robots(self, session):
        status, headers, text = await self._fetch_with_retry(session, f"{self.base_url}/robots.txt")
        if status == 200 and text and "html" not in headers.get("Content-Type", ""):
            for line in text.splitlines():
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

    async def _parse_sitemap(self, session):
        sitemap_urls = [
            f"{self.base_url}/sitemap.xml",
            f"{self.base_url}/sitemap_index.xml",
            f"{self.base_url}/wp-sitemap.xml",
        ]
        for sitemap_url in sitemap_urls:
            status, headers, text = await self._fetch_with_retry(session, sitemap_url)
            if status == 200 and text and "xml" in headers.get("Content-Type", ""):
                urls = re.findall(r'<loc>(.*?)</loc>', text)
                for url in urls:
                    if urlparse(url).netloc == self.domain:
                        self.endpoints.add(url)
                if urls:
                    print(f"  [{Fore.CYAN}-{Style.RESET_ALL}] Sitemap: found {len(urls)} URLs from {sitemap_url}")
                
                sub_sitemaps = [u for u in urls if 'sitemap' in u.lower() and u.endswith('.xml')]
                for sub in sub_sitemaps[:5]:
                    s_status, s_headers, s_text = await self._fetch_with_retry(session, sub)
                    if s_status == 200 and s_text:
                        sub_urls = re.findall(r'<loc>(.*?)</loc>', s_text)
                        for url in sub_urls:
                            if urlparse(url).netloc == self.domain:
                                self.endpoints.add(url)

    def _seed_wp_paths(self):
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
            self.endpoints.add(self.base_url + path)

    def _extract_urls_from_text(self, text, base_url):
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

    async def _extract_from_js(self, session):
        if not self.js_files:
            return
        print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Extracting URLs from {len(self.js_files)} JS files...")
        
        async def fetch_and_extract(js_url):
            status, _, text = await self._fetch_with_retry(session, js_url)
            if status == 200 and text:
                self._extract_urls_from_text(text, js_url)
                
        tasks = [fetch_and_extract(url) for url in list(self.js_files)[:20]]
        await asyncio.gather(*tasks)

    def get_endpoints(self):
        return list(self.endpoints)
        
    def get_forms(self):
        return self.forms
