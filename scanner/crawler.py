import asyncio
import logging
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Optional, Set

import aiohttp
from bs4 import BeautifulSoup

from scanner.injections import InjectionTester
from scanner.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


class AsyncCrawler:
    def __init__(self, base_url: str, max_pages: int = 20, concurrency: int = 5, timeout: int = 10):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.max_pages = max_pages
        self.concurrency = concurrency
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.visited: Set[str] = set()
        self.vulnerabilities: List[Vulnerability] = []
        self.session: Optional[aiohttp.ClientSession] = None
        self.tester = InjectionTester(self)

    async def _fetch(self, url: str, method: str = 'get', **kwargs) -> str:
        try:
            async with self.session.request(method, url, timeout=self.timeout, **kwargs) as resp:
                return await resp.text()
        except Exception as e:
            logger.debug(f"Request failed: {url} – {e}")
            return ""

    async def get_forms(self, url: str, html: str) -> List[Dict]:
        """Парсит HTML и возвращает список форм."""
        soup = BeautifulSoup(html, 'html.parser')
        forms = []
        for form in soup.find_all('form'):
            action = form.get('action') or ''
            method = form.get('method', 'get').lower()
            inputs = []
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name')
                if name:
                    inputs.append({
                        'name': name,
                        'type': inp.get('type', 'text').lower() if inp.name == 'input' else inp.name
                    })
            if inputs:
                forms.append({
                    'action': urljoin(url, action),
                    'method': method,
                    'inputs': inputs
                })
        return forms

    async def scan_page(self, url: str):
        """Проверяет одну страницу: получает формы и тестирует их."""
        if url in self.visited or len(self.visited) >= self.max_pages:
            return
        self.visited.add(url)
        logger.info(f"Scanning {url}")

        html = await self._fetch(url)
        if not html:
            return

        forms = await self.get_forms(url, html)
        for form in forms:
            # SQLi
            sqli = await self.tester.test_sqli(url, form)
            if sqli:
                self.vulnerabilities.append(sqli)
                logger.warning(f"SQLi found: {sqli.detail}")

            # XSS
            xss = await self.tester.test_xss(url, form)
            if xss:
                self.vulnerabilities.append(xss)
                logger.warning(f"XSS found: {xss.detail}")

            # Blind SQLi (time-based)
            blind = await self.tester.test_blind_sqli(url, form)
            if blind:
                self.vulnerabilities.append(blind)
                logger.warning(f"Blind SQLi found: {blind.detail}")

        # Продолжаем краулинг по ссылкам
        soup = BeautifulSoup(html, 'html.parser')
        links = []
        for a in soup.find_all('a', href=True):
            link = urljoin(url, a['href'])
            if urlparse(link).netloc == self.domain and link not in self.visited:
                links.append(link)

        # Ограничиваем параллелизм
        sem = asyncio.Semaphore(self.concurrency)
        async def bounded_scan(link):
            async with sem:
                await self.scan_page(link)

        tasks = [bounded_scan(link) for link in links[:self.max_pages - len(self.visited)]]
        if tasks:
            await asyncio.gather(*tasks)

    async def run(self) -> List['Vulnerability']:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0'
        }
        async with aiohttp.ClientSession(headers=headers) as session:
            self.session = session
            await self.scan_page(self.base_url)
        return self.vulnerabilities
