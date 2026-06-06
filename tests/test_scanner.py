import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlparse

from scanner.crawler import AsyncCrawler
from scanner.injections import InjectionTester
from scanner.vulnerability import Vulnerability
from scanner.ai_reporter import generate_ai_report


# ------------------------------------------------------------
# Тесты для Vulnerability (dataclass)
# ------------------------------------------------------------
class TestVulnerability:
    def test_to_dict(self):
        v = Vulnerability(url="http://test.com", vuln_type="SQLi", detail="Тест", evidence="<script>")
        d = v.to_dict()
        assert d["url"] == "http://test.com"
        assert d["vuln_type"] == "SQLi"
        assert d["detail"] == "Тест"
        assert d["evidence"] == "<script>"

    def test_to_dict_no_evidence(self):
        v = Vulnerability(url="http://test.com", vuln_type="XSS", detail="Без evidence")
        d = v.to_dict()
        assert d["evidence"] is None


# ------------------------------------------------------------
# Тесты для InjectionTester (с моками HTTP)
# ------------------------------------------------------------
@pytest.mark.asyncio
class TestInjectionTester:

    async def test_sqli_found(self):
        """Проверка, что SQLi определяется при наличии ошибки в ответе."""
        # Создаём мок краулера, у которого _fetch возвращает текст с SQL-ошибкой
        mock_crawler = MagicMock()
        mock_crawler._fetch = AsyncMock(return_value="... you have an error in your sql syntax ...")

        tester = InjectionTester(mock_crawler)
        form = {
            "action": "http://test.com/login",
            "method": "post",
            "inputs": [{"name": "user", "type": "text"}]
        }
        vuln = await tester.test_sqli(url="http://test.com", form=form)
        assert vuln is not None
        assert vuln.vuln_type == "SQL Injection"
        assert "user" in vuln.detail

    async def test_sqli_not_found(self):
        """Если ответ без ошибок, уязвимости быть не должно."""
        mock_crawler = MagicMock()
        mock_crawler._fetch = AsyncMock(return_value="Welcome! User logged in.")

        tester = InjectionTester(mock_crawler)
        form = {
            "action": "http://test.com/login",
            "method": "post",
            "inputs": [{"name": "user", "type": "text"}]
        }
        vuln = await tester.test_sqli(url="http://test.com", form=form)
        assert vuln is None

    async def test_xss_found(self):
        """Проверка, что XSS определяется при отражении пейлоада."""
        mock_crawler = MagicMock()
        mock_crawler._fetch = AsyncMock(return_value='Hello <script>alert("XSS")</script>')

        tester = InjectionTester(mock_crawler)
        form = {
            "action": "http://test.com/search",
            "method": "get",
            "inputs": [{"name": "q", "type": "text"}]
        }
        vuln = await tester.test_xss(url="http://test.com", form=form)
        assert vuln is not None
        assert vuln.vuln_type == "Reflected XSS"

    async def test_xss_not_found(self):
        """Если пейлоад не отражается, XSS нет."""
        mock_crawler = MagicMock()
        mock_crawler._fetch = AsyncMock(return_value="Search results for safe input")

        tester = InjectionTester(mock_crawler)
        form = {
            "action": "http://test.com/search",
            "method": "get",
            "inputs": [{"name": "q", "type": "text"}]
        }
        vuln = await tester.test_xss(url="http://test.com", form=form)
        assert vuln is None

    async def test_blind_sqli_found(self):
        """Проверка time-based: если ответ пришёл через 5 секунд, то уязвимость."""
        mock_crawler = MagicMock()
        # Имитируем задержку 5 сек при _fetch
        async def slow_fetch(*args, **kwargs):
            import asyncio
            await asyncio.sleep(5)
            return "normal page"
        mock_crawler._fetch = slow_fetch

        tester = InjectionTester(mock_crawler)
        form = {
            "action": "http://test.com/login",
            "method": "post",
            "inputs": [{"name": "user", "type": "text"}]
        }
        vuln = await tester.test_blind_sqli(url="http://test.com", form=form)
        assert vuln is not None
        assert vuln.vuln_type == "Blind SQL Injection (Time-based)"

    async def test_blind_sqli_not_found(self):
        """Если ответ пришёл быстро, уязвимости нет."""
        mock_crawler = MagicMock()
        mock_crawler._fetch = AsyncMock(return_value="fast reply")

        tester = InjectionTester(mock_crawler)
        form = {
            "action": "http://test.com/login",
            "method": "post",
            "inputs": [{"name": "user", "type": "text"}]
        }
        vuln = await tester.test_blind_sqli(url="http://test.com", form=form)
        assert vuln is None


# ------------------------------------------------------------
# Тесты для AsyncCrawler (функции _fetch, get_forms, is_same_origin)
# ------------------------------------------------------------
@pytest.mark.asyncio
class TestAsyncCrawler:

    async def test_get_forms(self):
        """Проверка, что get_forms корректно извлекает формы из HTML."""
        html = """
        <html>
        <form action="/login" method="post">
            <input name="username" type="text">
            <input name="password" type="password">
            <button type="submit">Войти</button>
        </form>
        <form action="/search" method="get">
            <input name="q" type="text">
        </form>
        </html>
        """
        # Создаём crawler, но не запускаем его (сессия не нужна для парсинга)
        crawler = AsyncCrawler("http://test.com", max_pages=1, concurrency=1)
        # напрямую вызываем get_forms
        forms = await crawler.get_forms("http://test.com/", html)
        assert len(forms) == 2
        # Первая форма
        assert forms[0]["action"] == "http://test.com/login"
        assert forms[0]["method"] == "post"
        assert len(forms[0]["inputs"]) == 2
        # Вторая форма
        assert forms[1]["action"] == "http://test.com/search"
        assert forms[1]["method"] == "get"
        assert forms[1]["inputs"][0]["name"] == "q"

    async def test_get_forms_no_forms(self):
        """Если HTML без форм, возвращается пустой список."""
        crawler = AsyncCrawler("http://test.com")
        forms = await crawler.get_forms("http://test.com/", "<html><body>No forms</body></html>")
        assert forms == []

    def test_domain_check(self):
        """Проверка, что краулер правильно определяет свой домен."""
        crawler = AsyncCrawler("http://example.com")
        assert crawler.domain == "example.com"
        # URL другого домена
        assert urlparse("http://evil.com").netloc != crawler.domain


# ------------------------------------------------------------
# Тесты для AI-репортера (мокаем requests)
# ------------------------------------------------------------
class TestAiReporter:

    @patch("scanner.ai_reporter.requests.post")
    def test_generate_ai_report_success(self, mock_post):
        """Проверяем, что при успешном ответе API возвращается текст отчёта."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "Рекомендации: исправить SQL-инъекции."}}]
        }
        mock_post.return_value = mock_response

        vulns = [
            Vulnerability(url="http://test.com", vuln_type="SQLi", detail="параметр id")
        ]
        result = generate_ai_report(vulns, "http://test.com")
        assert "Рекомендации" in result

    @patch("scanner.ai_reporter.requests.post")
    def test_generate_ai_report_error(self, mock_post):
        """Проверяем обработку ошибки API."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_post.return_value = mock_response

        vulns = [Vulnerability(url="http://test.com", vuln_type="XSS", detail="test")]
        result = generate_ai_report(vulns, "http://test.com")
        assert "Ошибка" in result

    def test_generate_ai_report_no_key(self):
        """Если ключ не задан, возвращается сообщение об ошибке."""
        with patch.dict("os.environ", {"DEEPSEEK_API_KEY": ""}):
            # перезагрузить модуль, чтобы считать пустой ключ? 
            # проще: напрямую проверить условие в функции
            # но функция читает ключ при импорте, поэтому лучше проверить через mock
            from scanner import ai_reporter
            original_key = ai_reporter.DEEPSEEK_API_KEY
            ai_reporter.DEEPSEEK_API_KEY = ""
            result = ai_reporter.generate_ai_report([], "http://test.com")
            assert "не задан" in result
            ai_reporter.DEEPSEEK_API_KEY = original_key  # восстановить

    def test_generate_ai_report_no_vulns(self):
        """Если уязвимостей нет, отчёт говорит об этом."""
        result = generate_ai_report([], "http://test.com")
        assert "не обнаружены" in result
