import os
import logging
import requests
from typing import List
from scanner.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"


def generate_ai_report(vulns: List[Vulnerability], target: str) -> str:
    if not DEEPSEEK_API_KEY:
        return "⚠️  API-ключ DeepSeek не задан (переменная DEEPSEEK_API_KEY). Отчёт не сгенерирован."

    if not vulns:
        return "✅ Уязвимости не обнаружены. Отличная работа!"

    # Формируем промпт
    vuln_text = "\n".join(
        f"- URL: {v.url}\n  Тип: {v.vuln_type}\n  Детали: {v.detail}"
        for v in vulns
    )
    prompt = f"""Ты – эксперт по кибербезопасности. Проанализируй следующий отчёт сканера уязвимостей для сайта {target}.

Найдены уязвимости:
{vuln_text}

Создай структурированный отчёт на русском языке:
1. Краткое резюме
2. Детальное описание каждой уязвимости (как она работает, риски)
3. Конкретные рекомендации по исправлению для каждой
4. Общие рекомендации по защите веб-приложения"""

    headers = {
        "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "deepseek-chat",
        "messages": [
            {"role": "system", "content": "Ты – помощник по кибербезопасности. Отвечай на русском."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.3,
        "max_tokens": 2000
    }

    try:
        resp = requests.post(DEEPSEEK_API_URL, headers=headers, json=payload, timeout=30)
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"]
        else:
            return f"Ошибка API DeepSeek: {resp.status_code} – {resp.text}"
    except Exception as e:
        return f"Ошибка при вызове DeepSeek: {e}"
