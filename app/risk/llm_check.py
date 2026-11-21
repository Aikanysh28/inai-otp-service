"""Проверка LLM-провайдеров из окружения:  python3 -m app.risk.llm_check

Для каждого провайдера цепочки (RISK_LLM_PROVIDERS или RISK_LLM_API_KEY):
есть ли ключ, GET {base_url}/models (код ответа и до 20 подходящих моделей), пробный вызов
на сюжете demo_story с замером времени, прошёл ли ответ проверку фактов, итоговый текст.
Ключи не печатаются. Код выхода 0 — хотя бы один провайдер дал принятый ответ.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from typing import Optional

from .config import RiskSettings
from .engine import RiskEngine
from .llm import (
    PRESETS, USER_AGENT, LLMError, LLMProvider, complete, configured_names,
    providers_from_settings,
)
from .simulate import FakeClock, demo_story
from .summary import LLM_SYSTEM, SummaryService, fact_check

MODEL_HINTS = ("flash", "llama", "qwen", "gpt-oss", "free")
REASONS_RU = {"network": "нет сети или ошибка сервера", "auth": "неверный ключ",
              "rate_limited": "лимит провайдера", "bad_response": "некорректный ответ",
              "timeout": "превышено время ожидания"}


def list_models(provider: LLMProvider, timeout: float) -> tuple[Optional[int], list[str]]:
    headers = {"Authorization": "Bearer " + provider.key} if provider.key else {}
    if provider.kind == "anthropic":
        headers = {"x-api-key": provider.key, "anthropic-version": "2023-06-01"}
    headers["User-Agent"] = USER_AGENT
    request = urllib.request.Request(provider.base_url + "/models", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status, data = response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, []
    except (OSError, ValueError):
        return None, []
    items = data.get("data", data.get("models", [])) if isinstance(data, dict) else []
    ids = [str(item.get("id") or item.get("name", "")) for item in items if isinstance(item, dict)]
    return status, [i for i in ids if any(h in i.lower() for h in MODEL_HINTS)][:20]


def main() -> int:
    settings = RiskSettings.from_env(read_env_file=True)  # как сервер: + RISK_* из .env
    names = configured_names(settings)
    chain = providers_from_settings(settings)
    if not names:
        print("LLM выключена: задайте RISK_LLM_PROVIDERS (например, groq) "
              "и ключ RISK_LLM_GROQ_KEY.")
        return 1
    print(f"Цепочка из окружения: {', '.join(names)} · таймаут {settings.llm_timeout:g} с")
    active = {p.name for p in chain}
    for name in names:
        if name not in PRESETS:
            print(f"  {name}: неизвестный пресет — пропущен")
        elif name not in active:
            print(f"  {name}: ключ задан: нет — провайдер пропускается")

    engine = RiskEngine(settings, clock=FakeClock(), id_key=b"llm-check")
    demo_story(engine.sink, engine.clock)
    service: SummaryService = engine._summary
    payload, aliases = service.llm_payload(service.facts(3600))
    user = json.dumps(payload, ensure_ascii=False)
    print(f"Пробные данные: demo_story, инцидентов {payload['incidents_count']}, "
          "IP под псевдонимами")

    accepted_any = False
    for provider in chain:
        print(f"\n=== {provider.name} · {provider.model} · {provider.base_url}")
        print(f"  ключ задан: {'да' if provider.has_key else 'нет (не нужен)'}")
        status, models = list_models(provider, settings.llm_timeout)
        print(f"  GET /models: {status if status is not None else 'нет ответа'}"
              + (f" · модели: {', '.join(models)}" if models else ""))
        started = time.monotonic()
        try:
            text = complete(provider, LLM_SYSTEM, user, settings.llm_timeout,
                            urllib.request.urlopen)
        except LLMError as error:
            print(f"  пробный вызов: ошибка — {REASONS_RU.get(error.kind, error.kind)} ({error})")
            continue
        elapsed = time.monotonic() - started
        checked = fact_check(text, payload, aliases)
        verdict = "пройдена" if checked else "НЕ пройдена"
        print(f"  пробный вызов: {elapsed:.1f} с · проверка фактов: {verdict}")
        answer = service.restore_ips(checked or text, aliases)
        print("  ответ:", answer.replace("\n", "\n         "))
        accepted_any |= checked is not None
    print("\nИТОГ:", "есть принятый ответ" if accepted_any
          else "ни один провайдер не дал принятый ответ")
    return 0 if accepted_any else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
