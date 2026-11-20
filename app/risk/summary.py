"""Сводка инцидента для дежурного: шаблон по агрегатам движка и (по желанию) пересказ через LLM.

Шаблон работает всегда. LLM включается, только если задан RISK_LLM_API_KEY: в Anthropic
Messages API уходит лишь JSON с агрегатами (IP, баллы, маски номеров, счётчики) — без полных
номеров, кодов и сырых событий. Любая ошибка, отказ или таймаут — возвращается шаблон.
Ответ кешируется на llm_cache_seconds, вызов идёт только по запросу /api/risk/summary.
"""
from __future__ import annotations

import hashlib
import json
import threading
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Callable, Optional

if TYPE_CHECKING:  # pragma: no cover
    from .engine import RiskEngine

LLM_URL = "https://api.anthropic.com/v1/messages"
LLM_VERSION = "2023-06-01"
LLM_SYSTEM = ("Ты помогаешь дежурному администратору OTP-сервиса. Тебе дают JSON с агрегатами "
              "модуля оценки рисков. Перепиши это для дежурного администратора на русском, "
              "3–5 предложений, используй только факты из JSON, ничего не добавляй. "
              "Без markdown-разметки.")

INCIDENT_TITLES = {
    "pumping": "SMS pumping",
    "bruteforce": "подбор кода к номеру",
    "distributed": "распределённый подбор",
    "suspicious": "подозрительная активность",
}
LEVEL_RU = {"low": "низкий", "medium": "средний", "high": "высокий"}


def make_node_id(msisdn_id: str) -> str:
    """Короткий непрозрачный id узла номера для графа (из псевдонима, не из номера)."""
    return hashlib.sha256(msisdn_id.encode()).hexdigest()[:12]


def incident_type(reasons: list[str]) -> str:
    names = set(reasons)
    if {"fan_out", "sequential", "no_conversion"} <= names and not names & {"fail_rate", "ip_limited"}:
        return "pumping"
    if "fan_out" in names and names & {"fail_rate", "ip_limited"}:
        return "distributed"
    if {"fail_rate", "hammering_locked"} <= names:
        return "bruteforce"
    return "suspicious"


def _plural(n: int, one: str, few: str, many: str) -> str:
    if n % 10 == 1 and n % 100 != 11:
        return one
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return few
    return many


def _num(value: float) -> str:
    return f"{value:g}" if isinstance(value, float) else str(value)


class SummaryService:
    def __init__(self, engine: "RiskEngine", opener: Optional[Callable[..., Any]] = None):
        self.engine = engine
        self.opener = opener or urllib.request.urlopen
        self._cache: dict[int, tuple[float, dict]] = {}
        self._lock = threading.Lock()
        self.llm_calls = 0

    # ---------- агрегаты и шаблон ----------

    def facts(self, window: int) -> dict:
        """Всё, что знает сводка: только агрегаты, без полных номеров и сырых событий."""
        engine, s = self.engine, self.engine.settings
        now = engine.clock()
        overview = engine.overview(window=window)
        tz = timezone(timedelta(hours=s.tz_offset_hours))
        fmt = lambda ts: datetime.fromtimestamp(ts, tz).strftime("%H:%M")  # noqa: E731
        return {
            "period": {"from": fmt(now - window), "to": fmt(now), "timezone": "Бишкек (UTC+6)",
                       "minutes": round(window / 60)},
            "threat_level": overview["threat_level"],
            "sms_sent": overview["sms_sent"],
            "sms_suspicious": overview["sms_suspicious"],
            "sms_cost_suspicious": overview["sms_cost_suspicious"],
            "currency": s.currency,
            "conversion": overview["conversion"],
            "mode": "наблюдение: модуль не меняет ответы сервиса",
            "incidents": [{**incident, "title": INCIDENT_TITLES[incident["type"]],
                           "time": fmt(incident["first_seen"])}
                          for incident in engine.incidents(window=window)],
        }

    def template(self, facts: dict) -> str:
        p, cur = facts["period"], facts["currency"]
        lines = [f"Период {p['from']}–{p['to']} по Бишкеку ({p['minutes']} мин). "
                 f"Общий уровень угрозы: {LEVEL_RU.get(facts['threat_level'], facts['threat_level'])}."]
        conversion = ("—" if facts["conversion"] is None
                      else f"{round(facts['conversion'] * 100)}%")
        lines.append(f"Отправлено SMS: {facts['sms_sent']}, из них подозрительных: "
                     f"{facts['sms_suspicious']} (≈{_num(facts['sms_cost_suspicious'])} {cur}). "
                     f"Конверсия: {conversion}.")
        incidents = facts["incidents"]
        if not incidents:
            lines.append("Инцидентов уровня «средний» и «высокий» нет.")
            return "\n".join(lines)
        lines.append(f"Инцидентов: {len(incidents)}.")
        for i, inc in enumerate(incidents, 1):
            parts = [f"{i}. {inc['title'][:1].upper() + inc['title'][1:]} с IP {inc['ip']} (с {inc['time']}): "
                     f"балл {inc['score']}, уровень {LEVEL_RU.get(inc['level'], inc['level'])}"]
            n = inc["numbers"]
            numbers = f"{n} {_plural(n, 'номер', 'номера', 'номеров')}"
            if inc["number_range"]:
                numbers += f" подряд, от {inc['number_range']['first']} до {inc['number_range']['last']}"
            parts.append(numbers)
            if inc["sms_sent"]:
                parts.append(f"SMS: {inc['sms_sent']} (≈{_num(inc['sms_cost'])} {cur})")
            if inc["verify_attempts"]:
                parts.append(f"попыток ввода кода: {inc['verify_attempts']}")
            fh = inc["first_high"]
            if fh:
                detected = f"тревога «высокий» через {round(fh['after_seconds'])} с"
                if fh["at_number"]:
                    detected += f", на {fh['at_number']}-м номере"
                parts.append(detected)
            parts.append("причины: " + "; ".join(r["detail"] for r in inc["reasons"]))
            parts.append(f"в боевом режиме: {inc['would_action_text']}")
            lines.append(", ".join(parts[:2]) + ". " + "; ".join(parts[2:]) + ".")
        lines.append("Рекомендации: " + "; ".join(self._recommendations(incidents)) + ".")
        return "\n".join(lines)

    @staticmethod
    def _recommendations(incidents: list[dict]) -> list[str]:
        kinds = {inc["type"] for inc in incidents}
        tips = []
        if "pumping" in kinds:
            tips.append("включить лимит send по IP и подсети и проверку конверсии по диапазонам номеров")
        if kinds & {"bruteforce", "distributed"}:
            tips.append("проверить атакующие IP и при повторе включить режим блокировки (enforce)")
        if not tips:
            tips.append("продолжать наблюдение, при повторе проверить IP вручную")
        return tips

    # ---------- LLM ----------

    def llm_request(self, facts: dict) -> urllib.request.Request:
        s = self.engine.settings
        body = {
            "model": s.llm_model,
            "max_tokens": 1024,
            "system": LLM_SYSTEM,
            "output_config": {"effort": "low"},
            "messages": [{"role": "user", "content": json.dumps(facts, ensure_ascii=False)}],
        }
        return urllib.request.Request(
            LLM_URL, data=json.dumps(body, ensure_ascii=False).encode("utf-8"), method="POST",
            headers={"x-api-key": s.llm_api_key, "anthropic-version": LLM_VERSION,
                     "content-type": "application/json"})

    def _call_llm(self, facts: dict) -> Optional[str]:
        """Текст от LLM или None (ошибка, отказ, пустой ответ, таймаут)."""
        timeout = self.engine.settings.llm_timeout
        result: dict[str, Optional[str]] = {"text": None}

        def run() -> None:
            try:
                with self.opener(self.llm_request(facts), timeout=timeout) as response:
                    data = json.loads(response.read().decode("utf-8"))
                if data.get("stop_reason") == "refusal":
                    return
                # У Haiku 5.5 размышление включено по умолчанию: берём только текстовые блоки
                text = "".join(block.get("text", "") for block in data.get("content", [])
                               if block.get("type") == "text").strip()
                result["text"] = text or None
            except Exception:  # noqa: BLE001 — любая ошибка LLM означает шаблон
                result["text"] = None

        self.llm_calls += 1
        worker = threading.Thread(target=run, name="risk-llm", daemon=True)
        worker.start()
        worker.join(timeout)  # «висящий» вызов не задерживает ответ дольше таймаута
        return result["text"] if not worker.is_alive() else None

    def summarize(self, window: int = 600) -> dict:
        s = self.engine.settings
        use_llm = bool(s.llm_api_key)
        now = self.engine.clock()
        if use_llm:
            with self._lock:
                cached = self._cache.get(window)
                if cached and now - cached[0] < s.llm_cache_seconds:
                    return dict(cached[1], cached=True)
        facts = self.facts(window)
        text, source = self.template(facts), "template"
        if use_llm:
            llm_text = self._call_llm(facts)
            if llm_text:
                text, source = llm_text, "llm"
        answer = {"text": text, "incidents": facts["incidents"], "source": source,
                  "generated_at": round(now, 3), "window": window, "cached": False}
        if use_llm:
            with self._lock:
                self._cache[window] = (now, answer)
        return answer

