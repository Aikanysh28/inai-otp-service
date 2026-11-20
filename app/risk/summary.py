"""Сводка инцидента для дежурного: шаблон по агрегатам движка и (по желанию) пересказ через LLM.

Шаблон работает всегда. LLM включается цепочкой провайдеров (RISK_LLM_PROVIDERS, см. llm.py)
или, как раньше, одним RISK_LLM_API_KEY (Anthropic). Наружу уходит только JSON с агрегатами:
IP заменены псевдонимами IP-1, IP-2, номера — маски диапазонов, без кодов и сырых событий.
Ответ модели принимается после проверки фактов (только числа и псевдонимы из входного JSON),
иначе — следующий провайдер или шаблон. Кеш — llm_cache_seconds; вызов только по запросу
/api/risk/summary, никогда в потоке OTP-запросов.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Callable, Optional

from .llm import LLMChain, configured_names, providers_from_settings
from .signals import ACTION_TITLES, LEVEL_TITLES, classify

if TYPE_CHECKING:  # pragma: no cover
    from .engine import RiskEngine

LLM_SYSTEM = ("Ты помощник дежурного администратора OTP-сервиса. Перескажи инциденты из JSON "
              "на русском языке, 3–5 предложений, без списков и разметки. Используй только факты "
              "и числа из JSON, ничего не добавляй и не округляй. Называй IP так же, как в JSON "
              "(IP-1, IP-2). Для каждого инцидента: тип атаки, источник, масштаб, потери, когда "
              "обнаружен, что было бы сделано в боевом режиме.")

LEVEL_RU = {level: title.lower() for level, title in LEVEL_TITLES.items()}


def make_node_id(msisdn_id: str) -> str:
    """Короткий непрозрачный id узла номера для графа (из псевдонима, не из номера)."""
    return hashlib.sha256(msisdn_id.encode()).hexdigest()[:12]


LEGACY_TYPES = {"sms_pumping": "pumping", "code_bruteforce": "bruteforce",
                "distributed_bruteforce": "distributed", "suspicious": "suspicious",
                "none": "suspicious"}


def incident_type(reasons: list[str]) -> str:
    """Старый код типа (поле type сводки) — через общий классификатор signals.classify."""
    return LEGACY_TYPES[classify(reasons, "medium")]


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
        s = engine.settings
        # opener читается при каждом вызове: тесты подменяют service.opener после создания
        self.chain = LLMChain(providers_from_settings(s), s.llm_timeout, lambda: self.opener)
        self.last_request: Optional[str] = None  # тело последнего запроса к LLM (для проверки)

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
            "incidents": [{**incident, "title": incident["incident_title"],
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
            lines.append("За период инцидентов не обнаружено.")
            return "\n".join(lines)
        lines.append(f"Инцидентов: {len(incidents)}.")
        for i, inc in enumerate(incidents, 1):
            parts = [f"{i}. {inc['title']} с IP {inc['ip']} (с {inc['time']}): "
                     f"риск {inc['score']} / 100, уровень {LEVEL_RU.get(inc['level'], inc['level'])}"]
            n = inc["numbers"]
            numbers = f"{n} {_plural(n, 'номер', 'номера', 'номеров')}"
            if inc["number_range"]:
                numbers += f" подряд, от {inc['number_range']['first']} до {inc['number_range']['last']}"
            parts.append(numbers)
            if inc["sms_sent"]:
                parts.append(f"SMS: {inc['sms_sent']} (≈{_num(inc['sms_cost'])} {cur})")
            if inc["verify_attempts"]:
                parts.append(f"попыток ввода кода: {inc['verify_attempts']}")
            moment = inc["first_high"] or inc.get("detected")
            if moment:
                level = "критический" if inc["first_high"] else "средний"
                detected = f"обнаружен ({level} риск) через {round(moment['after_seconds'])} с"
                if inc["incident_type"] == "sms_pumping" and moment["at_number"]:
                    detected += f", на {moment['at_number']}-м номере"
                parts.append(detected)
            parts.append("признаки: " + "; ".join(f"{r['title'].lower()} — {r['detail']}"
                                                   for r in inc["reasons"]))
            action = f"в боевом режиме: {inc['would_action_title']}"
            if inc.get("savings") and inc["savings"]["sms"]:
                sv = inc["savings"]
                action += f", можно было сэкономить ≈{sv['sms']} SMS ({_num(sv['cost'])} {cur})"
            parts.append(action)
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

    # ---------- LLM: только агрегаты, IP под псевдонимами, ответ проверяется ----------

    def llm_payload(self, facts: dict) -> tuple[dict, dict[str, str]]:
        """JSON для модели и словарь «псевдоним -> настоящий IP».

        Наружу уходят только агрегаты: IP заменены на IP-1, IP-2 (по порядку инцидентов),
        номера — только маски диапазонов; без кодов, хешей, сырых событий и epoch-времён.
        """
        aliases: dict[str, str] = {}
        incidents = []
        for i, inc in enumerate(facts["incidents"], 1):
            alias = f"IP-{i}"
            aliases[alias] = inc["ip"]
            fh = inc.get("first_high")
            incidents.append({
                "ip": alias,
                "type": inc["title"],
                "meaning": inc["incident_subtitle"],
                "since": inc["time"],
                "score": inc["score"],
                "level": LEVEL_RU.get(inc["level"], inc["level"]),
                "numbers": inc["numbers"],
                "number_range": inc["number_range"],
                "sms_sent": inc["sms_sent"],
                "sms_cost": inc["sms_cost"],
                "verify_attempts": inc["verify_attempts"],
                "detected_high": ({"after_seconds": round(fh["after_seconds"]),
                                   "at_number": fh["at_number"]} if fh else None),
                "reasons": [f"{r['title']}: {r['detail']}" for r in inc["reasons"]],
                "would_action": inc["would_action_title"],
                "could_save": inc.get("savings"),
            })
        payload = {
            "period": facts["period"],
            "threat_level": LEVEL_RU.get(facts["threat_level"], facts["threat_level"]),
            "sms_sent": facts["sms_sent"],
            "sms_suspicious": facts["sms_suspicious"],
            "sms_cost_suspicious": facts["sms_cost_suspicious"],
            "currency": facts["currency"],
            "mode": facts["mode"],
            "incidents_count": len(incidents),
            "incidents": incidents,
        }
        return payload, aliases

    @staticmethod
    def restore_ips(text: str, aliases: dict[str, str]) -> str:
        return ALIAS_RE.sub(lambda m: aliases.get(m.group(0), m.group(0)), text)

    def summarize(self, window: int = 600) -> dict:
        s = self.engine.settings
        chain = self.chain
        now = self.engine.clock()
        if chain.enabled:
            with self._lock:
                cached = self._cache.get(window)
                if cached and now - cached[0] < s.llm_cache_seconds:
                    return dict(cached[1], cached=True)
        facts = self.facts(window)
        answer = {"text": self.template(facts), "incidents": facts["incidents"],
                  "source": "template", "provider": None, "model": None, "latency_ms": None,
                  "fallback_reason": None, "generated_at": round(now, 3), "window": window,
                  "cached": False}
        if not chain.enabled:
            answer["fallback_reason"] = "disabled"
            return answer
        if not facts["incidents"]:
            answer["fallback_reason"] = "no_incidents"
        else:
            payload, aliases = self.llm_payload(facts)
            user = json.dumps(payload, ensure_ascii=False)
            self.last_request = user
            result = chain.run(LLM_SYSTEM, user, lambda text: fact_check(text, payload, aliases))
            if result.text is not None:
                answer.update(text=self.restore_ips(result.text, aliases), source="llm",
                              provider=result.provider.name, model=result.provider.model,
                              latency_ms=result.latency_ms)
            else:
                answer["fallback_reason"] = result.reason
        with self._lock:
            self._cache[window] = (now, answer)
        return answer

    def meta(self) -> dict:
        return dict(self.chain.meta(), configured=configured_names(self.engine.settings))


# ---------- проверка фактов ----------

ALIAS_RE = re.compile(r"\bIP-\d+\b")
NUMBER_RE = re.compile(r"\d+(?:[ \u00a0\u202f]\d{3})*(?:[.,]\d+)?")
MIN_TEXT, MAX_TEXT = 100, 1200
MASK_STARS = re.compile(r"(?<=\d)\*+(?=\d)")


def _value(raw: str) -> Optional[float]:
    try:
        return float(re.sub(r"[ \u00a0\u202f]", "", raw).replace(",", "."))
    except ValueError:
        return None


def _numbers(text: str) -> set[float]:
    """Все числа источника (JSON): целиком и по частям, «23:32» даёт 23 и 32."""
    found = set()
    for match in NUMBER_RE.finditer(text):
        for raw in [match.group(0), *re.split(r"[ \u00a0\u202f]", match.group(0))]:
            value = _value(raw)
            if value is not None:
                found.add(value)
    return found


def _numbers_ok(text: str, allowed: set[float]) -> bool:
    """Каждое число текста есть в источнике: «1 200» — как 1200 или как 1 и 200."""
    for match in NUMBER_RE.finditer(text):
        token = match.group(0)
        whole = _value(token)
        if whole in allowed:
            continue
        parts = [_value(p) for p in re.split(r"[ \u00a0\u202f]", token)]
        if len(parts) > 1 and all(p in allowed for p in parts):
            continue
        return False
    return True


def _clean_markdown(text: str) -> Optional[str]:
    """Убрать лишнюю разметку; None — если в ответе таблица или блок кода."""
    if "```" in text or re.search(r"^\s*\|.*\|\s*$", text, re.M):
        return None
    # звёздочки масок номеров (+996700***203) не трогаем — убираем только разметку жирного
    text = MASK_STARS.sub(lambda m: m.group(0).replace("*", "\x00"), text)
    text = text.replace("**", "").replace("__", "").replace("\x00", "*")
    text = re.sub(r"^\s*#{1,6}\s*", "", text, flags=re.M)
    text = re.sub(r"^\s*[-*•]\s+", "", text, flags=re.M)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def fact_check(text: str, payload: dict, aliases: dict[str, str]) -> Optional[str]:
    """Очищенный текст, если в нём только факты из payload; иначе None."""
    cleaned = _clean_markdown(text)
    if cleaned is None or not MIN_TEXT <= len(cleaned) <= MAX_TEXT:
        return None
    mentioned = set(ALIAS_RE.findall(cleaned))
    if not mentioned <= set(aliases):
        return None
    source = json.dumps(payload, ensure_ascii=False)
    allowed = _numbers(source)
    if not _numbers_ok(ALIAS_RE.sub(" ", cleaned), allowed):
        return None
    return cleaned
