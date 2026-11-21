"""LLM-клиент на stdlib для пересказа сводки: OpenAI-совместимые пресеты и Anthropic.

Почти все бесплатные провайдеры (Groq, Gemini, OpenRouter, Ollama) говорят на протоколе
POST {base_url}/chat/completions, поэтому клиент один, а провайдеры — пресеты.
Цепочка перебирает провайдеров по порядку: ошибка, отказ проверки фактов — следующий;
провайдер после 429 молчит до Retry-After (или 60 с), после 401/403 — до перезапуска.
Вся цепочка укладывается в 2 × timeout, чтобы кнопка «Сводка» не висела.
Ключи нигде не печатаются: у LLMProvider ключ скрыт из repr.
"""
from __future__ import annotations

import json
import math
import socket
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .config import RiskSettings

ANTHROPIC_VERSION = "2023-06-01"
# Свой User-Agent обязателен: Groq (защита от ботов) отвечает 403 на стандартный
# «Python-urllib/3.x», и такой ответ иначе выглядел бы как неверный ключ.
USER_AGENT = "otp-risk/1.0"
DEFAULT_RETRY_AFTER = 60.0

# имя -> (base_url, модель по умолчанию, вид протокола, поле ключа в RiskSettings, нужен ли ключ)
PRESETS: dict[str, tuple[str, str, str, Optional[str], bool]] = {
    # llama-3.3-70b-versatile на Groq больше нет (проверено GET /models 21.11.2026)
    "groq": ("https://api.groq.com/openai/v1", "openai/gpt-oss-120b", "openai",
             "llm_groq_key", True),
    # Модель Gemini не проверена без ключа: актуальный список — `python3 -m app.risk.llm_check`
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai", "gemini-2.5-flash",
               "openai", "llm_gemini_key", True),
    "openrouter": ("https://openrouter.ai/api/v1", "openrouter/free", "openai",
                   "llm_openrouter_key", True),
    "ollama": ("http://localhost:11434/v1", "qwen2.5:7b", "openai", None, False),
    "anthropic": ("https://api.anthropic.com/v1", "claude-haiku-5-5", "anthropic",
                  "llm_anthropic_key", True),
}
DISPLAY_NAMES = {"groq": "Groq", "gemini": "Gemini", "openrouter": "OpenRouter",
                 "ollama": "Ollama", "anthropic": "Anthropic"}

# Причины отката (они же fallback_reason в ответе API)
AUTO_CHAIN = ("groq", "openrouter", "gemini", "anthropic")  # если RISK_LLM_PROVIDERS не задан
KEY_VARS = {"groq": "RISK_LLM_GROQ_KEY", "gemini": "RISK_LLM_GEMINI_KEY",
            "openrouter": "RISK_LLM_OPENROUTER_KEY", "anthropic": "RISK_LLM_ANTHROPIC_KEY"}
REASONS = ("disabled", "no_env", "no_key", "unknown_provider", "forbidden",
           "no_incidents", "network", "auth", "rate_limited", "bad_response",
           "fact_check", "timeout")


class LLMError(Exception):
    """Ошибка вызова провайдера; kind — одна из REASONS (network, auth, rate_limited, ...)."""

    def __init__(self, kind: str, message: str = "", retry_after: Optional[float] = None):
        super().__init__(message or kind)
        self.kind = kind
        self.retry_after = retry_after


@dataclass(frozen=True)
class LLMProvider:
    name: str
    base_url: str
    model: str
    key: str = field(default="", repr=False)
    kind: str = "openai"  # openai | anthropic

    @property
    def has_key(self) -> bool:
        return bool(self.key)

    def public(self) -> dict:
        """Описание без ключа — для meta и llm_check."""
        return {"name": self.name, "display_name": DISPLAY_NAMES.get(self.name, self.name),
                "model": self.model, "base_url": self.base_url, "kind": self.kind,
                "has_key": self.has_key}


def providers_from_settings(s: RiskSettings) -> list[LLMProvider]:
    """Цепочка из RISK_LLM_PROVIDERS; без неё и с RISK_LLM_API_KEY — Anthropic, как раньше.

    Провайдер без ключа (кроме ollama) пропускается. RISK_LLM_MODEL и RISK_LLM_BASE_URL
    действуют на первого провайдера цепочки; RISK_LLM_API_KEY — запасной ключ для него же.
    """
    names = configured_names(s)
    chain: list[LLMProvider] = []
    for index, name in enumerate(names):
        if name not in PRESETS:
            continue
        base_url, model, kind, key_field, needs_key = PRESETS[name]
        key = getattr(s, key_field) if key_field else ""
        first = index == 0
        if first and not key and s.llm_api_key:
            key = s.llm_api_key
        if needs_key and not key:
            continue
        chain.append(LLMProvider(
            name=name,
            base_url=(s.llm_base_url if first and s.llm_base_url else base_url).rstrip("/"),
            model=s.llm_model if first and s.llm_model else model,
            key=key, kind=kind))
    return chain


def configured_names(s: RiskSettings) -> list[str]:
    """Цепочка из RISK_LLM_PROVIDERS; если её нет — из найденных ключей (groq, openrouter,
    gemini, anthropic); только RISK_LLM_API_KEY без ключей провайдеров — Anthropic, как раньше."""
    names = [n.strip().lower() for n in s.llm_providers.split(",") if n.strip()]
    if names:
        return names
    auto = [name for name in AUTO_CHAIN if getattr(s, PRESETS[name][3])]
    return auto or (["anthropic"] if s.llm_api_key else [])


def startup_line(s: RiskSettings) -> str:
    """Одна строка для stderr при старте сервера — без значений ключей."""
    source = {"env": "окружение", ".env": ".env", "none": "нет"}.get(s.llm_config_source, s.llm_config_source)
    chain = providers_from_settings(s)
    if chain:
        first = chain[0]
        others = f" → {', '.join(p.name for p in chain[1:])}" if len(chain) > 1 else ""
        key = "ключ задан" if first.has_key else "ключ не нужен"
        return f"[risk] LLM: {first.name} ({first.model}){others}, {key}; источник: {source}"
    reason = disabled_reason(s)
    if reason and reason[0] == "no_env":
        return "[risk] LLM выключена: нет RISK_LLM_PROVIDERS и ключей"
    return f"[risk] {reason[1] if reason else 'LLM выключена'}; источник: {source}"


def disabled_reason(s: RiskSettings) -> Optional[tuple[str, str]]:
    """Почему цепочка пуста: (код, текст для людей) или None, если LLM включена."""
    if providers_from_settings(s):
        return None
    names = [n.strip().lower() for n in s.llm_providers.split(",") if n.strip()]
    unknown = [n for n in names if n not in PRESETS]
    if unknown:
        return ("unknown_provider", "Неизвестный провайдер в RISK_LLM_PROVIDERS: " + ", ".join(unknown))
    if names:
        missing = [n for n in names if PRESETS[n][4]]
        name = missing[0] if missing else names[0]
        var = KEY_VARS.get(name, "RISK_LLM_API_KEY")
        return ("no_key", f"LLM выключена: нет ключа для провайдера {name} (переменная {var})")
    return ("no_env", "LLM выключена: серверу не передан ни один параметр RISK_LLM_*. "
                      "Перезапустите сервер после загрузки .env")


# ---------- один вызов ----------

def build_request(provider: LLMProvider, system: str, user: str) -> urllib.request.Request:
    if provider.kind == "anthropic":
        body = {"model": provider.model, "max_tokens": 1024, "system": system,
                "output_config": {"effort": "low"},
                "messages": [{"role": "user", "content": user}]}
        headers = {"x-api-key": provider.key, "anthropic-version": ANTHROPIC_VERSION,
                   "content-type": "application/json"}
        url = provider.base_url + "/messages"
    else:
        # Запас токенов: «рассуждающие» модели (gpt-oss) сначала думают, потом пишут ответ —
        # при 400 токенах всё уходит на рассуждение и текст пустой (finish_reason: length).
        body = {"model": provider.model, "temperature": 0.2, "max_tokens": 1500,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": user}]}
        if "gpt-oss" in provider.model:
            body["reasoning_effort"] = "low"  # короткое рассуждение: быстрее и не съедает ответ
        headers = {"Content-Type": "application/json"}
        if provider.key:
            headers["Authorization"] = "Bearer " + provider.key
        url = provider.base_url + "/chat/completions"
    headers["User-Agent"] = USER_AGENT
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    return urllib.request.Request(url, data=data, method="POST", headers=headers)


def parse_response(provider: LLMProvider, data: Any) -> str:
    try:
        if provider.kind == "anthropic":
            if data.get("stop_reason") == "refusal":
                raise LLMError("bad_response", "refusal")
            # У Haiku 5.5 размышление включено по умолчанию: берём только текстовые блоки
            text = "".join(block.get("text", "") for block in data.get("content", [])
                           if block.get("type") == "text")
        else:
            text = data["choices"][0]["message"]["content"]
    except LLMError:
        raise
    except (KeyError, IndexError, TypeError, AttributeError) as error:
        raise LLMError("bad_response", f"unexpected format: {type(error).__name__}") from None
    if not isinstance(text, str) or not text.strip():
        raise LLMError("bad_response", "empty text")
    return text.strip()


def _retry_after(headers: Any) -> Optional[float]:
    try:
        value = float(headers.get("Retry-After"))
        return value if math.isfinite(value) and value >= 0 else None
    except (TypeError, ValueError, AttributeError):
        return None


def complete(provider: LLMProvider, system: str, user: str, timeout: float,
             opener: Callable[..., Any] = urllib.request.urlopen) -> str:
    """Один вызов провайдера; текст ответа или LLMError с причиной."""
    request = build_request(provider, system, user)
    try:
        with opener(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as error:
        if error.code == 401:
            raise LLMError("auth", "HTTP 401") from None
        if error.code == 403:  # Cloudflare, регион, сеть — не обязательно ключ
            raise LLMError("forbidden", "HTTP 403") from None
        if error.code == 429:
            raise LLMError("rate_limited", "HTTP 429", _retry_after(error.headers)) from None
        if error.code >= 500:
            raise LLMError("network", f"HTTP {error.code}") from None
        raise LLMError("bad_response", f"HTTP {error.code}") from None
    except (socket.timeout, TimeoutError):
        raise LLMError("timeout") from None
    except urllib.error.URLError as error:
        kind = "timeout" if isinstance(error.reason, (socket.timeout, TimeoutError)) else "network"
        raise LLMError(kind, str(error.reason)) from None
    except OSError as error:
        raise LLMError("network", type(error).__name__) from None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise LLMError("bad_response", "not json") from None
    return parse_response(provider, data)


# ---------- цепочка ----------

@dataclass
class ChainResult:
    text: Optional[str]
    provider: Optional[LLMProvider]
    latency_ms: Optional[int]
    reason: Optional[str]  # причина отката, если text is None
    attempts: list[dict] = field(default_factory=list)


class LLMChain:
    def __init__(self, providers: list[LLMProvider], timeout: float,
                 opener: Callable[[], Callable[..., Any]],
                 monotonic: Callable[[], float] = time.monotonic):
        self.providers = providers
        self.timeout = timeout
        self._opener = opener  # функция, возвращающая текущий opener (его подменяют тесты)
        self.monotonic = monotonic
        self._cooldown: dict[str, float] = {}  # имя -> до какого момента пропускать
        self._cooldown_reason: dict[str, str] = {}
        self._lock = threading.Lock()
        self.calls_ok = 0
        self.fallbacks: Counter = Counter()

    @property
    def enabled(self) -> bool:
        return bool(self.providers)

    def cooling(self, name: str) -> Optional[str]:
        with self._lock:
            until = self._cooldown.get(name)
            if until is None:
                return None
            if until > self.monotonic():
                return self._cooldown_reason.get(name)
            del self._cooldown[name]
            return None

    def _cool(self, name: str, reason: str, seconds: float) -> None:
        with self._lock:
            self._cooldown[name] = self.monotonic() + seconds
            self._cooldown_reason[name] = reason

    def _call(self, provider: LLMProvider, system: str, user: str, timeout: float) -> str:
        """Вызов с жёстким ограничением по времени: «висящий» провайдер не держит кнопку."""
        result: dict[str, Any] = {}

        def run() -> None:
            try:
                result["text"] = complete(provider, system, user, timeout, self._opener())
            except LLMError as error:
                result["error"] = error
            except Exception as error:  # noqa: BLE001 — любой сбой клиента — откат
                result["error"] = LLMError("bad_response", type(error).__name__)

        worker = threading.Thread(target=run, name="risk-llm", daemon=True)
        worker.start()
        worker.join(timeout)
        if worker.is_alive():
            raise LLMError("timeout")
        if "error" in result:
            raise result["error"]
        return result["text"]

    def run(self, system: str, user: str,
            validate: Callable[[str], Optional[str]]) -> ChainResult:
        """Первый ответ, прошедший validate (вернул текст), или причина отката."""
        if not self.providers:
            return ChainResult(None, None, None, "disabled")
        started = self.monotonic()
        deadline = started + 2 * self.timeout
        attempts: list[dict] = []
        last_reason: Optional[str] = None
        for provider in self.providers:
            skipped = self.cooling(provider.name)
            if skipped:
                attempts.append({"provider": provider.name, "result": "skipped",
                                 "reason": skipped})
                last_reason = last_reason or skipped
                continue
            remaining = deadline - self.monotonic()
            if remaining <= 0:
                last_reason = "timeout"
                break
            t0 = self.monotonic()
            try:
                text = self._call(provider, system, user, min(self.timeout, remaining))
            except LLMError as error:
                last_reason = error.kind
                attempts.append({"provider": provider.name, "result": "error",
                                 "reason": error.kind})
                if error.kind == "rate_limited":
                    self._cool(provider.name, "rate_limited",
                               error.retry_after or DEFAULT_RETRY_AFTER)
                elif error.kind == "auth":
                    self._cool(provider.name, "auth", math.inf)  # до перезапуска
                elif error.kind == "forbidden":
                    self._cool(provider.name, "forbidden", DEFAULT_RETRY_AFTER)
                continue
            accepted = validate(text)
            latency = int(round((self.monotonic() - t0) * 1000))
            if accepted is None:
                last_reason = "fact_check"
                attempts.append({"provider": provider.name, "result": "rejected",
                                 "reason": "fact_check"})
                continue
            self.calls_ok += 1
            attempts.append({"provider": provider.name, "result": "ok"})
            return ChainResult(accepted, provider, latency, None, attempts)
        reason = last_reason or "timeout"
        self.fallbacks[reason] += 1
        return ChainResult(None, None, None, reason, attempts)

    def meta(self) -> dict:
        return {
            "enabled": self.enabled,
            "providers": [dict(p.public(), cooling=self.cooling(p.name)) for p in self.providers],
            "timeout": self.timeout,
            "budget": 2 * self.timeout,
            "calls_ok": self.calls_ok,
            "fallbacks": dict(self.fallbacks),
        }
