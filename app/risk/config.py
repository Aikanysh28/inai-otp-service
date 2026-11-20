"""Настройки модуля рисков: все пороги признаков и уровней в одном месте.

Любое поле можно переопределить переменной окружения RISK_<ИМЯ_ПОЛЯ>,
например RISK_WINDOW=600, RISK_SMS_PRICE=2.5, RISK_CURRENCY=сом.
"""
from __future__ import annotations

import dataclasses
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class RiskSettings:
    # Окно, за которое считаются признаки по IP, сек.
    window: int = 600
    # Бишкек: UTC+6 без перехода на летнее время. Только для «ночи» и отображения.
    tz_offset_hours: int = 6

    # Уровни: low < medium_at <= medium < high_at <= high
    medium_at: int = 30
    high_at: int = 60
    max_score: int = 100

    # fan_out: уникальных номеров в send-событиях с одного IP
    fan_out_low: int = 5  # больше -> +fan_out_low_points
    fan_out_high: int = 15  # больше -> +fan_out_high_points
    fan_out_low_points: int = 20
    fan_out_high_points: int = 40

    # sequential: номера идут подряд
    sequential_min_numbers: int = 5
    sequential_max_gap: int = 10  # «сосед» — tail, отличающийся на 1..max_gap
    sequential_share: float = 0.5  # доля номеров с соседом должна быть больше
    sequential_points: int = 25

    # no_conversion: SMS отправлены, но не подтверждены
    no_conversion_min_sends: int = 5
    no_conversion_ratio: float = 0.1
    no_conversion_points: int = 25

    # fail_rate: доля неудачных проверок
    fail_rate_min_attempts: int = 5
    fail_rate_share: float = 0.5
    fail_rate_points: int = 25

    # new_ip: номер раньше подтверждался с другого IP
    new_ip_points: int = 15
    known_ip_ttl: int = 30 * 24 * 3600

    # hammering_locked: попытки к заблокированному номеру
    hammering_min: int = 3
    hammering_points: int = 15

    # ip_limited: срабатывал лимит проверок по IP
    ip_limited_points: int = 15
    service_ip_verify_limit: int = 20  # лимит сервиса по ТЗ — только для подписи признака

    # night: последнее событие в [night_start_hour, night_end_hour) по Бишкеку
    night_start_hour: int = 1
    night_end_hour: int = 6
    night_points: int = 10

    # Экономика: цена одной SMS для оценки ущерба
    sms_price: float = 1.0
    currency: str = "сом"

    # Сводка инцидента через LLM — выключена, пока не задана цепочка провайдеров или ключ.
    # RISK_LLM_PROVIDERS: пресеты через запятую (groq, gemini, openrouter, ollama, anthropic).
    # Только RISK_LLM_API_KEY без цепочки — как раньше: Anthropic.
    llm_providers: str = ""
    llm_api_key: str = dataclasses.field(default="", repr=False)
    llm_groq_key: str = dataclasses.field(default="", repr=False)
    llm_gemini_key: str = dataclasses.field(default="", repr=False)
    llm_openrouter_key: str = dataclasses.field(default="", repr=False)
    llm_anthropic_key: str = dataclasses.field(default="", repr=False)
    llm_model: str = ""  # пусто — модель пресета; действует на первого провайдера цепочки
    llm_base_url: str = ""  # пусто — адрес пресета; действует на первого провайдера цепочки
    llm_timeout: float = 6.0  # на одного провайдера; на всю цепочку — не больше 2 × llm_timeout
    llm_cache_seconds: int = 30

    # Ограничения памяти
    max_events_per_ip: int = 5000
    max_points: int = 20000
    max_alerts: int = 500
    history_hours: int = 24
    cleanup_every: int = 1000

    @classmethod
    def from_env(cls, prefix: str = "RISK_", environ: dict | None = None) -> "RiskSettings":
        """Значения по умолчанию, переопределённые переменными окружения prefix + ИМЯ_ПОЛЯ."""
        env = os.environ if environ is None else environ
        overrides = {}
        for field in dataclasses.fields(cls):
            raw = env.get(prefix + field.name.upper())
            if raw is None or raw == "":
                continue
            default = field.default
            try:
                if isinstance(default, bool):
                    value = raw.strip().lower() in ("1", "true", "yes", "on")
                elif isinstance(default, int):
                    value = int(raw)
                elif isinstance(default, float):
                    value = float(raw)
                else:
                    value = raw
            except ValueError as error:
                raise ValueError(f"{prefix}{field.name.upper()}: некорректное значение {raw!r}") \
                    from error
            overrides[field.name] = value
        return cls(**overrides)
