"""Настройки сервиса. Все параметры можно переопределить переменными окружения."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    return int(value) if value else default


def _env_list(name: str) -> frozenset[str]:
    return frozenset(item.strip() for item in os.getenv(name, "").split(",") if item.strip())


def _load_secret() -> bytes:
    secret = os.getenv("OTP_SECRET")
    if secret:
        return secret.encode()
    # Без заданного ключа генерируем случайный на время жизни процесса:
    # хеши всё равно живут не дольше нескольких минут.
    return secrets.token_bytes(32)


@dataclass(frozen=True)
class Settings:
    secret_key: bytes = field(default_factory=_load_secret, repr=False)

    code_length: int = 6
    code_ttl: int = 120  # секунд жизни кода

    # Прогрессивная задержка повторной отправки: перед 2-й, 3-й, 4-й ... отправкой
    resend_delays: tuple[int, ...] = (30, 60, 120)
    send_limit: int = 3  # не больше N отправок на номер ...
    send_window: int = 600  # ... за 10 минут

    max_failed_attempts: int = 5
    block_duration: int = 900  # 15 минут

    ip_verify_limit: int = 20  # не больше N проверок с одного IP ...
    ip_verify_window: int = 60  # ... в минуту

    log_dir: str = field(default_factory=lambda: os.getenv("OTP_LOG_DIR", "logs"))
    # Тестовый SMS-транспорт: каждая выдача дописывается строкой JSON в этот файл
    # (формат жюри: {"ts", "msisdn", "code"}). Сервис этот файл не читает.
    outbox_path: str = field(
        default_factory=lambda: os.getenv("OTP_OUTBOX", os.path.join(PROJECT_ROOT, "outbox", "sms.jsonl"))
    )
    # IP соединений, которым доверяем заголовок X-Forwarded-For (например, тестовый стенд жюри
    # на 127.0.0.1). По умолчанию пусто: IP берётся только из сокета.
    trusted_proxies: frozenset[str] = field(default_factory=lambda: _env_list("OTP_TRUSTED_PROXIES"))

    # Хранилище: пусто — в памяти процесса; иначе Redis, напр. redis://localhost:6379/0
    redis_url: str = field(default_factory=lambda: os.getenv("REDIS_URL", ""))
    # Если задан — дашборд и /api/security/events требуют ?token=... или X-Dashboard-Token
    dashboard_token: str = field(default_factory=lambda: os.getenv("DASHBOARD_TOKEN", ""), repr=False)

    host: str = field(default_factory=lambda: os.getenv("HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: _env_int("PORT", 8000))
