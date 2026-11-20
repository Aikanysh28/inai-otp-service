"""Журнал событий безопасности: JSON-строки в logs/security.log и консоль.

Кодов в журнале нет, номера маскируются. Последние события хранятся в памяти для дашборда.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import Counter, deque
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional


class SecurityEvent(str, Enum):
    OTP_ISSUED = "otp_issued"
    SEND_RATE_LIMITED = "send_rate_limited"
    SEND_REJECTED_BLOCKED = "send_rejected_blocked"
    VERIFY_SUCCESS = "verify_success"
    VERIFY_FAILED = "verify_failed"
    VERIFY_EXPIRED = "verify_expired"
    VERIFY_REJECTED_BLOCKED = "verify_rejected_blocked"
    VERIFY_IP_RATE_LIMITED = "verify_ip_rate_limited"
    MSISDN_BLOCKED = "msisdn_blocked"
    STORE_UNAVAILABLE = "store_unavailable"
    # личный кабинет абонента
    CABINET_LOGIN = "cabinet_login"
    MSISDN_FROZEN = "msisdn_frozen"
    MSISDN_UNFROZEN = "msisdn_unfrozen"
    SEND_REJECTED_FROZEN = "send_rejected_frozen"


def _build_logger(name: str, path: str, console: bool) -> logging.Logger:
    """Логгер в файл и (опционально) консоль.

    Создаётся собственный экземпляр, а не глобальный logging.getLogger(name):
    иначе несколько журналов (например, в тестах) перехватывали бы обработчики друг друга.
    """
    logger = logging.Logger(name, logging.INFO)
    handlers: list[logging.Handler] = [logging.FileHandler(path, encoding="utf-8")]
    if console:
        handlers.append(logging.StreamHandler())
    for handler in handlers:
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    return logger


def mask_msisdn(msisdn: str) -> str:
    """996770730000 -> 9967*****000."""
    if len(msisdn) <= 6:
        return "*" * len(msisdn)
    return msisdn[:4] + "*" * (len(msisdn) - 7) + msisdn[-3:]


class SecurityLog:
    """Пишет события безопасности и хранит последние из них для дашборда."""

    HISTORY_SIZE = 5000
    TOP_IPS = 10
    RECENT_BLOCKS = 10

    # Группы событий для графика дашборда (порядок = порядок серий на графике)
    CATEGORIES: dict[str, tuple[SecurityEvent, ...]] = {
        "issued": (SecurityEvent.OTP_ISSUED,),
        "failed": (SecurityEvent.VERIFY_FAILED, SecurityEvent.VERIFY_EXPIRED),
        "success": (SecurityEvent.VERIFY_SUCCESS,),
        "rejected": (
            SecurityEvent.MSISDN_BLOCKED,
            SecurityEvent.VERIFY_REJECTED_BLOCKED,
            SecurityEvent.VERIFY_IP_RATE_LIMITED,
            SecurityEvent.SEND_RATE_LIMITED,
            SecurityEvent.SEND_REJECTED_BLOCKED,
            SecurityEvent.SEND_REJECTED_FROZEN,
        ),
    }
    _CATEGORY_OF = {
        event.value: category for category, events in CATEGORIES.items() for event in events
    }
    # Штатные события не делают IP подозрительным
    _ROUTINE = frozenset(event.value for event in (
        SecurityEvent.OTP_ISSUED, SecurityEvent.VERIFY_SUCCESS, SecurityEvent.CABINET_LOGIN,
        SecurityEvent.MSISDN_FROZEN, SecurityEvent.MSISDN_UNFROZEN,
    ))

    def __init__(self, log_dir: str, clock: Callable[[], float] = time.time,
                 console: bool = True):
        os.makedirs(log_dir, exist_ok=True)
        path = os.path.join(log_dir, "security.log")
        self._logger = _build_logger("otp.security", path, console)
        self._clock = clock
        self._started = clock()
        self._history: deque[tuple[float, dict]] = deque(maxlen=self.HISTORY_SIZE)
        self._counters: Counter[str] = Counter()
        self._mutex = threading.Lock()
        self._sinks: list[Callable[..., None]] = []

    def add_sink(self, fn: Callable[..., None]) -> None:
        """Подписчик на события: fn(record, msisdn=<номер без маски или None>, ts=<clock()>).

        Вызывается после записи события; исключения подписчика на журнал не влияют.
        """
        self._sinks.append(fn)

    def event(self, event: SecurityEvent, msisdn: Optional[str] = None,
              ip: Optional[str] = None, **details) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "event": event.value,
        }
        if msisdn is not None:
            record["msisdn"] = mask_msisdn(msisdn)
        if ip is not None:
            record["ip"] = ip
        record.update(details)
        self._logger.info(json.dumps(record, ensure_ascii=False))
        with self._mutex:
            self._history.append((self._clock(), record))
            self._counters[event.value] += 1
        for sink in self._sinks:
            try:
                sink(dict(record), msisdn=msisdn, ts=self._clock())
            except Exception:  # noqa: BLE001 — подписчик не должен влиять на журнал и ответ
                pass

    def snapshot(self, limit: int = 100, minutes: int = 30) -> dict:
        """Данные для дашборда: счётчики, поминутная лента, топ IP, последние события."""
        now = self._clock()
        with self._mutex:
            history = list(self._history)
            counters = dict(self._counters)
        records = [record for _, record in history]

        suspicious = Counter(
            r["ip"] for r in records if r["event"] not in self._ROUTINE and "ip" in r
        )
        blocks = [r for r in records if r["event"] == SecurityEvent.MSISDN_BLOCKED.value]

        return {
            "now": now,
            "uptime": int(now - self._started),
            "counters": counters,
            "timeline": self._timeline(history, now, minutes),
            "top_ips": [{"ip": ip, "events": n} for ip, n in suspicious.most_common(self.TOP_IPS)],
            "recent_blocks": blocks[-self.RECENT_BLOCKS:][::-1],
            "events": records[-limit:][::-1],
        }

    def _timeline(self, history: list[tuple[float, dict]], now: float,
                  minutes: int) -> list[dict]:
        """Число событий каждой категории по минутам: от самой старой минуты к текущей."""
        current_minute = int(now // 60)
        timeline = [
            {"minute": (current_minute - age) * 60, **dict.fromkeys(self.CATEGORIES, 0)}
            for age in range(minutes - 1, -1, -1)
        ]
        for timestamp, record in history:
            age = current_minute - int(timestamp // 60)
            category = self._CATEGORY_OF.get(record["event"])
            if category and 0 <= age < minutes:
                timeline[minutes - 1 - age][category] += 1
        return timeline

    def close(self) -> None:
        for handler in list(self._logger.handlers):
            self._logger.removeHandler(handler)
            handler.close()
