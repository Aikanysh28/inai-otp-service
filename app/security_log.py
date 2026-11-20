"""Журнал событий безопасности и «доставка» SMS.

Два независимых канала:
* SecurityLog — JSON-строки в logs/security.log и консоль. Коды сюда НЕ попадают.
* SmsGateway  — заглушка SMS-шлюза: код печатается в консоль и logs/sms.log.
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


def _build_logger(name: str, path: str, fmt: str) -> logging.Logger:
    """Логгер в файл и консоль.

    Создаётся собственный экземпляр, а не глобальный logging.getLogger(name):
    иначе несколько журналов (например, в тестах) перехватывали бы обработчики друг друга.
    """
    logger = logging.Logger(name, logging.INFO)
    formatter = logging.Formatter(fmt)
    for handler in (logging.FileHandler(path, encoding="utf-8"), logging.StreamHandler()):
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


def _close_logger(logger: logging.Logger) -> None:
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()


def mask_msisdn(msisdn: str) -> str:
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
        ),
    }
    _CATEGORY_OF = {event.value: category for category, events in CATEGORIES.items() for event in events}
    # Штатные события не делают IP подозрительным
    _ROUTINE = frozenset({SecurityEvent.OTP_ISSUED.value, SecurityEvent.VERIFY_SUCCESS.value})

    def __init__(self, log_dir: str, clock: Callable[[], float] = time.time):
        os.makedirs(log_dir, exist_ok=True)
        self._logger = _build_logger("otp.security", os.path.join(log_dir, "security.log"), "%(message)s")
        self._clock = clock
        self._started = clock()
        self._history: deque[tuple[float, dict]] = deque(maxlen=self.HISTORY_SIZE)
        self._counters: Counter[str] = Counter()
        self._mutex = threading.Lock()

    def event(self, event: SecurityEvent, msisdn: Optional[str] = None, ip: Optional[str] = None,
              **details) -> None:
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

    def snapshot(self, limit: int = 100, minutes: int = 30) -> dict:
        """Данные для дашборда: счётчики, поминутная лента, топ IP, последние события."""
        now = self._clock()
        with self._mutex:
            history = list(self._history)
            counters = dict(self._counters)
        records = [record for _, record in history]

        suspicious = Counter(r["ip"] for r in records if r["event"] not in self._ROUTINE and "ip" in r)
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

    def _timeline(self, history: list[tuple[float, dict]], now: float, minutes: int) -> list[dict]:
        """Число событий каждой категории по минутам: от самой старой минуты к текущей."""
        current_minute = int(now // 60)
        timeline = [
            {"minute": (current_minute - age) * 60, **{category: 0 for category in self.CATEGORIES}}
            for age in range(minutes - 1, -1, -1)
        ]
        for t, record in history:
            age = current_minute - int(t // 60)
            category = self._CATEGORY_OF.get(record["event"])
            if category and 0 <= age < minutes:
                timeline[minutes - 1 - age][category] += 1
        return timeline

    def close(self) -> None:
        _close_logger(self._logger)


class SmsGateway:
    """Заглушка SMS-шлюза: «отправляет» код в консоль и logs/sms.log."""

    def __init__(self, log_dir: str):
        os.makedirs(log_dir, exist_ok=True)
        self._logger = _build_logger("otp.sms", os.path.join(log_dir, "sms.log"), "%(asctime)s [SMS] %(message)s")

    def deliver(self, msisdn: str, code: str) -> None:
        self._logger.info("to=+%s code=%s", msisdn, code)

    def close(self) -> None:
        _close_logger(self._logger)
