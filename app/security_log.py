"""Журнал событий безопасности и «доставка» SMS.

Два независимых канала:
* security — JSON-строки в logs/security.log и консоль. Коды сюда НЕ попадают.
* sms      — заглушка SMS-шлюза: код печатается в консоль и logs/sms.log.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import Counter, deque
from datetime import datetime, timezone


def _make_logger(name: str, path: str, fmt: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    formatter = logging.Formatter(fmt)
    file_handler = logging.FileHandler(path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(console)
    return logger


def mask_msisdn(msisdn: str) -> str:
    if len(msisdn) <= 6:
        return "*" * len(msisdn)
    return msisdn[:4] + "*" * (len(msisdn) - 7) + msisdn[-3:]


class SecurityLog:
    """Пишет события безопасности: выдача кода, неудачные вводы, блокировки, лимиты."""

    HISTORY = 5000  # сколько последних событий держим в памяти для дашборда

    # Группы событий для графика дашборда (порядок = порядок серий)
    CATEGORIES = {
        "issued": ("otp_issued",),
        "failed": ("verify_failed", "verify_expired"),
        "success": ("verify_success",),
        "rejected": ("msisdn_blocked", "verify_rejected_blocked", "verify_ip_rate_limited",
                     "send_rate_limited", "send_rejected_blocked"),
    }

    def __init__(self, log_dir: str, clock=time.time):
        self._clock = clock
        self._history: deque[dict] = deque(maxlen=self.HISTORY)
        self._counters: Counter[str] = Counter()
        self._started = clock()
        self._mx = threading.Lock()
        os.makedirs(log_dir, exist_ok=True)
        self._security = _make_logger(
            "otp.security", os.path.join(log_dir, "security.log"), "%(message)s"
        )
        self._sms = _make_logger(
            "otp.sms", os.path.join(log_dir, "sms.log"), "%(asctime)s [SMS] %(message)s"
        )

    def event(self, event: str, msisdn: str | None = None, ip: str | None = None, **details) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "event": event,
        }
        if msisdn is not None:
            record["msisdn"] = mask_msisdn(msisdn)
        if ip is not None:
            record["ip"] = ip
        record.update(details)
        self._security.info(json.dumps(record, ensure_ascii=False))
        with self._mx:
            self._history.append({**record, "t": self._clock()})
            self._counters[event] += 1

    def snapshot(self, limit: int = 100, minutes: int = 30) -> dict:
        """Данные для дашборда: счётчики, поминутная лента, топ IP, последние события."""
        now = self._clock()
        with self._mx:
            history = list(self._history)
            counters = dict(self._counters)

        event_to_cat = {e: c for c, events in self.CATEGORIES.items() for e in events}
        current_minute = int(now // 60)
        timeline = [
            {"minute": (current_minute - i) * 60, **{c: 0 for c in self.CATEGORIES}}
            for i in range(minutes - 1, -1, -1)
        ]
        suspicious: Counter[str] = Counter()
        blocks = []
        for rec in history:
            age = current_minute - int(rec["t"] // 60)
            cat = event_to_cat.get(rec["event"])
            if 0 <= age < minutes and cat:
                timeline[minutes - 1 - age][cat] += 1
            if rec["event"] != "otp_issued" and rec["event"] != "verify_success" and "ip" in rec:
                suspicious[rec["ip"]] += 1
            if rec["event"] == "msisdn_blocked":
                blocks.append(rec)

        def public(rec: dict) -> dict:
            return {k: v for k, v in rec.items() if k != "t"}

        return {
            "now": now,
            "uptime": int(now - self._started),
            "counters": counters,
            "timeline": timeline,
            "top_ips": [{"ip": ip, "events": n} for ip, n in suspicious.most_common(10)],
            "recent_blocks": [public(r) for r in reversed(blocks[-10:])],
            "events": [public(r) for r in reversed(history[-limit:])],
        }

    def deliver_sms(self, msisdn: str, code: str) -> None:
        """Заглушка SMS-шлюза: «отправляет» код в консоль/лог доставки."""
        self._sms.info("to=+%s code=%s", msisdn, code)
