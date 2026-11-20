"""Нормализованное событие модуля рисков и перевод записей журнала в него.

Принимает записи журнала безопасности в текущем формате (`otp_issued`, `verify_failed`, ...)
и в целевом (`send_ok`, `verify_fail`, ...). Полный номер нигде не сохраняется:
из сырого номера сразу получаются псевдоним (HMAC), последние 4 цифры и маска.
"""
from __future__ import annotations

import hashlib
import hmac
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

# Текущее имя -> (целевое имя, HTTP-статус по умолчанию)
EVENT_MAP: dict[str, tuple[str, int]] = {
    "otp_issued": ("send_ok", 200),
    "send_rate_limited": ("send_rejected", 429),
    "send_rejected_blocked": ("send_rejected", 423),
    # личный кабинет: отказ в выдаче, потому что владелец заморозил коды
    "send_rejected_frozen": ("send_rejected", 423),
    "verify_success": ("verify_ok", 200),
    "verify_failed": ("verify_fail", 401),
    "verify_expired": ("verify_expired", 410),
    "msisdn_blocked": ("number_blocked", 423),
    "verify_rejected_blocked": ("verify_locked", 423),
    "verify_ip_rate_limited": ("ip_rate_limited", 429),
    "bad_request": ("bad_request", 400),
    "store_unavailable": ("store_unavailable", 503),
}

# Целевые имена принимаются как есть
TARGET_STATUS: dict[str, int] = {
    "send_ok": 200,
    "send_rejected": 429,
    "verify_ok": 200,
    "verify_fail": 401,
    "verify_expired": 410,
    "number_blocked": 423,
    "verify_locked": 423,
    "ip_rate_limited": 429,
    "bad_request": 400,
    "store_unavailable": 503,
}

# Причины отказа в send: текущие -> целевые
REASON_MAP = {"resend_delay": "cooldown", "send_limit": "limit"}
# Причина по умолчанию, если в записи её нет
DEFAULT_REASON = {"send_rejected_blocked": "blocked", "send_rejected_frozen": "frozen"}

KINDS = tuple(TARGET_STATUS)
_NON_DIGITS = re.compile(r"\D")


@dataclass(frozen=True, slots=True)
class RiskEvent:
    ts: float
    kind: str
    raw_event: str
    ip: str
    msisdn_id: Optional[str]
    msisdn_tail: Optional[str]
    msisdn_masked: Optional[str]
    status: Optional[int]
    reason: Optional[str]
    user_agent: Optional[str] = None
    scope: Optional[str] = None  # например "cabinet" — код для входа в кабинет абонента


def digits_only(msisdn: str) -> str:
    return _NON_DIGITS.sub("", msisdn)


def derive_id_key(secret_key: bytes) -> bytes:
    """Ключ псевдонимов номеров из ключа сервиса: HMAC-SHA256(secret_key, b"risk-id")."""
    return hmac.new(secret_key, b"risk-id", hashlib.sha256).digest()


def make_msisdn_id(msisdn: str, id_key: bytes) -> str:
    """Псевдоним номера: HMAC-SHA256(id_key, "msisdn:" + цифры), первые 16 hex-символов."""
    message = b"msisdn:" + digits_only(msisdn).encode()
    return hmac.new(id_key, message, hashlib.sha256).hexdigest()[:16]


def mask_msisdn(msisdn: str) -> str:
    """996700123456 -> +996700***456 (код страны и оператора, три звёздочки, три последние цифры)."""
    digits = digits_only(msisdn)
    if len(digits) < 9:
        return "+" + "*" * len(digits)
    return "+" + digits[:6] + "***" + digits[-3:]


def parse_ts(value: Any) -> Optional[float]:
    """Epoch-секунды из числа или ISO-строки (без таймзоны считаем UTC)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        return number if math.isfinite(number) else None
    if isinstance(value, str) and value:
        try:
            moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.timestamp()
    return None


def _event_time(record: Mapping[str, Any], ts: Optional[float]) -> Optional[float]:
    for candidate in (ts, record.get("ts_epoch"), record.get("ts")):
        parsed = parse_ts(candidate)
        if parsed is not None:
            return parsed
    return None


def _status(record: Mapping[str, Any], default: int) -> int:
    value = record.get("status")
    if isinstance(value, int) and not isinstance(value, bool) and 100 <= value <= 599:
        return value
    return default


def normalize(record: Any, *, id_key: bytes, msisdn: Optional[str] = None,
              ts: Optional[float] = None) -> Optional[RiskEvent]:
    """Запись журнала -> RiskEvent; None, если событие неизвестно или у него нет времени."""
    if not isinstance(record, Mapping):
        return None
    raw_event = record.get("event")
    if not isinstance(raw_event, str):
        return None
    if raw_event in EVENT_MAP:
        kind, default_status = EVENT_MAP[raw_event]
    elif raw_event in TARGET_STATUS:
        kind, default_status = raw_event, TARGET_STATUS[raw_event]
    else:
        return None

    moment = _event_time(record, ts)
    if moment is None:
        return None

    msisdn_id = tail = masked = None
    if isinstance(msisdn, str) and digits_only(msisdn):
        digits = digits_only(msisdn)
        msisdn_id = make_msisdn_id(digits, id_key)
        tail = digits[-4:]
        masked = mask_msisdn(digits)
    elif isinstance(record.get("msisdn"), str) and record["msisdn"]:
        # Режим чтения готового лога: только маска коллеги, «подряд» не вычислить.
        msisdn_id = "m:" + record["msisdn"]
        masked = record["msisdn"]

    reason = record.get("reason")
    if isinstance(reason, str):
        reason = REASON_MAP.get(reason, reason)
    else:
        reason = DEFAULT_REASON.get(raw_event)

    user_agent = record.get("user_agent")
    scope = record.get("scope")
    ip = record.get("ip")
    return RiskEvent(
        ts=moment,
        kind=kind,
        raw_event=raw_event,
        ip=ip if isinstance(ip, str) and ip else "unknown",
        msisdn_id=msisdn_id,
        msisdn_tail=tail,
        msisdn_masked=masked,
        status=_status(record, default_status),
        reason=reason,
        user_agent=user_agent if isinstance(user_agent, str) else None,
        scope=scope if isinstance(scope, str) and scope else None,
    )
