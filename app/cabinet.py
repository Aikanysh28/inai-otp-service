"""Личный кабинет абонента: вход по OTP, история запросов кодов, заморозка выдачи.

Сценарий: абонент видит, кто и когда запрашивал коды на его номер, и может «заморозить»
выдачу кодов внешним сервисам (потерял телефон, уехал, подозревает подмену SIM).
Пока заморозка действует, /otp/send для номера отвечает 423, а действующий код аннулирован.
Номера, которые никто не замораживал (в том числе тестовые номера жюри), ведут себя по ТЗ.
"""
from __future__ import annotations

import hashlib
import secrets
from typing import Optional

from .otp_service import (
    CABINET_SCOPE, DEFAULT_SCOPE, FREEZE_KEY, MSISDN_LOCK, OTPService, SendResult, VerifyResult,
    VerifyStatus, otp_key,
)
from .security_log import SecurityEvent

SESSION_KEY = "session:{}"
SESSION_TTL = 30 * 60
# Допустимые сроки заморозки, секунд; None — до ручной разморозки
FREEZE_DURATIONS = (3600, 24 * 3600, 7 * 24 * 3600, None)


def _token_digest(token: str) -> str:
    """В хранилище лежит только хеш токена: утечка хранилища не даёт войти в кабинет."""
    return hashlib.sha256(token.encode()).hexdigest()


class Cabinet:
    def __init__(self, otp: OTPService):
        self.otp = otp
        self.store = otp.store

    # ---------- вход ----------

    def request_code(self, msisdn: str, ip: str) -> SendResult:
        """Код для входа в кабинет: с теми же лимитами, но выдаётся и при заморозке."""
        return self.otp.send(msisdn, ip, scope=CABINET_SCOPE)

    def login(self, msisdn: str, code: str, ip: str) -> tuple[VerifyResult, Optional[str]]:
        """Проверить код входа; при успехе — новый токен сессии.

        IP-квоту списывает вызывающая сторона (как и для /otp/verify).
        """
        result = self.otp.verify_code(msisdn, code, ip, scope=CABINET_SCOPE)
        if result.status is not VerifyStatus.OK:
            return result, None
        token = secrets.token_urlsafe(32)
        self.store.set(SESSION_KEY.format(_token_digest(token)), msisdn, ttl=SESSION_TTL)
        with self.store.lock(MSISDN_LOCK.format(msisdn)):
            self.otp.record_event(SecurityEvent.CABINET_LOGIN, msisdn, ip)
        return result, token

    def session_msisdn(self, token: str) -> Optional[str]:
        return self.store.get(SESSION_KEY.format(_token_digest(token))) if token else None

    def logout(self, token: str) -> None:
        self.store.delete(SESSION_KEY.format(_token_digest(token)))

    # ---------- заморозка ----------

    def freeze(self, msisdn: str, ip: str, duration: Optional[int]) -> None:
        """Заморозить выдачу кодов внешним сервисам на duration секунд (None — бессрочно)."""
        if duration not in FREEZE_DURATIONS:
            raise ValueError(f"duration must be one of {FREEZE_DURATIONS}")
        with self.store.lock(MSISDN_LOCK.format(msisdn)):
            now = self.otp.clock()
            until = None if duration is None else now + duration
            self.store.set(FREEZE_KEY.format(msisdn), {"since": now, "until": until},
                           ttl=duration)
            self.store.delete(otp_key(msisdn, DEFAULT_SCOPE))  # выданный код больше не действует
            self.otp.record_event(SecurityEvent.MSISDN_FROZEN, msisdn, ip, duration=duration)

    def unfreeze(self, msisdn: str, ip: str) -> None:
        with self.store.lock(MSISDN_LOCK.format(msisdn)):
            self.store.delete(FREEZE_KEY.format(msisdn))
            self.otp.record_event(SecurityEvent.MSISDN_UNFROZEN, msisdn, ip)

    # ---------- сводка ----------

    def overview(self, msisdn: str) -> dict:
        return {
            "msisdn": msisdn,
            "now": self.otp.clock(),
            "frozen": self.otp.freeze_status(msisdn),
            "blocked_until": self.otp.blocked_until(msisdn),
            "history": self.otp.history(msisdn),
        }
