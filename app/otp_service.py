"""Бизнес-логика OTP: генерация, хранение хеша, проверка, лимиты и блокировки.

Все изменения состояния номера идут под store.lock(номер): секция «прочитать-проверить-записать»
атомарна, поэтому из параллельных verify с верным кодом успешен ровно один.
Лимит по IP проверяется под своей блокировкой ДО блокировки номера (не вложенно) —
взаимоблокировка невозможна.
"""
from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

from .config import Settings
from .security_log import SecurityEvent, SecurityLog, SmsGateway
from .store import MemoryStore, Store

# Ключи хранилища ({} — номер или IP)
OTP_KEY = "otp:{}"  # HMAC кода и срок его действия
SENDS_KEY = "sends:{}"  # отметки времени отправок за окно
FAILS_KEY = "fails:{}"  # число неверных вводов подряд
BLOCK_KEY = "block:{}"  # время окончания блокировки номера
IP_VERIFY_KEY = "ipverify:{}"  # отметки времени проверок с IP за окно
MSISDN_LOCK = "msisdn:{}"
IP_LOCK = "ip:{}"


class SendStatus(str, Enum):
    SENT = "sent"
    RESEND_TOO_EARLY = "resend_too_early"
    SEND_LIMIT = "send_limit_exceeded"
    BLOCKED = "msisdn_blocked"


class VerifyStatus(str, Enum):
    OK = "verified"
    INVALID = "invalid_code"
    EXPIRED = "code_expired"
    BLOCKED = "msisdn_blocked"
    IP_RATE_LIMIT = "ip_rate_limited"


@dataclass(frozen=True)
class SendResult:
    status: SendStatus
    retry_after: Optional[int] = None  # сек. до следующей разрешённой отправки
    expires_in: Optional[int] = None


@dataclass(frozen=True)
class VerifyResult:
    status: VerifyStatus
    retry_after: Optional[int] = None
    attempts_left: Optional[int] = None


def _whole_seconds(seconds: float) -> int:
    """Округление вверх до целых секунд, минимум 1 (для Retry-After)."""
    return max(1, math.ceil(seconds))


class OTPService:
    def __init__(
        self,
        settings: Settings,
        log: SecurityLog,
        clock: Callable[[], float] = time.time,
        store: Optional[Store] = None,
        sms: Optional[SmsGateway] = None,
    ):
        self.settings = settings
        self.log = log
        self.clock = clock
        self.store: Store = store or MemoryStore(clock)
        self.sms = sms or SmsGateway(settings.outbox_path, clock)

    # ---------- send ----------

    def send(self, msisdn: str, ip: str) -> SendResult:
        with self.store.lock(MSISDN_LOCK.format(msisdn)):
            now = self.clock()
            sends = self._recent(SENDS_KEY.format(msisdn), self.settings.send_window, now)

            rejected = self._check_send_allowed(msisdn, ip, sends, now)
            if rejected is not None:
                return rejected

            code = self._generate_code()
            # Новая запись перезаписывает старую => предыдущий код аннулирован.
            self.store.set(
                OTP_KEY.format(msisdn),
                {"hash": self._hash(msisdn, code), "expires_at": now + self.settings.code_ttl},
                # храним запись дольше TTL, чтобы отличать «истёк» (410) от «нет кода» (401)
                ttl=self.settings.code_ttl + self.settings.send_window,
            )
            sends.append(now)
            self.store.set(SENDS_KEY.format(msisdn), sends, ttl=self.settings.send_window)

            self.sms.deliver(msisdn, code)
            self.log.event(SecurityEvent.OTP_ISSUED, msisdn, ip, send_no=len(sends),
                           expires_in=self.settings.code_ttl)
            return SendResult(
                SendStatus.SENT,
                retry_after=_whole_seconds(self._next_send_in(sends, now)),
                expires_in=self.settings.code_ttl,
            )

    def _check_send_allowed(self, msisdn: str, ip: str, sends: list[float], now: float) -> Optional[SendResult]:
        """None — отправка разрешена, иначе результат с отказом."""
        blocked = self._block_remaining(msisdn, now)
        if blocked is not None:
            retry = _whole_seconds(blocked)
            self.log.event(SecurityEvent.SEND_REJECTED_BLOCKED, msisdn, ip, retry_after=retry)
            return SendResult(SendStatus.BLOCKED, retry_after=retry)

        if len(sends) >= self.settings.send_limit:
            retry = _whole_seconds(self._window_frees_in(sends, now))
            self.log.event(SecurityEvent.SEND_RATE_LIMITED, msisdn, ip, reason="send_limit", retry_after=retry)
            return SendResult(SendStatus.SEND_LIMIT, retry_after=retry)

        if sends:
            wait = sends[-1] + self._resend_delay(len(sends)) - now
            if wait > 0:
                retry = _whole_seconds(wait)
                self.log.event(SecurityEvent.SEND_RATE_LIMITED, msisdn, ip, reason="resend_delay", retry_after=retry)
                return SendResult(SendStatus.RESEND_TOO_EARLY, retry_after=retry)
        return None

    def _resend_delay(self, sends_made: int) -> int:
        """Задержка перед следующей отправкой после sends_made отправок: 30, 60, 120, 120, ..."""
        delays = self.settings.resend_delays
        return delays[min(sends_made, len(delays)) - 1]

    def _window_frees_in(self, sends: list[float], now: float) -> float:
        """Через сколько секунд самая старая отправка выйдет из окна лимита."""
        return sends[0] + self.settings.send_window - now

    def _next_send_in(self, sends: list[float], now: float) -> float:
        if len(sends) >= self.settings.send_limit:
            return self._window_frees_in(sends, now)
        return self._resend_delay(len(sends))

    # ---------- verify ----------

    def verify(self, msisdn: str, code: str, ip: str) -> VerifyResult:
        """Полная проверка: IP-лимит, затем код. HTTP-слой вызывает шаги по отдельности,
        потому что IP-лимит должен списываться и для запросов с ошибкой формата."""
        limited = self.consume_verify_quota(ip, msisdn)
        if limited is not None:
            return limited
        return self.verify_code(msisdn, code, ip)

    def verify_code(self, msisdn: str, code: str, ip: str) -> VerifyResult:
        """Проверка кода без IP-лимита (квоту списывает consume_verify_quota)."""
        with self.store.lock(MSISDN_LOCK.format(msisdn)):
            now = self.clock()

            blocked = self._block_remaining(msisdn, now)
            if blocked is not None:
                retry = _whole_seconds(blocked)
                self.log.event(SecurityEvent.VERIFY_REJECTED_BLOCKED, msisdn, ip, retry_after=retry)
                return VerifyResult(VerifyStatus.BLOCKED, retry_after=retry)

            otp_key = OTP_KEY.format(msisdn)
            record = self.store.get(otp_key)

            if record is not None and now >= record["expires_at"]:
                self.store.delete(otp_key)
                self.log.event(SecurityEvent.VERIFY_EXPIRED, msisdn, ip)
                return VerifyResult(VerifyStatus.EXPIRED)

            if record is None:
                # Кода нет или он уже использован: 401, но в счётчик ошибок не идёт —
                # блокировку считают только неверные коды к активному OTP.
                self.log.event(SecurityEvent.VERIFY_FAILED, msisdn, ip, has_active_code=False)
                return VerifyResult(VerifyStatus.INVALID)

            if hmac.compare_digest(record["hash"], self._hash(msisdn, code)):
                self.store.delete(otp_key)  # код одноразовый
                self.store.delete(FAILS_KEY.format(msisdn))
                self.log.event(SecurityEvent.VERIFY_SUCCESS, msisdn, ip)
                return VerifyResult(VerifyStatus.OK)

            return self._register_failure(msisdn, ip, now)

    def consume_verify_quota(self, ip: str, msisdn: Optional[str] = None) -> Optional[VerifyResult]:
        """Лимит проверок с IP по всем номерам сразу (защита от распределённого перебора).

        Списывается за любой verify, в том числе с ошибкой формата.
        None — квота есть и одна проверка списана, иначе результат с отказом.
        """
        with self.store.lock(IP_LOCK.format(ip)):
            now = self.clock()
            key = IP_VERIFY_KEY.format(ip)
            hits = self._recent(key, self.settings.ip_verify_window, now)
            if len(hits) >= self.settings.ip_verify_limit:
                retry = _whole_seconds(hits[0] + self.settings.ip_verify_window - now)
                self.log.event(SecurityEvent.VERIFY_IP_RATE_LIMITED, msisdn, ip, retry_after=retry)
                return VerifyResult(VerifyStatus.IP_RATE_LIMIT, retry_after=retry)
            hits.append(now)
            self.store.set(key, hits, ttl=self.settings.ip_verify_window)
            return None

    def _register_failure(self, msisdn: str, ip: str, now: float) -> VerifyResult:
        """Неверный код к активному OTP. На max_failed_attempts-й ошибке номер блокируется
        сразу, и уже этот ответ — 423; блокировка действует [now, now + block_duration)."""
        fails_key = FAILS_KEY.format(msisdn)
        fails = (self.store.get(fails_key) or 0) + 1
        attempts_left = self.settings.max_failed_attempts - fails
        self.log.event(SecurityEvent.VERIFY_FAILED, msisdn, ip, failed_attempts=fails, has_active_code=True)

        if attempts_left > 0:
            self.store.set(fails_key, fails, ttl=self.settings.block_duration)
            return VerifyResult(VerifyStatus.INVALID, attempts_left=attempts_left)

        duration = self.settings.block_duration
        self.store.set(BLOCK_KEY.format(msisdn), now + duration, ttl=duration)
        self.store.delete(fails_key)
        self.store.delete(OTP_KEY.format(msisdn))  # текущий код больше не действует
        self.log.event(SecurityEvent.MSISDN_BLOCKED, msisdn, ip, duration=duration,
                       reason="too_many_failed_attempts")
        return VerifyResult(VerifyStatus.BLOCKED, retry_after=duration)

    # ---------- helpers ----------

    def _hash(self, msisdn: str, code: str) -> str:
        # Номер входит в сообщение, чтобы хеш одного номера нельзя было применить к другому.
        message = f"{msisdn}:{code}".encode()
        return hmac.new(self.settings.secret_key, message, hashlib.sha256).hexdigest()

    def _generate_code(self) -> str:
        length = self.settings.code_length
        return f"{secrets.randbelow(10 ** length):0{length}d}"

    def _block_remaining(self, msisdn: str, now: float) -> Optional[float]:
        until = self.store.get(BLOCK_KEY.format(msisdn))
        if until is not None and until > now:
            return until - now
        return None

    def _recent(self, key: str, window: int, now: float) -> list[float]:
        """Отметки времени из key, попадающие в скользящее окно window секунд."""
        return [t for t in (self.store.get(key) or []) if now - t < window]
