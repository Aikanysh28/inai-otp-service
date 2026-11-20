"""Бизнес-логика OTP: генерация, хранение хеша, проверка, лимиты и блокировки."""
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
from .security_log import SecurityLog
from .store import MemoryStore, RedisStore


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


@dataclass
class SendResult:
    status: SendStatus
    retry_after: Optional[int] = None  # сек. до следующей разрешённой отправки
    expires_in: Optional[int] = None
    code: Optional[str] = None  # заполняется только при debug_return_code


@dataclass
class VerifyResult:
    status: VerifyStatus
    retry_after: Optional[int] = None
    attempts_left: Optional[int] = None


def _ceil(seconds: float) -> int:
    return max(1, math.ceil(seconds))


class OTPService:
    def __init__(
        self,
        settings: Settings,
        log: SecurityLog,
        clock: Callable[[], float] = time.time,
        store: Optional[MemoryStore | RedisStore] = None,
    ):
        self.s = settings
        self.log = log
        self.clock = clock
        self.store = store or MemoryStore(clock)
        # Все изменения состояния номера идут под store.lock(msisdn): «прочитать-проверить-записать»
        # атомарно, поэтому из параллельных verify с верным кодом успешен ровно один.
        # Блокировки берутся по очереди, а не вложенно — взаимоблокировка невозможна.

    # ---------- helpers ----------

    def _hash(self, msisdn: str, code: str) -> str:
        # Номер входит в сообщение, чтобы хеш одного номера нельзя было применить к другому.
        msg = f"{msisdn}:{code}".encode()
        return hmac.new(self.s.secret_key, msg, hashlib.sha256).hexdigest()

    def _generate_code(self) -> str:
        return f"{secrets.randbelow(10 ** self.s.code_length):0{self.s.code_length}d}"

    def _block_remaining(self, msisdn: str, now: float) -> Optional[float]:
        until = self.store.get(f"block:{msisdn}")
        if until is not None and until > now:
            return until - now
        return None

    def _recent(self, key: str, window: int, now: float) -> list[float]:
        return [t for t in (self.store.get(key) or []) if now - t < window]

    # ---------- send ----------

    def send(self, msisdn: str, ip: str) -> SendResult:
        with self.store.lock(f"msisdn:{msisdn}"):
            now = self.clock()

            blocked = self._block_remaining(msisdn, now)
            if blocked is not None:
                self.log.event("send_rejected_blocked", msisdn, ip, retry_after=_ceil(blocked))
                return SendResult(SendStatus.BLOCKED, retry_after=_ceil(blocked))

            sends_key = f"sends:{msisdn}"
            sends = self._recent(sends_key, self.s.send_window, now)

            if len(sends) >= self.s.send_limit:
                retry = sends[0] + self.s.send_window - now
                self.log.event("send_rate_limited", msisdn, ip, reason="send_limit", retry_after=_ceil(retry))
                return SendResult(SendStatus.SEND_LIMIT, retry_after=_ceil(retry))

            if sends:
                delay = self.s.resend_delays[min(len(sends), len(self.s.resend_delays)) - 1]
                wait = sends[-1] + delay - now
                if wait > 0:
                    self.log.event("send_rate_limited", msisdn, ip, reason="resend_delay", retry_after=_ceil(wait))
                    return SendResult(SendStatus.RESEND_TOO_EARLY, retry_after=_ceil(wait))

            code = self._generate_code()
            # Новая запись перезаписывает старую => предыдущий код аннулирован.
            self.store.set(
                f"otp:{msisdn}",
                {"hash": self._hash(msisdn, code), "expires_at": now + self.s.code_ttl},
                # храним запись дольше TTL, чтобы отличать «истёк» (410) от «нет кода» (401)
                ttl=self.s.code_ttl + self.s.send_window,
            )
            sends.append(now)
            self.store.set(sends_key, sends, ttl=self.s.send_window)

            if len(sends) >= self.s.send_limit:
                next_in = sends[0] + self.s.send_window - now
            else:
                next_in = self.s.resend_delays[min(len(sends), len(self.s.resend_delays)) - 1]

            self.log.deliver_sms(msisdn, code)
            self.log.event("otp_issued", msisdn, ip, send_no=len(sends), expires_in=self.s.code_ttl)

            return SendResult(
                SendStatus.SENT,
                retry_after=_ceil(next_in),
                expires_in=self.s.code_ttl,
                code=code if self.s.debug_return_code else None,
            )

    # ---------- verify ----------

    def _take_ip_slot(self, msisdn: str, ip: str) -> Optional[VerifyResult]:
        """Лимит по IP — по всем номерам сразу (защита от распределённого перебора)."""
        with self.store.lock(f"ip:{ip}"):
            now = self.clock()
            ip_key = f"ipverify:{ip}"
            hits = self._recent(ip_key, self.s.ip_verify_window, now)
            if len(hits) >= self.s.ip_verify_limit:
                retry = _ceil(hits[0] + self.s.ip_verify_window - now)
                self.log.event("verify_ip_rate_limited", msisdn, ip, retry_after=retry)
                return VerifyResult(VerifyStatus.IP_RATE_LIMIT, retry_after=retry)
            hits.append(now)
            self.store.set(ip_key, hits, ttl=self.s.ip_verify_window)
            return None

    def verify(self, msisdn: str, code: str, ip: str) -> VerifyResult:
        # 1. Лимит по IP.
        limited = self._take_ip_slot(msisdn, ip)
        if limited is not None:
            return limited

        with self.store.lock(f"msisdn:{msisdn}"):
            now = self.clock()

            # 2. Блокировка номера.
            blocked = self._block_remaining(msisdn, now)
            if blocked is not None:
                self.log.event("verify_rejected_blocked", msisdn, ip, retry_after=_ceil(blocked))
                return VerifyResult(VerifyStatus.BLOCKED, retry_after=_ceil(blocked))

            otp_key = f"otp:{msisdn}"
            record = self.store.get(otp_key)

            # 3. Истёкший код.
            if record is not None and now >= record["expires_at"]:
                self.store.delete(otp_key)
                self.log.event("verify_expired", msisdn, ip)
                return VerifyResult(VerifyStatus.EXPIRED)

            # 4. Сравнение за постоянное время.
            if record is not None and hmac.compare_digest(record["hash"], self._hash(msisdn, code)):
                self.store.delete(otp_key)  # одноразовый
                self.store.delete(f"fails:{msisdn}")
                self.log.event("verify_success", msisdn, ip)
                return VerifyResult(VerifyStatus.OK)

            # 5. Неверный код (или кода нет / уже использован) — считаем попытку.
            fails_key = f"fails:{msisdn}"
            fails = (self.store.get(fails_key) or 0) + 1
            attempts_left = self.s.max_failed_attempts - fails
            self.log.event("verify_failed", msisdn, ip, failed_attempts=fails, has_active_code=record is not None)

            if attempts_left <= 0:
                self.store.set(f"block:{msisdn}", now + self.s.block_duration, ttl=self.s.block_duration)
                self.store.delete(fails_key)
                self.store.delete(otp_key)  # текущий код больше не действует
                self.log.event("msisdn_blocked", msisdn, ip, duration=self.s.block_duration, reason="too_many_failed_attempts")
                return VerifyResult(VerifyStatus.INVALID, attempts_left=0)

            self.store.set(fails_key, fails, ttl=self.s.block_duration)
            return VerifyResult(VerifyStatus.INVALID, attempts_left=attempts_left)
