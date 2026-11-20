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
from .security_log import SecurityEvent, SecurityLog
from .sms import SmsGateway
from .store import MemoryStore, Store

# Ключи хранилища ({} — номер или IP)
OTP_KEY = "otp:{}"  # HMAC кода и срок его действия
SENDS_KEY = "sends:{}"  # отметки времени отправок за окно
FAILS_KEY = "fails:{}"  # число неверных вводов подряд
BLOCK_KEY = "block:{}"  # время окончания блокировки номера
FREEZE_KEY = "freeze:{}"  # заморозка кодов владельцем номера: {"since", "until"}
HISTORY_KEY = "history:{}"  # последние события номера для личного кабинета
IP_VERIFY_KEY = "ipverify:{}"  # отметки времени проверок с IP за окно
MSISDN_LOCK = "msisdn:{}"
IP_LOCK = "ip:{}"

HISTORY_LIMIT = 50
HISTORY_TTL = 30 * 24 * 3600

# Назначение кода. Заморозка владельцем действует только на коды для внешних сервисов;
# код для входа в личный кабинет выдаётся и при заморозке — иначе её нельзя было бы снять.
# У кодов кабинета свои код и счётчик выдач (те же лимиты), чтобы злоумышленник, заваливая
# номер запросами кодов, не мог помешать владельцу войти в кабинет. Блокировка — общая.
DEFAULT_SCOPE = "otp"
CABINET_SCOPE = "cabinet"


def scoped_key(template: str, msisdn: str, scope: str = DEFAULT_SCOPE) -> str:
    key = template.format(msisdn)
    return key if scope == DEFAULT_SCOPE else f"{scope}:{key}"


def otp_key(msisdn: str, scope: str = DEFAULT_SCOPE) -> str:
    return scoped_key(OTP_KEY, msisdn, scope)


class SendStatus(str, Enum):
    SENT = "sent"
    RESEND_TOO_EARLY = "resend_too_early"
    SEND_LIMIT = "send_limit_exceeded"
    BLOCKED = "msisdn_blocked"
    FROZEN = "msisdn_frozen"


class VerifyStatus(str, Enum):
    OK = "verified"
    INVALID = "invalid_code"
    EXPIRED = "code_expired"
    BLOCKED = "msisdn_blocked"
    IP_RATE_LIMIT = "ip_rate_limited"


@dataclass(frozen=True)
class SendResult:
    status: SendStatus
    # Для отказа — через сколько секунд повторить; для успеха — когда разрешена следующая выдача.
    retry_after: Optional[int] = None
    expires_in: Optional[int] = None
    demo_code: Optional[str] = None


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

    def send(self, msisdn: str, ip: str, scope: str = DEFAULT_SCOPE,
             service: Optional[str] = None) -> SendResult:
        """Выдать код. service — необязательное имя сервиса-заказчика для истории абонента."""
        with self.store.lock(MSISDN_LOCK.format(msisdn)):
            now = self.clock()
            sends_key = scoped_key(SENDS_KEY, msisdn, scope)
            sends = self._recent(sends_key, self.settings.send_window, now)
            details = {"scope": scope} if scope != DEFAULT_SCOPE else {}
            if service:
                details["service"] = service

            rejected = self._check_send_allowed(msisdn, ip, sends, now, scope, details)
            if rejected is not None:
                return rejected

            code = self._generate_code()
            ttl = self.settings.code_ttl
            # Новая запись перезаписывает старую => предыдущий код аннулирован.
            # Храним запись дольше TTL, чтобы отличать «истёк» (410) от «нет кода» (401).
            self.store.set(
                otp_key(msisdn, scope),
                {"hash": self._hash(msisdn, code), "expires_at": now + ttl},
                ttl=ttl + self.settings.send_window,
            )
            sends.append(now)
            self.store.set(sends_key, sends, ttl=self.settings.send_window)

            self.sms.deliver(msisdn, code)
            self.record_event(SecurityEvent.OTP_ISSUED, msisdn, ip, send_no=len(sends),
                              expires_in=ttl, **details)
            return SendResult(
                SendStatus.SENT,
                retry_after=_whole_seconds(self._next_send_in(sends, now)),
                expires_in=ttl,
                demo_code=code if self.settings.demo_show_code else None,
            )

    def _check_send_allowed(self, msisdn: str, ip: str, sends: list[float], now: float,
                            scope: str, details: dict) -> Optional[SendResult]:
        """None — отправка разрешена, иначе результат с отказом.

        details (назначение кода, имя сервиса) попадают в событие отказа — абонент увидит
        в кабинете, какой сервис пытался запросить код.
        """
        blocked = self._block_remaining(msisdn, now)
        if blocked is not None:
            return self._reject_send(SendStatus.BLOCKED, SecurityEvent.SEND_REJECTED_BLOCKED,
                                     msisdn, ip, blocked, **details)

        freeze = self.freeze_status(msisdn, now) if scope == DEFAULT_SCOPE else None
        if freeze is not None:
            remaining = None if freeze["until"] is None else freeze["until"] - now
            return self._reject_send(SendStatus.FROZEN, SecurityEvent.SEND_REJECTED_FROZEN,
                                     msisdn, ip, remaining, **details)

        if len(sends) >= self.settings.send_limit:
            return self._reject_send(SendStatus.SEND_LIMIT, SecurityEvent.SEND_RATE_LIMITED,
                                     msisdn, ip, self._window_frees_in(sends, now),
                                     reason="send_limit", **details)

        if sends:
            wait = sends[-1] + self._resend_delay(len(sends)) - now
            if wait > 0:
                return self._reject_send(SendStatus.RESEND_TOO_EARLY,
                                         SecurityEvent.SEND_RATE_LIMITED, msisdn, ip, wait,
                                         reason="resend_delay", **details)
        return None

    def _reject_send(self, status: SendStatus, event: SecurityEvent, msisdn: str, ip: str,
                     wait: Optional[float], **details) -> SendResult:
        """wait=None — срок неизвестен (бессрочная заморозка), Retry-After не выставляется."""
        retry = None if wait is None else _whole_seconds(wait)
        self.record_event(event, msisdn, ip, **details, retry_after=retry)
        return SendResult(status, retry_after=retry)

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
        """Полная проверка: IP-лимит, затем код.

        HTTP-слой вызывает шаги по отдельности, потому что IP-лимит должен списываться
        и для запросов с ошибкой формата.
        """
        limited = self.consume_verify_quota(ip, msisdn)
        if limited is not None:
            return limited
        return self.verify_code(msisdn, code, ip)

    def consume_verify_quota(self, ip: str,
                             msisdn: Optional[str] = None) -> Optional[VerifyResult]:
        """Лимит проверок с IP по всем номерам сразу (защита от распределённого перебора).

        Списывается за любой verify, в том числе с ошибкой формата.
        None — квота есть и одна проверка списана, иначе результат с отказом.
        """
        window = self.settings.ip_verify_window
        with self.store.lock(IP_LOCK.format(ip)):
            now = self.clock()
            key = IP_VERIFY_KEY.format(ip)
            hits = self._recent(key, window, now)
            if len(hits) >= self.settings.ip_verify_limit:
                retry = _whole_seconds(hits[0] + window - now)
                # Не под блокировкой номера, поэтому только в общий журнал, без истории номера.
                self.log.event(SecurityEvent.VERIFY_IP_RATE_LIMITED, msisdn, ip,
                               retry_after=retry)
                return VerifyResult(VerifyStatus.IP_RATE_LIMIT, retry_after=retry)
            hits.append(now)
            self.store.set(key, hits, ttl=window)
            return None

    def verify_code(self, msisdn: str, code: str, ip: str,
                    scope: str = DEFAULT_SCOPE) -> VerifyResult:
        """Проверка кода без IP-лимита (квоту списывает consume_verify_quota)."""
        with self.store.lock(MSISDN_LOCK.format(msisdn)):
            now = self.clock()

            blocked = self._block_remaining(msisdn, now)
            if blocked is not None:
                retry = _whole_seconds(blocked)
                self.record_event(SecurityEvent.VERIFY_REJECTED_BLOCKED, msisdn, ip,
                                  retry_after=retry)
                return VerifyResult(VerifyStatus.BLOCKED, retry_after=retry)

            key = otp_key(msisdn, scope)
            record = self.store.get(key)

            if record is None:
                # Кода нет или он уже использован: 401, но в счётчик ошибок не идёт —
                # блокировку считают только неверные коды к активному OTP.
                self.record_event(SecurityEvent.VERIFY_FAILED, msisdn, ip, has_active_code=False)
                return VerifyResult(VerifyStatus.INVALID)

            if now >= record["expires_at"]:
                self.store.delete(key)
                self.record_event(SecurityEvent.VERIFY_EXPIRED, msisdn, ip)
                return VerifyResult(VerifyStatus.EXPIRED)

            if hmac.compare_digest(record["hash"], self._hash(msisdn, code)):
                self.store.delete(key)  # код одноразовый
                self.store.delete(FAILS_KEY.format(msisdn))
                self.record_event(SecurityEvent.VERIFY_SUCCESS, msisdn, ip)
                return VerifyResult(VerifyStatus.OK)

            return self._register_failure(msisdn, ip, now, scope)

    def _register_failure(self, msisdn: str, ip: str, now: float,
                          scope: str = DEFAULT_SCOPE) -> VerifyResult:
        """Неверный код к активному OTP.

        На max_failed_attempts-й ошибке номер блокируется сразу, и уже этот ответ — 423;
        блокировка действует [now, now + block_duration).
        """
        fails_key = FAILS_KEY.format(msisdn)
        fails = (self.store.get(fails_key) or 0) + 1
        attempts_left = self.settings.max_failed_attempts - fails
        self.record_event(SecurityEvent.VERIFY_FAILED, msisdn, ip, failed_attempts=fails,
                          has_active_code=True)

        if attempts_left > 0:
            self.store.set(fails_key, fails, ttl=self.settings.block_duration)
            return VerifyResult(VerifyStatus.INVALID, attempts_left=attempts_left)

        duration = self.settings.block_duration
        self.store.set(BLOCK_KEY.format(msisdn), now + duration, ttl=duration)
        self.store.delete(fails_key)
        self.store.delete(otp_key(msisdn, scope))  # текущий код больше не действует
        self.record_event(SecurityEvent.MSISDN_BLOCKED, msisdn, ip, duration=duration,
                          reason="too_many_failed_attempts")
        return VerifyResult(VerifyStatus.BLOCKED, retry_after=duration)

    # ---------- состояние номера для личного кабинета ----------

    def record_event(self, event: SecurityEvent, msisdn: str, ip: Optional[str],
                     **details) -> None:
        """Событие в журнал безопасности и в историю номера.

        Вызывать под store.lock(MSISDN_LOCK) этого номера: история дописывается
        по схеме «прочитать-изменить-записать».
        """
        self.log.event(event, msisdn, ip, **details)
        key = HISTORY_KEY.format(msisdn)
        entry = {"ts": self.clock(), "event": event.value, "ip": ip, **details}
        history = (self.store.get(key) or [])[-(HISTORY_LIMIT - 1):]
        self.store.set(key, history + [entry], ttl=HISTORY_TTL)

    def history(self, msisdn: str) -> list[dict]:
        """События номера, от новых к старым."""
        return list(reversed(self.store.get(HISTORY_KEY.format(msisdn)) or []))

    def freeze_status(self, msisdn: str, now: Optional[float] = None) -> Optional[dict]:
        """{"since", "until"} действующей заморозки (until=None — бессрочно) или None."""
        now = self.clock() if now is None else now
        freeze = self.store.get(FREEZE_KEY.format(msisdn))
        if freeze is None or (freeze["until"] is not None and freeze["until"] <= now):
            return None
        return freeze

    def blocked_until(self, msisdn: str) -> Optional[float]:
        until = self.store.get(BLOCK_KEY.format(msisdn))
        return until if until is not None and until > self.clock() else None

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
