"""Слой API без привязки к HTTP-серверу: разбор запроса, валидация, маршруты, коды ответов.

  POST /otp/send   {"msisdn", "service"?}  -> 200 | 400 | 423 | 429
  POST /otp/verify {"msisdn", "code"}      -> 200 | 400 | 401 | 410 | 423 | 429
  GET  /health                             -> 200 | 503
  GET  /dashboard                          -> HTML-дашборд событий безопасности
  GET  /demo                               -> HTML-форма ручной проверки OTP
  POST /demo/send  {"msisdn"}              -> как /otp/send, но с кодом в ответе;
                                              только при OTP_DEMO_SHOW_CODE=1
  GET  /api/security/events                -> JSON для дашборда

Личный кабинет абонента (Authorization: Bearer <token> там, где нужен вход):
  GET  /cabinet                            -> HTML-страница кабинета
  POST /cabinet/code     {"msisdn"}        -> код для входа (как /otp/send)
  POST /cabinet/login    {"msisdn","code"} -> {"token", "expires_in"} (ошибки — как /otp/verify)
  GET  /cabinet/me                         -> статус номера и история запросов кодов
  POST /cabinet/freeze   {"duration"}      -> заморозить выдачу кодов (сек или null)
  POST /cabinet/unfreeze                   -> снять заморозку
  POST /cabinet/logout                     -> завершить сессию
"""
from __future__ import annotations

import hmac
import json
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Callable, Mapping, Optional, Union
from urllib.parse import parse_qs, urlsplit

from .cabinet import FREEZE_DURATIONS, SESSION_TTL, Cabinet
from .otp_service import OTPService, SendResult, SendStatus, VerifyResult, VerifyStatus
from .security_log import SecurityEvent
from .store import StoreUnavailable

MSISDN_RE = re.compile(r"^996\d{9}$")  # строка из 12 цифр, начинается с 996
SERVICE_MAX_LENGTH = 40
EVENTS_DEFAULT_LIMIT = 100
EVENTS_MAX_LIMIT = 1000
STORE_RETRY_AFTER = 5
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

SEND_HTTP_STATUS = {
    SendStatus.SENT: 200,
    SendStatus.RESEND_TOO_EARLY: 429,
    SendStatus.SEND_LIMIT: 429,
    SendStatus.BLOCKED: 423,
    SendStatus.FROZEN: 423,
}

VERIFY_HTTP_STATUS = {
    VerifyStatus.OK: 200,
    VerifyStatus.INVALID: 401,
    VerifyStatus.EXPIRED: 410,
    VerifyStatus.BLOCKED: 423,
    VerifyStatus.IP_RATE_LIMIT: 429,
}


class BadRequest(Exception):
    """Некорректный JSON или формат полей (-> HTTP 400)."""


@dataclass(frozen=True)
class Request:
    method: str
    path: str
    query: Mapping[str, str]
    headers: Mapping[str, str]
    body: bytes
    ip: str

    @classmethod
    def build(cls, method: str, target: str, headers: Mapping[str, str], body: bytes,
              ip: str) -> Request:
        url = urlsplit(target)
        query = {key: values[0] for key, values in parse_qs(url.query).items()}
        return cls(method, url.path.rstrip("/") or "/", query, headers, body, ip)

    def json(self) -> dict:
        try:
            data = json.loads(self.body or b"{}")
        except (ValueError, UnicodeDecodeError):
            raise BadRequest("body must be valid JSON") from None
        if not isinstance(data, dict):
            raise BadRequest("body must be a JSON object")
        return data

    def bearer_token(self) -> str:
        scheme, _, token = (self.headers.get("Authorization") or "").partition(" ")
        return token.strip() if scheme.lower() == "bearer" else ""


@dataclass
class Response:
    status: int
    body: Union[dict, bytes]  # dict сериализуется в JSON, bytes отдаются как есть
    headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def json(cls, status: int, body: dict, retry_after: Optional[int] = None) -> Response:
        """JSON-ответ; для неуспешного с retry_after добавляется заголовок Retry-After."""
        headers = {}
        if retry_after is not None and status != 200:
            headers["Retry-After"] = str(retry_after)
        return cls(status, body, headers)

    @classmethod
    def error(cls, status: int, reason: str, **extra: Any) -> Response:
        return cls(status, {"status": reason, **extra})


def validate_msisdn(value: object) -> str:
    """Номер — строка ровно из 12 цифр, начинается с 996 (без «+», пробелов и т.п.)."""
    if not isinstance(value, str) or not MSISDN_RE.fullmatch(value):
        raise BadRequest("msisdn must be a string of 12 digits starting with 996")
    return value


def validate_code(value: object, length: int) -> str:
    """Код — строка ровно из length цифр; ведущие нули значимы, число не принимается."""
    is_digits = isinstance(value, str) and value.isascii() and value.isdigit()
    if not is_digits or len(value) != length:
        raise BadRequest(f"code must be a string of exactly {length} digits")
    return value


def validate_service(value: object) -> Optional[str]:
    """Необязательное имя сервиса, запросившего код (видно абоненту в истории)."""
    if value is None:
        return None
    if not isinstance(value, str) or not 0 < len(value.strip()) <= SERVICE_MAX_LENGTH \
            or not value.isprintable():
        raise BadRequest(f"service must be a printable string up to {SERVICE_MAX_LENGTH} chars")
    return value.strip()


def _field(body: dict, name: str) -> object:
    if name not in body:
        raise BadRequest(f"field '{name}' is required")
    return body[name]


def _without_none(**fields: Any) -> dict:
    return {name: value for name, value in fields.items() if value is not None}


def _send_response(result: SendResult, show_code: bool = False) -> Response:
    """show_code — только для демо-режима (OTP_DEMO_SHOW_CODE=1): код прямо в ответе."""
    if result.status is SendStatus.SENT:
        payload = _without_none(status=result.status.value, expires_in=result.expires_in,
                                next_send_in=result.retry_after,
                                code=result.demo_code if show_code else None)
    else:
        payload = _without_none(status=result.status.value, retry_after=result.retry_after)
    return Response.json(SEND_HTTP_STATUS[result.status], payload,
                         retry_after=result.retry_after)


def _verify_response(result: VerifyResult, **extra: Any) -> Response:
    payload = _without_none(status=result.status.value, attempts_left=result.attempts_left,
                            retry_after=result.retry_after, **extra)
    return Response.json(VERIFY_HTTP_STATUS[result.status], payload,
                         retry_after=result.retry_after)


@lru_cache(maxsize=None)
def _static_page(name: str) -> bytes:
    with open(os.path.join(STATIC_DIR, name), "rb") as f:
        return f.read()


def _html(name: str) -> Response:
    return Response(200, _static_page(name),
                    {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"})


class OTPApi:
    def __init__(self, service: OTPService, dashboard_token: str = ""):
        self.service = service
        self.cabinet = Cabinet(service)
        self.dashboard_token = dashboard_token
        self._routes: dict[tuple[str, str], Callable[[Request], Response]] = {
            ("GET", "/health"): self.health,
            ("POST", "/otp/send"): self.send,
            ("POST", "/otp/verify"): self.verify,
            ("GET", "/dashboard"): self.dashboard,
            ("GET", "/demo"): self.demo,
            ("GET", "/api/security/events"): self.events,
            ("GET", "/cabinet"): lambda request: _html("cabinet.html"),
            ("POST", "/cabinet/code"): self.cabinet_code,
            ("POST", "/cabinet/login"): self.cabinet_login,
            ("GET", "/cabinet/me"): self._authenticated(self.cabinet_me),
            ("POST", "/cabinet/freeze"): self._authenticated(self.cabinet_freeze),
            ("POST", "/cabinet/unfreeze"): self._authenticated(self.cabinet_unfreeze),
            ("POST", "/cabinet/logout"): self._authenticated(self.cabinet_logout),
        }
        if service.settings.demo_show_code:
            self._routes["POST", "/demo/send"] = self.demo_send
        self._paths = {path for _, path in self._routes}

    def handle(self, request: Request) -> Response:
        route = self._routes.get((request.method, request.path))
        if route is None:
            if request.path in self._paths:
                return Response.error(405, "method_not_allowed")
            return Response.error(404, "not_found")
        try:
            return route(request)
        except BadRequest as error:
            return Response.error(400, "bad_request", error=str(error))
        except StoreUnavailable:
            # Хранилище недоступно: не выдаём и не проверяем коды «вслепую» (fail closed).
            self.service.log.event(SecurityEvent.STORE_UNAVAILABLE, ip=request.ip,
                                   path=request.path)
            return Response.json(503, {"status": "service_unavailable"},
                                 retry_after=STORE_RETRY_AFTER)

    # ---------- OTP ----------

    def send(self, request: Request) -> Response:
        return self._send(request, show_code=False)

    def demo_send(self, request: Request) -> Response:
        response = self._send(request, show_code=True)
        response.headers["Cache-Control"] = "no-store"
        return response

    def _send(self, request: Request, *, show_code: bool) -> Response:
        body = request.json()
        msisdn = validate_msisdn(_field(body, "msisdn"))
        service = validate_service(body.get("service"))
        result = self.service.send(msisdn, request.ip, service=service)
        return _send_response(result, show_code=show_code)

    def verify(self, request: Request) -> Response:
        # IP-лимит списывается первым — до разбора тела, проверки кода и блокировки номера:
        # любой verify, даже с ошибкой формата, расходует квоту IP.
        result = self.service.consume_verify_quota(request.ip)
        if result is None:
            msisdn, code = self._msisdn_and_code(request)
            result = self.service.verify_code(msisdn, code, request.ip)
        return _verify_response(result)

    def _msisdn_and_code(self, request: Request) -> tuple[str, str]:
        body = request.json()
        msisdn = validate_msisdn(_field(body, "msisdn"))
        code = validate_code(_field(body, "code"), self.service.settings.code_length)
        return msisdn, code

    # ---------- личный кабинет ----------

    def cabinet_code(self, request: Request) -> Response:
        msisdn = validate_msisdn(_field(request.json(), "msisdn"))
        return _send_response(self.cabinet.request_code(msisdn, request.ip))

    def cabinet_login(self, request: Request) -> Response:
        # Вход по коду — та же проверка OTP, поэтому и тот же IP-лимит.
        result = self.service.consume_verify_quota(request.ip)
        token = None
        if result is None:
            msisdn, code = self._msisdn_and_code(request)
            result, token = self.cabinet.login(msisdn, code, request.ip)
        if token is None:
            return _verify_response(result)
        return _verify_response(result, token=token, expires_in=SESSION_TTL)

    def _authenticated(self, handler: Callable[[Request, str], Response]
                       ) -> Callable[[Request], Response]:
        """Обёртка маршрута кабинета: пускает только с действующим токеном сессии."""
        def route(request: Request) -> Response:
            msisdn = self.cabinet.session_msisdn(request.bearer_token())
            if msisdn is None:
                return Response.error(401, "unauthorized")
            return handler(request, msisdn)
        return route

    def cabinet_me(self, request: Request, msisdn: str) -> Response:
        return Response(200, self.cabinet.overview(msisdn), {"Cache-Control": "no-store"})

    def cabinet_freeze(self, request: Request, msisdn: str) -> Response:
        duration = request.json().get("duration")
        if isinstance(duration, bool) or duration not in FREEZE_DURATIONS:
            raise BadRequest(f"duration must be one of {list(FREEZE_DURATIONS)}")
        self.cabinet.freeze(msisdn, request.ip, duration)
        return self.cabinet_me(request, msisdn)

    def cabinet_unfreeze(self, request: Request, msisdn: str) -> Response:
        self.cabinet.unfreeze(msisdn, request.ip)
        return self.cabinet_me(request, msisdn)

    def cabinet_logout(self, request: Request, msisdn: str) -> Response:
        self.cabinet.logout(request.bearer_token())
        return Response(200, {"status": "logged_out"})

    # ---------- служебное ----------

    def health(self, request: Request) -> Response:
        store = self.service.store
        try:
            store.ping()
        except StoreUnavailable:
            return Response(503, {"status": "degraded", "storage": store.name})
        return Response(200, {"status": "ok", "storage": store.name})

    def dashboard(self, request: Request) -> Response:
        if not self._authorized(request):
            return Response.error(401, "unauthorized")
        return _html("dashboard.html")

    def demo(self, request: Request) -> Response:
        return _html("demo.html")

    def events(self, request: Request) -> Response:
        if not self._authorized(request):
            return Response.error(401, "unauthorized")
        try:
            limit = int(request.query.get("limit", EVENTS_DEFAULT_LIMIT))
        except ValueError:
            raise BadRequest("limit must be an integer") from None
        data = self.service.log.snapshot(limit=max(1, min(limit, EVENTS_MAX_LIMIT)))
        data["storage"] = self.service.store.name
        return Response(200, data, {"Cache-Control": "no-store"})

    def _authorized(self, request: Request) -> bool:
        if not self.dashboard_token:
            return True
        given = request.query.get("token") or request.headers.get("X-Dashboard-Token") or ""
        return hmac.compare_digest(given.encode(), self.dashboard_token.encode())
