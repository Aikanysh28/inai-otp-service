"""Слой API, не зависящий от HTTP-сервера: разбор запроса, валидация, маршрутизация, коды ответов.

  POST /otp/send   {"msisdn"}          -> 200 | 429
  POST /otp/verify {"msisdn", "code"}  -> 200 | 401 | 410 | 423 | 429
  GET  /health                         -> 200 | 503
  GET  /dashboard                      -> HTML-дашборд событий безопасности
  GET  /api/security/events            -> JSON для дашборда
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

from .otp_service import OTPService, SendStatus, VerifyStatus
from .security_log import SecurityEvent
from .store import StoreUnavailable

MSISDN_RE = re.compile(r"^\d{10,15}$")
MSISDN_SEPARATORS_RE = re.compile(r"[\s\-()]")
MAX_CODE_CHARS = 32  # неверный по формату код — просто неверный код, но мегабайты не сравниваем
EVENTS_DEFAULT_LIMIT = 100
EVENTS_MAX_LIMIT = 1000
STORE_RETRY_AFTER = 5
DASHBOARD_HTML = os.path.join(os.path.dirname(__file__), "static", "dashboard.html")

SEND_HTTP_STATUS = {
    SendStatus.SENT: 200,
    SendStatus.RESEND_TOO_EARLY: 429,
    SendStatus.SEND_LIMIT: 429,
    SendStatus.BLOCKED: 429,
}

VERIFY_HTTP_STATUS = {
    VerifyStatus.OK: 200,
    VerifyStatus.INVALID: 401,
    VerifyStatus.EXPIRED: 410,
    VerifyStatus.BLOCKED: 423,
    VerifyStatus.IP_RATE_LIMIT: 429,
}


class BadRequest(Exception):
    """Некорректный запрос клиента (-> HTTP 422)."""


@dataclass(frozen=True)
class Request:
    method: str
    path: str
    query: Mapping[str, str]
    headers: Mapping[str, str]
    body: bytes
    ip: str

    @classmethod
    def build(cls, method: str, target: str, headers: Mapping[str, str], body: bytes, ip: str) -> "Request":
        url = urlsplit(target)
        query = {key: values[0] for key, values in parse_qs(url.query).items()}
        return cls(method, url.path.rstrip("/") or "/", query, headers, body, ip)

    def json(self) -> dict:
        try:
            data = json.loads(self.body or b"{}")
        except (ValueError, UnicodeDecodeError):
            raise BadRequest("body must be valid JSON")
        if not isinstance(data, dict):
            raise BadRequest("body must be a JSON object")
        return data


@dataclass
class Response:
    status: int
    body: Union[dict, bytes]  # dict сериализуется в JSON, bytes отдаются как есть
    headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def json(cls, status: int, body: dict, retry_after: Optional[int] = None, **headers: str) -> "Response":
        if retry_after is not None and status != 200:
            headers["Retry-After"] = str(retry_after)
        return cls(status, body, headers)

    @classmethod
    def error(cls, status: int, reason: str, **extra: Any) -> "Response":
        return cls(status, {"status": reason, **extra})


def normalize_msisdn(value: object) -> str:
    """Принимает 996555123456, +996 555 123-456 и т.п.; возвращает только цифры."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise BadRequest("msisdn must be a string")
    digits = MSISDN_SEPARATORS_RE.sub("", str(value)).removeprefix("+")
    if not MSISDN_RE.match(digits):
        raise BadRequest("msisdn must contain 10-15 digits, e.g. 996555123456")
    return digits


def normalize_code(value: object, length: int) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise BadRequest("code must be a string of digits")
    if isinstance(value, int):
        # int теряет ведущие нули (012345 -> 12345), восстанавливаем
        return f"{value:0{length}d}"
    return value.strip()[:MAX_CODE_CHARS]


def _require(body: dict, *fields: str) -> None:
    for name in fields:
        if name not in body:
            raise BadRequest(f"field '{name}' is required")


@lru_cache(maxsize=1)
def _dashboard_page() -> bytes:
    with open(DASHBOARD_HTML, "rb") as f:
        return f.read()


class OTPApi:
    def __init__(self, service: OTPService, dashboard_token: str = ""):
        self.service = service
        self.dashboard_token = dashboard_token
        self._routes: dict[tuple[str, str], Callable[[Request], Response]] = {
            ("GET", "/health"): self.health,
            ("POST", "/otp/send"): self.send,
            ("POST", "/otp/verify"): self.verify,
            ("GET", "/dashboard"): self.dashboard,
            ("GET", "/api/security/events"): self.events,
        }
        self._paths = {path for _, path in self._routes}

    def handle(self, request: Request) -> Response:
        route = self._routes.get((request.method, request.path))
        if route is None:
            if request.path in self._paths:
                return Response.error(405, "method_not_allowed")
            return Response.error(404, "not_found")
        try:
            return route(request)
        except BadRequest as e:
            return Response.error(422, "bad_request", error=str(e))
        except StoreUnavailable:
            # Хранилище недоступно: не выдаём и не проверяем коды «вслепую» (fail closed).
            self.service.log.event(SecurityEvent.STORE_UNAVAILABLE, ip=request.ip, path=request.path)
            return Response.json(503, {"status": "service_unavailable"}, retry_after=STORE_RETRY_AFTER)

    # ---------- OTP ----------

    def send(self, request: Request) -> Response:
        body = request.json()
        _require(body, "msisdn")
        result = self.service.send(normalize_msisdn(body["msisdn"]), request.ip)

        payload: dict = {"status": result.status.value}
        if result.status is SendStatus.SENT:
            payload.update(expires_in=result.expires_in, next_send_in=result.retry_after)
            if result.code is not None:
                payload["code"] = result.code
        else:
            payload["retry_after"] = result.retry_after
        return Response.json(SEND_HTTP_STATUS[result.status], payload, retry_after=result.retry_after)

    def verify(self, request: Request) -> Response:
        body = request.json()
        _require(body, "msisdn", "code")
        msisdn = normalize_msisdn(body["msisdn"])
        code = normalize_code(body["code"], self.service.settings.code_length)
        result = self.service.verify(msisdn, code, request.ip)

        payload = {
            "status": result.status.value,
            "attempts_left": result.attempts_left,
            "retry_after": result.retry_after,
        }
        payload = {key: value for key, value in payload.items() if value is not None}
        return Response.json(VERIFY_HTTP_STATUS[result.status], payload, retry_after=result.retry_after)

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
        return Response(200, _dashboard_page(),
                        {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"})

    def events(self, request: Request) -> Response:
        if not self._authorized(request):
            return Response.error(401, "unauthorized")
        try:
            limit = int(request.query.get("limit", EVENTS_DEFAULT_LIMIT))
        except ValueError:
            raise BadRequest("limit must be an integer")
        data = self.service.log.snapshot(limit=max(1, min(limit, EVENTS_MAX_LIMIT)))
        data["storage"] = self.service.store.name
        return Response(200, data, {"Cache-Control": "no-store"})

    def _authorized(self, request: Request) -> bool:
        if not self.dashboard_token:
            return True
        given = request.query.get("token") or request.headers.get("X-Dashboard-Token") or ""
        return hmac.compare_digest(given.encode(), self.dashboard_token.encode())
