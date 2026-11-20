"""REST API на стандартной библиотеке (без внешних зависимостей).

  POST /otp/send   {"msisdn"}          -> 200 | 429
  POST /otp/verify {"msisdn", "code"}  -> 200 | 401 | 410 | 423 | 429
  GET  /health                         -> 200
  GET  /dashboard                      -> HTML-дашборд событий безопасности
  GET  /api/security/events            -> JSON для дашборда

Логика маршрутизации отделена от HTTP-сервера (OTPApi.handle), чтобы её
можно было тестировать без сети.
"""
from __future__ import annotations

import hmac
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Mapping, Optional, Union
from urllib.parse import parse_qs, urlsplit

from .config import Settings
from .otp_service import OTPService, SendStatus, VerifyStatus
from .security_log import SecurityLog
from .store import MemoryStore, RedisStore, StoreUnavailable

MSISDN_RE = re.compile(r"^\d{10,15}$")
CODE_RE = re.compile(r"^\d{1,12}$")
MAX_BODY = 4096
DASHBOARD_HTML = os.path.join(os.path.dirname(__file__), "static", "dashboard.html")

SEND_HTTP = {
    SendStatus.SENT: 200,
    SendStatus.RESEND_TOO_EARLY: 429,
    SendStatus.SEND_LIMIT: 429,
    SendStatus.BLOCKED: 429,
}

VERIFY_HTTP = {
    VerifyStatus.OK: 200,
    VerifyStatus.INVALID: 401,
    VerifyStatus.EXPIRED: 410,
    VerifyStatus.BLOCKED: 423,
    VerifyStatus.IP_RATE_LIMIT: 429,
}

# (http status, тело: dict -> JSON или bytes -> как есть, заголовки)
Response = tuple[int, Union[dict, bytes], dict]


class BadRequest(Exception):
    pass


def normalize_msisdn(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise BadRequest("msisdn must be a string")
    raw = re.sub(r"[\s\-()]", "", str(value))
    if raw.startswith("+"):
        raw = raw[1:]
    if not MSISDN_RE.match(raw):
        raise BadRequest("msisdn must contain 10-15 digits, e.g. 996555123456")
    return raw


def normalize_code(value: object) -> str:
    if isinstance(value, bool):
        raise BadRequest("code must be a string of digits")
    if isinstance(value, int):
        # int теряет ведущие нули (012345 -> 12345), восстанавливаем
        return f"{value:06d}"
    if isinstance(value, str):
        # неверный по формату код = просто неверный код (401), но мусор длиной в мегабайт не пускаем
        return value.strip()[:32]
    raise BadRequest("code must be a string of digits")


def _with_retry(status: int, body: dict, retry_after: Optional[int]) -> Response:
    headers = {}
    if retry_after is not None and status != 200:
        headers["Retry-After"] = str(retry_after)
    return status, body, headers


class OTPApi:
    def __init__(self, service: OTPService, dashboard_token: str = ""):
        self.service = service
        self.dashboard_token = dashboard_token

    def handle(self, method: str, path: str, raw_body: bytes, ip: str,
               headers: Optional[Mapping[str, str]] = None) -> Response:
        url = urlsplit(path)
        path = url.path.rstrip("/") or "/"
        query = {k: v[0] for k, v in parse_qs(url.query).items()}
        headers = headers or {}
        routes = {
            ("GET", "/health"): lambda _: self.health(),
            ("POST", "/otp/send"): lambda b: self.send(b, ip),
            ("POST", "/otp/verify"): lambda b: self.verify(b, ip),
            ("GET", "/dashboard"): lambda _: self.dashboard(query, headers),
            ("GET", "/api/security/events"): lambda _: self.events(query, headers),
        }
        route = routes.get((method, path))
        if route is None:
            known = {p for _, p in routes}
            if path in known:
                return 405, {"status": "method_not_allowed"}, {}
            return 404, {"status": "not_found"}, {}
        try:
            body = self._parse(raw_body) if method == "POST" else {}
            return route(body)
        except BadRequest as e:
            return 422, {"status": "bad_request", "error": str(e)}, {}
        except StoreUnavailable:
            # Хранилище недоступно: не выдаём и не проверяем коды «вслепую» (fail closed).
            self.service.log.event("store_unavailable", ip=ip, path=path)
            return 503, {"status": "service_unavailable"}, {"Retry-After": "5"}

    def health(self) -> Response:
        store = self.service.store
        try:
            store.ping()
        except StoreUnavailable:
            return 503, {"status": "degraded", "storage": store.name}, {}
        return 200, {"status": "ok", "storage": store.name}, {}

    # ---------- дашборд ----------

    def _authorized(self, query: dict, headers: Mapping[str, str]) -> bool:
        if not self.dashboard_token:
            return True
        given = query.get("token") or headers.get("X-Dashboard-Token") or ""
        return hmac.compare_digest(given.encode(), self.dashboard_token.encode())

    def dashboard(self, query: dict, headers: Mapping[str, str]) -> Response:
        if not self._authorized(query, headers):
            return 401, {"status": "unauthorized"}, {}
        with open(DASHBOARD_HTML, "rb") as f:
            return 200, f.read(), {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"}

    def events(self, query: dict, headers: Mapping[str, str]) -> Response:
        if not self._authorized(query, headers):
            return 401, {"status": "unauthorized"}, {}
        try:
            limit = max(1, min(int(query.get("limit", 100)), 1000))
        except ValueError:
            raise BadRequest("limit must be an integer")
        data = self.service.log.snapshot(limit=limit)
        data["storage"] = self.service.store.name
        return 200, data, {"Cache-Control": "no-store"}

    @staticmethod
    def _parse(raw: bytes) -> dict:
        try:
            body = json.loads(raw or b"{}")
        except (ValueError, UnicodeDecodeError):
            raise BadRequest("body must be valid JSON")
        if not isinstance(body, dict):
            raise BadRequest("body must be a JSON object")
        return body

    def send(self, body: dict, ip: str) -> Response:
        if "msisdn" not in body:
            raise BadRequest("field 'msisdn' is required")
        msisdn = normalize_msisdn(body["msisdn"])
        result = self.service.send(msisdn, ip)
        payload: dict = {"status": result.status.value}
        if result.status is SendStatus.SENT:
            payload["expires_in"] = result.expires_in
            payload["next_send_in"] = result.retry_after
            if result.code is not None:
                payload["code"] = result.code
        else:
            payload["retry_after"] = result.retry_after
        return _with_retry(SEND_HTTP[result.status], payload, result.retry_after)

    def verify(self, body: dict, ip: str) -> Response:
        for field in ("msisdn", "code"):
            if field not in body:
                raise BadRequest(f"field '{field}' is required")
        msisdn = normalize_msisdn(body["msisdn"])
        code = normalize_code(body["code"])
        result = self.service.verify(msisdn, code, ip)
        payload: dict = {"status": result.status.value}
        if result.attempts_left is not None:
            payload["attempts_left"] = result.attempts_left
        if result.retry_after is not None:
            payload["retry_after"] = result.retry_after
        return _with_retry(VERIFY_HTTP[result.status], payload, result.retry_after)


def make_handler(api: OTPApi):
    class Handler(BaseHTTPRequestHandler):
        server_version = "OTPService/1.0"
        sys_version = ""

        def _dispatch(self, method: str):
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                status, body, headers = 413, {"status": "payload_too_large"}, {}
            else:
                raw = self.rfile.read(length) if length else b""
                # X-Forwarded-For намеренно не используется: его подделывает атакующий.
                status, body, headers = api.handle(method, self.path, raw, self.client_address[0], self.headers)
            if isinstance(body, bytes):
                data = body
            else:
                data = json.dumps(body, ensure_ascii=False).encode()
                headers.setdefault("Content-Type", "application/json; charset=utf-8")
            self.send_response(status)
            self.send_header("Content-Length", str(len(data)))
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def log_message(self, fmt, *args):
            # access-лог отключён: под атакой тысячи строк в консоли мешают видеть SMS и события
            pass

    return Handler


def create_server(settings: Optional[Settings] = None, service: Optional[OTPService] = None,
                  host: Optional[str] = None, port: Optional[int] = None) -> ThreadingHTTPServer:
    settings = settings or Settings()
    if service is None:
        service = OTPService(settings, SecurityLog(settings.log_dir), store=build_store(settings))
    server = ThreadingHTTPServer(
        (host if host is not None else settings.host, port if port is not None else settings.port),
        make_handler(OTPApi(service, settings.dashboard_token)),
    )
    server.daemon_threads = True
    return server


def build_store(settings: Settings) -> Union[MemoryStore, RedisStore]:
    """REDIS_URL задан — Redis (проверяем соединение при старте), иначе память процесса."""
    if not settings.redis_url:
        return MemoryStore()
    store = RedisStore.from_url(settings.redis_url)
    store.ping()
    return store
