"""HTTP-сервер на стандартной библиотеке и сборка зависимостей сервиса.

Маршруты и валидация — в app/api.py; здесь только транспорт: прочитать запрос,
передать в OTPApi, записать ответ.
"""
from __future__ import annotations

import ipaddress
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import AbstractSet, Optional

from .api import OTPApi, Request, Response
from .config import Settings
from .otp_service import OTPService
from .security_log import SecurityLog
from .store import MemoryStore, RedisStore, Store

MAX_BODY = 4096


def resolve_client_ip(peer_ip: str, forwarded_for: Optional[str], trusted_proxies: AbstractSet[str]) -> str:
    """IP клиента: из сокета, а X-Forwarded-For — только если соединение пришло от доверенного прокси.

    Произвольному X-Forwarded-For не доверяем: иначе атакующий обходил бы IP-лимит, меняя заголовок.
    Берётся последний адрес цепочки — его добавил сам доверенный прокси.
    """
    if peer_ip in trusted_proxies and forwarded_for:
        candidate = forwarded_for.split(",")[-1].strip()
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            pass
    return peer_ip


def make_handler(api: OTPApi, trusted_proxies: AbstractSet[str] = frozenset()) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "OTPService/1.0"
        sys_version = ""

        def do_GET(self) -> None:
            self._write(self._handle())

        def do_POST(self) -> None:
            self._write(self._handle())

        def _handle(self) -> Response:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if length < 0:
                return Response.error(400, "bad_content_length")
            if length > MAX_BODY:
                return Response.error(413, "payload_too_large")
            body = self.rfile.read(length) if length else b""
            ip = resolve_client_ip(self.client_address[0], self.headers.get("X-Forwarded-For"), trusted_proxies)
            return api.handle(Request.build(self.command, self.path, self.headers, body, ip))

        def _write(self, response: Response) -> None:
            headers = dict(response.headers)
            if isinstance(response.body, bytes):
                data = response.body
            else:
                data = json.dumps(response.body, ensure_ascii=False).encode()
                headers.setdefault("Content-Type", "application/json; charset=utf-8")
            self.send_response(response.status)
            self.send_header("Content-Length", str(len(data)))
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format: str, *args) -> None:
            # access-лог отключён: под атакой тысячи строк в консоли мешают видеть SMS и события
            pass

    return Handler


def build_store(settings: Settings) -> Store:
    """REDIS_URL задан — Redis (соединение проверяется при старте), иначе память процесса."""
    if not settings.redis_url:
        return MemoryStore()
    store = RedisStore.from_url(settings.redis_url)
    store.ping()
    return store


def create_server(settings: Optional[Settings] = None, service: Optional[OTPService] = None,
                  host: Optional[str] = None, port: Optional[int] = None) -> ThreadingHTTPServer:
    settings = settings or Settings()
    if service is None:
        service = OTPService(settings, SecurityLog(settings.log_dir), store=build_store(settings))
    address = (settings.host if host is None else host, settings.port if port is None else port)
    handler = make_handler(OTPApi(service, settings.dashboard_token), settings.trusted_proxies)
    server = ThreadingHTTPServer(address, handler)
    server.daemon_threads = True
    return server
