"""Общие помощники тестов: HTTP-клиент, запуск сервера, выдача и перехват кодов."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from typing import Iterator, Optional

import pytest

from app.config import Settings
from app.main import create_server
from app.otp_service import OTPService
from app.store import MemoryStore, RedisStore

MSISDN = "996555123456"


class Resp:
    def __init__(self, status_code: int, body: bytes, headers):
        self.status_code = status_code
        self.body = body
        self.headers = headers

    @property
    def text(self) -> str:
        return self.body.decode()

    def json(self):
        return json.loads(self.body)


class Client:
    """Мини-клиент поверх urllib к реально запущенному серверу."""

    def __init__(self, base: str):
        self.base = base
        self.outbox: Optional[str] = None

    def get(self, path: str, headers: Optional[dict] = None) -> Resp:
        return self._request(urllib.request.Request(self.base + path, headers=headers or {}))

    def post(self, path: str, body: Optional[dict] = None, raw: Optional[bytes] = None,
             headers: Optional[dict] = None) -> Resp:
        data = raw if raw is not None else json.dumps(body).encode()
        all_headers = {"Content-Type": "application/json", **(headers or {})}
        return self._request(urllib.request.Request(self.base + path, data=data, method="POST",
                                                    headers=all_headers))

    @staticmethod
    def _request(req: urllib.request.Request) -> Resp:
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return Resp(r.status, r.read(), r.headers)
        except urllib.error.HTTPError as e:
            return Resp(e.code, e.read(), e.headers)


@contextmanager
def running_server(settings: Settings, service: Optional[OTPService] = None) -> Iterator[Client]:
    """Поднять сервер на свободном порту в фоновом потоке и вернуть клиента к нему."""
    server = create_server(settings, service, host="127.0.0.1", port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield Client(f"http://127.0.0.1:{server.server_address[1]}")
    finally:
        server.shutdown()
        server.server_close()
        if service is not None:
            service.log.close()


def make_store(kind: str, clock):
    if kind == "memory":
        return MemoryStore(clock)
    fakeredis = pytest.importorskip("fakeredis")
    return RedisStore(fakeredis.FakeRedis(server=fakeredis.FakeServer()))


def make_settings(tmp_path, **overrides) -> Settings:
    return Settings(secret_key=b"test-secret", log_dir=str(tmp_path),
                    outbox_path=str(tmp_path / "outbox" / "sms.jsonl"), **overrides)


def delivered_code(outbox: str, msisdn: str = MSISDN) -> str:
    """Последний код для номера из тестового SMS-транспорта (как capture_delivery у жюри)."""
    with open(outbox, encoding="utf-8") as f:
        records = [json.loads(line) for line in f]
    return [r for r in records if r["msisdn"] == msisdn][-1]["code"]


def send(client, msisdn=MSISDN):
    return client.post("/otp/send", {"msisdn": msisdn})


def issue(client, msisdn=MSISDN) -> str:
    """Запросить код и «перехватить» его из outbox."""
    assert send(client, msisdn).status_code == 200
    return delivered_code(client.outbox, msisdn)


def verify(client, code, msisdn=MSISDN):
    return client.post("/otp/verify", {"msisdn": msisdn, "code": code})


def wrong(code: str) -> str:
    return f"{(int(code) + 1) % 1_000_000:06d}"
