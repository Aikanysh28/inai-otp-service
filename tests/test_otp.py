"""Тесты OTP-сервиса. Время подменяется фейковыми часами — тесты не ждут реальных секунд."""
from __future__ import annotations

import http.client
import json
import os
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from typing import Iterator, Optional

import pytest

from app.config import Settings
from app.main import create_server
from app.otp_service import OTPService, VerifyStatus
from app.security_log import SecurityEvent, SecurityLog
from app.store import MemoryStore, RedisStore

MSISDN = "996555123456"


class FakeClock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now

    def advance(self, seconds: float):
        self.now += seconds


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

    def get(self, path: str, headers: Optional[dict] = None) -> Resp:
        return self._request(urllib.request.Request(self.base + path, headers=headers or {}))

    def post(self, path: str, body: Optional[dict] = None, raw: Optional[bytes] = None) -> Resp:
        data = raw if raw is not None else json.dumps(body).encode()
        return self._request(urllib.request.Request(self.base + path, data=data, method="POST",
                                                    headers={"Content-Type": "application/json"}))

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
            service.sms.close()


def make_store(kind: str, clock):
    if kind == "memory":
        return MemoryStore(clock)
    fakeredis = pytest.importorskip("fakeredis")
    return RedisStore(fakeredis.FakeRedis(server=fakeredis.FakeServer()))


# Все сценарии прогоняются на обоих хранилищах: в памяти и в Redis.
@pytest.fixture(params=["memory", "redis"])
def env(request, tmp_path):
    clock = FakeClock()
    settings = Settings(secret_key=b"test-secret", log_dir=str(tmp_path), debug_return_code=True)
    service = OTPService(settings, SecurityLog(str(tmp_path), clock=clock), clock=clock,
                         store=make_store(request.param, clock))
    with running_server(settings, service) as client:
        yield client, clock, service, tmp_path


def send(client, msisdn=MSISDN):
    return client.post("/otp/send", {"msisdn": msisdn})


def verify(client, code, msisdn=MSISDN):
    return client.post("/otp/verify", {"msisdn": msisdn, "code": code})


def wrong(code: str) -> str:
    return f"{(int(code) + 1) % 1_000_000:06d}"


# ---------- базовые сценарии ----------

def test_success(env):
    client, *_ = env
    r = send(client)
    assert r.status_code == 200
    code = r.json()["code"]
    assert len(code) == 6 and code.isdigit()
    assert verify(client, code).status_code == 200


def test_code_is_one_time(env):
    client, *_ = env
    code = send(client).json()["code"]
    assert verify(client, code).status_code == 200
    assert verify(client, code).status_code == 401


def test_wrong_code(env):
    client, *_ = env
    code = send(client).json()["code"]
    r = verify(client, wrong(code))
    assert r.status_code == 401
    assert r.json()["attempts_left"] == 4


def test_expired(env):
    client, clock, *_ = env
    code = send(client).json()["code"]
    clock.advance(120)
    assert verify(client, code).status_code == 410


def test_valid_just_before_expiry(env):
    client, clock, *_ = env
    code = send(client).json()["code"]
    clock.advance(119)
    assert verify(client, code).status_code == 200


def test_new_send_invalidates_previous_code(env):
    client, clock, *_ = env
    old = send(client).json()["code"]
    clock.advance(30)
    new = send(client).json()["code"]
    if old != new:
        assert verify(client, old).status_code == 401
    assert verify(client, new).status_code == 200


def test_int_code_with_leading_zero_is_accepted(env):
    client, _, service, _ = env
    service._generate_code = lambda: "012345"
    send(client)
    assert verify(client, 12345).status_code == 200


def test_invalid_msisdn(env):
    client, *_ = env
    assert client.post("/otp/send", {"msisdn": "abc"}).status_code == 422
    assert client.post("/otp/send", {}).status_code == 422
    assert client.post("/otp/send", raw=b"not json").status_code == 422
    assert client.post("/otp/verify", {"msisdn": MSISDN}).status_code == 422


def test_msisdn_normalization(env):
    client, *_ = env
    code = send(client, "+996 555 123-456").json()["code"]
    assert verify(client, code, MSISDN).status_code == 200


# ---------- задержки и лимит отправки ----------

def test_progressive_resend_delay(env):
    client, clock, *_ = env
    assert send(client).status_code == 200

    r = send(client)
    assert r.status_code == 429 and int(r.headers["Retry-After"]) == 30
    clock.advance(29)
    assert send(client).status_code == 429
    clock.advance(1)
    assert send(client).status_code == 200  # 2-я отправка после 30 с

    clock.advance(59)
    assert send(client).status_code == 429
    clock.advance(1)
    assert send(client).status_code == 200  # 3-я отправка после 60 с


def test_max_three_sends_per_10_minutes(env):
    client, clock, *_ = env
    for delay in (0, 30, 60):
        clock.advance(delay)
        assert send(client).status_code == 200
    clock.advance(300)  # прошло 390 с с первой отправки — всё ещё в окне
    assert send(client).status_code == 429
    clock.advance(210)  # 600 с с первой отправки — окно сдвинулось
    assert send(client).status_code == 200


def test_send_limits_are_per_number(env):
    client, *_ = env
    assert send(client, "996555000001").status_code == 200
    assert send(client, "996555000002").status_code == 200


# ---------- блокировка и лимит по IP ----------

def test_block_after_5_failures(env):
    client, clock, *_ = env
    code = send(client).json()["code"]
    for i in range(5):
        r = verify(client, wrong(code))
        assert r.status_code == 401
        assert r.json()["attempts_left"] == 4 - i
    # теперь даже верный код отклоняется
    r = verify(client, code)
    assert r.status_code == 423
    assert int(r.headers["Retry-After"]) == 900
    # отправка нового кода тоже запрещена на время блокировки
    assert send(client).status_code == 429


def test_block_expires_after_15_minutes(env):
    client, clock, *_ = env
    code = send(client).json()["code"]
    for _ in range(5):
        verify(client, wrong(code))
    clock.advance(899)
    assert verify(client, code).status_code == 423
    clock.advance(1)
    new = send(client).json()["code"]
    assert verify(client, new).status_code == 200


def test_success_resets_failure_counter(env):
    client, clock, *_ = env
    code = send(client).json()["code"]
    for _ in range(4):
        verify(client, wrong(code))
    assert verify(client, code).status_code == 200
    clock.advance(30)
    code = send(client).json()["code"]
    assert verify(client, wrong(code)).json()["attempts_left"] == 4


def test_ip_limit_20_per_minute_across_numbers(env):
    client, clock, *_ = env
    for i in range(20):
        r = verify(client, "000000", msisdn=f"9965550000{i:02d}")
        assert r.status_code == 401
    r = verify(client, "000000", msisdn="996555000099")
    assert r.status_code == 429
    assert "Retry-After" in r.headers
    clock.advance(60)
    assert verify(client, "000000", msisdn="996555000099").status_code == 401


# ---------- параллельные запросы ----------

def test_parallel_verify_exactly_one_success(env):
    _, _, service, _ = env
    code = service.send(MSISDN, "1.1.1.1").code
    results = []
    barrier = threading.Barrier(15)

    def worker(i):
        barrier.wait()
        # разные IP, чтобы не упереться в лимит 20/мин
        results.append(service.verify(MSISDN, code, f"10.0.0.{i}").status)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(15)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(VerifyStatus.OK) == 1


def test_parallel_verify_over_http(env):
    client, _, service, _ = env
    code = send(client).json()["code"]
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(10) as pool:
        codes = list(pool.map(lambda _: verify(client, code).status_code, range(10)))
    assert codes.count(200) == 1


# ---------- хранение и журнал ----------

def test_only_hmac_stored_not_code(env):
    _, _, service, _ = env
    code = service.send(MSISDN, "1.1.1.1").code
    record = service.store.get(f"otp:{MSISDN}")
    assert code not in json.dumps(record)
    assert len(record["hash"]) == 64  # HMAC-SHA256 hex


def test_security_log_has_no_codes(env):
    client, clock, _, log_dir = env
    codes = []
    code = send(client).json()["code"]
    codes.append(code)
    for _ in range(5):
        verify(client, wrong(code))
        codes.append(wrong(code))
    verify(client, code)

    with open(os.path.join(log_dir, "security.log"), encoding="utf-8") as f:
        lines = [json.loads(line) for line in f if line.strip()]
    events = [e["event"] for e in lines]
    assert "otp_issued" in events
    assert events.count("verify_failed") == 5
    assert "msisdn_blocked" in events
    assert "verify_rejected_blocked" in events
    text = json.dumps(lines)
    for c in codes:
        assert c not in text
    assert MSISDN not in text  # номер маскируется


# ---------- дашборд ----------

def test_dashboard_page_and_events_api(env):
    client, *_ = env
    code = send(client).json()["code"]
    for _ in range(5):
        verify(client, wrong(code))

    page = client.get("/dashboard")
    assert page.status_code == 200
    assert page.headers["Content-Type"].startswith("text/html")

    r = client.get("/api/security/events")
    assert r.status_code == 200
    data = r.json()
    assert data["counters"]["otp_issued"] == 1
    assert data["counters"]["verify_failed"] == 5
    assert data["counters"]["msisdn_blocked"] == 1
    assert len(data["timeline"]) == 30
    last = data["timeline"][-1]
    assert last["issued"] == 1 and last["failed"] == 5 and last["rejected"] == 1
    assert data["top_ips"][0]["ip"] == "127.0.0.1"
    assert data["recent_blocks"][0]["event"] == "msisdn_blocked"
    assert code not in r.text  # в выдаче дашборда нет кодов


def test_dashboard_token(tmp_path):
    settings = Settings(secret_key=b"k", log_dir=str(tmp_path), dashboard_token="s3cret")
    with running_server(settings) as client:
        assert client.get("/dashboard").status_code == 401
        assert client.get("/api/security/events?token=wrong").status_code == 401
        assert client.get("/dashboard?token=s3cret").status_code == 200
        assert client.get("/api/security/events", headers={"X-Dashboard-Token": "s3cret"}).status_code == 200


# ---------- Redis ----------

def test_redis_unavailable_returns_503_fail_closed(tmp_path):
    redis = pytest.importorskip("redis")

    class DownRedis:
        """Клиент, у которого любая команда падает, как при недоступном сервере."""

        def __getattr__(self, name):
            def fail(*args, **kwargs):
                raise redis.ConnectionError("connection refused")
            return fail

    store = RedisStore(DownRedis())
    settings = Settings(secret_key=b"k", log_dir=str(tmp_path))
    service = OTPService(settings, SecurityLog(str(tmp_path)), store=store)
    with running_server(settings, service) as client:
        assert send(client).status_code == 503
        assert verify(client, "123456").status_code == 503
        assert client.get("/health").status_code == 503


def test_redis_keys_have_ttl():
    fakeredis = pytest.importorskip("fakeredis")
    r = fakeredis.FakeRedis(server=fakeredis.FakeServer())
    store = RedisStore(r)
    store.set("otp:x", {"a": 1}, ttl=120)
    assert store.get("otp:x") == {"a": 1}
    assert 0 < r.pttl("otp:otp:x") <= 120_000


def test_redis_lock_is_mutually_exclusive():
    fakeredis = pytest.importorskip("fakeredis")
    store = RedisStore(fakeredis.FakeRedis(server=fakeredis.FakeServer()))
    store.set("n", 0)

    def inc():
        for _ in range(20):
            with store.lock("counter"):
                store.set("n", store.get("n") + 1)

    threads = [threading.Thread(target=inc) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert store.get("n") == 100


# ---------- HTTP-слой ----------

@pytest.mark.parametrize("length", ["abc", "-5"])
def test_bad_content_length_returns_400(env, length):
    client, *_ = env
    host, port = client.base.removeprefix("http://").split(":")
    conn = http.client.HTTPConnection(host, int(port), timeout=5)
    try:
        conn.putrequest("POST", "/otp/send")
        conn.putheader("Content-Length", length)
        conn.endheaders()
        resp = conn.getresponse()
        assert resp.status == 400
        assert json.loads(resp.read())["status"] == "bad_content_length"
    finally:
        conn.close()


def test_unknown_route_and_wrong_method(env):
    client, *_ = env
    assert client.get("/nope").status_code == 404
    assert client.get("/otp/send").status_code == 405
    assert client.post("/health", {}).status_code == 405


def test_security_logs_are_isolated(tmp_path):
    """Два журнала пишут каждый в свой файл (раньше второй перехватывал глобальный логгер первого)."""
    first, second = SecurityLog(str(tmp_path / "a")), SecurityLog(str(tmp_path / "b"))
    try:
        first.event(SecurityEvent.OTP_ISSUED, MSISDN, "1.1.1.1")
        second.event(SecurityEvent.VERIFY_FAILED, MSISDN, "2.2.2.2")
    finally:
        first.close()
        second.close()
    a = (tmp_path / "a" / "security.log").read_text(encoding="utf-8")
    b = (tmp_path / "b" / "security.log").read_text(encoding="utf-8")
    assert "otp_issued" in a and "verify_failed" not in a
    assert "verify_failed" in b and "otp_issued" not in b
