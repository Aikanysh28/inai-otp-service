"""Тесты OTP-сервиса. Время подменяется фейковыми часами — тесты не ждут реальных секунд."""
from __future__ import annotations

import glob
import http.client
import json
import os
import threading
import urllib.request

import pytest

import run_scenarios
from app.main import resolve_client_ip
from app.otp_service import OTPService, VerifyStatus
from app.security_log import SecurityEvent, SecurityLog
from app.store import RedisStore
from tests.helpers import (
    MSISDN, Client, delivered_code, issue, make_settings, running_server, send, verify, wrong,
)


# ---------- базовые сценарии ----------

def test_success(env):
    client, *_ = env
    code = issue(client)
    assert len(code) == 6 and code.isdigit()
    assert verify(client, code).status_code == 200


def test_send_response_does_not_contain_code(env):
    client, *_ = env
    r = send(client)
    assert r.status_code == 200
    assert "code" not in r.json()
    assert delivered_code(client.outbox) not in r.text


def test_outbox_line_format(env):
    client, *_ = env
    issue(client)
    with open(client.outbox, encoding="utf-8") as f:
        record = json.loads(f.readlines()[-1])
    assert set(record) == {"ts", "msisdn", "code"}
    assert record["msisdn"] == MSISDN and record["ts"].endswith("+06:00")


def test_code_is_one_time(env):
    client, *_ = env
    code = issue(client)
    assert verify(client, code).status_code == 200
    assert verify(client, code).status_code == 401


def test_wrong_code(env):
    client, *_ = env
    code = issue(client)
    r = verify(client, wrong(code))
    assert r.status_code == 401
    assert r.json()["attempts_left"] == 4


def test_expired(env):
    client, clock, *_ = env
    code = issue(client)
    clock.advance(120)
    assert verify(client, code).status_code == 410


def test_valid_just_before_expiry(env):
    client, clock, *_ = env
    code = issue(client)
    clock.advance(119.999)
    assert verify(client, code).status_code == 200


def test_new_send_invalidates_previous_code(env):
    client, clock, service, _ = env
    codes = iter(["111111", "222222"])  # контролируемый источник: коды гарантированно разные
    service._generate_code = lambda: next(codes)
    old = issue(client)
    clock.advance(30)
    new = issue(client)
    assert verify(client, old).status_code == 401
    assert verify(client, new).status_code == 200


def test_leading_zero_and_all_zero_codes(env):
    client, clock, service, _ = env
    service._generate_code = lambda: "000000"
    assert verify(client, issue(client)).status_code == 200
    service._generate_code = lambda: "012345"
    clock.advance(30)
    issue(client)
    assert verify(client, 12345).status_code == 400  # число вместо строки — ошибка формата
    assert verify(client, "012345").status_code == 200


@pytest.mark.parametrize("body", [
    {"msisdn": "abc"}, {"msisdn": "+996555123456"}, {"msisdn": "996 555 123 456"},
    {"msisdn": "99655512345"}, {"msisdn": "9965551234567"}, {"msisdn": "123555123456"},
    {"msisdn": 996555123456}, {},
])
def test_send_bad_format_returns_400(env, body):
    client, *_ = env
    assert client.post("/otp/send", body).status_code == 400


@pytest.mark.parametrize("code", ["12345", "1234567", "12a456", " 123456", "１２３４５６", 123456, None])
def test_verify_bad_code_format_returns_400_and_not_counted(env, code):
    client, *_ = env
    real = issue(client)
    for _ in range(5):
        assert verify(client, code).status_code == 400
    assert verify(client, real).status_code == 200  # ошибки формата не привели к блокировке


def test_bad_json_returns_400(env):
    client, *_ = env
    assert client.post("/otp/send", raw=b"not json").status_code == 400
    assert client.post("/otp/send", raw=b"[1, 2]").status_code == 400
    assert client.post("/otp/verify", {"msisdn": MSISDN}).status_code == 400


# ---------- задержки и лимит отправки ----------

def test_progressive_resend_delay(env):
    client, clock, *_ = env
    assert send(client).status_code == 200

    r = send(client)
    assert r.status_code == 429 and int(r.headers["Retry-After"]) == 30
    clock.advance(29.999)
    assert send(client).status_code == 429
    clock.advance(0.001)
    assert send(client).status_code == 200  # 2-я отправка ровно через 30 с

    clock.advance(59.999)
    assert send(client).status_code == 429
    clock.advance(0.001)
    assert send(client).status_code == 200  # 3-я отправка ровно через 60 с


def test_max_three_sends_per_10_minutes(env):
    client, clock, *_ = env
    for delay in (0, 30, 60):
        clock.advance(delay)
        assert send(client).status_code == 200
    clock.advance(300)  # прошло 390 с с первой отправки — всё ещё в окне
    assert send(client).status_code == 429
    clock.advance(210)  # 600 с с первой отправки — она вышла из окна (t-600, t]
    assert send(client).status_code == 200


def test_rejected_send_keeps_active_code(env):
    client, clock, *_ = env
    code = issue(client)
    clock.advance(10)
    assert send(client).status_code == 429
    assert verify(client, code).status_code == 200


def test_send_limits_are_per_number(env):
    client, *_ = env
    assert send(client, "996555000001").status_code == 200
    assert send(client, "996555000002").status_code == 200


# ---------- блокировка и лимит по IP ----------

def test_block_on_fifth_failure(env):
    client, clock, *_ = env
    code = issue(client)
    for i in range(4):
        r = verify(client, wrong(code))
        assert r.status_code == 401
        assert r.json()["attempts_left"] == 4 - i
    r = verify(client, wrong(code))  # пятая ошибка — уже 423
    assert r.status_code == 423
    assert int(r.headers["Retry-After"]) == 900
    assert verify(client, code).status_code == 423  # верный код в блокировке тоже 423
    assert send(client).status_code == 423  # send при блокировке


def test_block_lasts_exactly_900_seconds(env):
    client, clock, *_ = env
    code = issue(client)
    for _ in range(5):
        verify(client, wrong(code))
    clock.advance(899.999)
    assert verify(client, code).status_code == 423
    assert send(client).status_code == 423
    clock.advance(0.001)
    assert verify(client, issue(client)).status_code == 200


def test_missing_or_expired_code_not_counted(env):
    client, clock, *_ = env
    for _ in range(6):
        assert verify(client, "123456").status_code == 401  # кода нет
    code = issue(client)
    clock.advance(120)
    assert verify(client, code).status_code == 410
    for _ in range(5):
        assert verify(client, code).status_code == 401  # истёкший код уже удалён
    clock.advance(60)  # сброс окна IP-лимита
    assert verify(client, issue(client)).status_code == 200


def test_success_resets_failure_counter(env):
    client, clock, *_ = env
    code = issue(client)
    for _ in range(4):
        verify(client, wrong(code))
    assert verify(client, code).status_code == 200
    clock.advance(30)
    code = issue(client)
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


def test_bad_format_verifies_consume_ip_limit(env):
    client, *_ = env
    code = issue(client)
    for _ in range(20):
        assert client.post("/otp/verify", raw=b"garbage").status_code == 400
    assert verify(client, code).status_code == 429


def test_ip_limit_checked_before_block(env):
    client, *_ = env
    code = issue(client)
    for _ in range(5):
        verify(client, wrong(code))
    for _ in range(15):
        verify(client, "000000", msisdn="996555000001")
    assert verify(client, code).status_code == 429  # не 423: IP-лимит раньше блокировки


# ---------- параллельные запросы ----------

def test_parallel_verify_exactly_one_success(env):
    client, _, service, _ = env
    code = issue(client)
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
    assert results.count(VerifyStatus.INVALID) == 14


def test_parallel_verify_over_http(env):
    client, *_ = env
    code = issue(client)
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(20) as pool:
        codes = list(pool.map(lambda _: verify(client, code).status_code, range(20)))
    assert codes.count(200) == 1 and codes.count(401) == 19


# ---------- хранение и журнал ----------

def test_only_hmac_stored_not_code(env):
    client, _, service, _ = env
    code = issue(client)
    record = service.store.get(f"otp:{MSISDN}")
    assert code not in json.dumps(record)
    assert len(record["hash"]) == 64  # HMAC-SHA256 hex


def test_security_log_has_no_codes(env):
    client, clock, _, log_dir = env
    code = issue(client)
    codes = [code, wrong(code)]
    for _ in range(5):
        verify(client, wrong(code))
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
    code = issue(client)
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
    settings = make_settings(tmp_path, dashboard_token="s3cret")
    with running_server(settings) as client:
        assert client.get("/dashboard").status_code == 401
        assert client.get("/api/security/events?token=wrong").status_code == 401
        assert client.get("/dashboard?token=s3cret").status_code == 200
        by_header = client.get("/api/security/events", headers={"X-Dashboard-Token": "s3cret"})
        assert by_header.status_code == 200


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
    settings = make_settings(tmp_path)
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
    """Два журнала пишут каждый в свой файл, не перехватывая логгер друг друга."""
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


# ---------- IP из соединения (как у жюри: клиенты с 127.0.0.1 и 127.0.0.2) ----------

def post_from(client, source_ip: str, path: str, body: dict) -> int:
    """POST с заданного локального адреса: сервер видит его как IP клиента."""
    host, port = client.base.removeprefix("http://").split(":")
    conn = http.client.HTTPConnection(host, int(port), timeout=5, source_address=(source_ip, 0))
    try:
        conn.request("POST", path, json.dumps(body), {"Content-Type": "application/json"})
        response = conn.getresponse()
        response.read()
        return response.status
    finally:
        conn.close()


@pytest.fixture
def second_loopback():
    """127.0.0.2 есть на Linux и Windows; на macOS без настройки — тест пропускается."""
    import socket
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.2", 0))
    except OSError:
        pytest.skip("адрес 127.0.0.2 недоступен в этой системе")
    finally:
        probe.close()


def test_ip_limit_is_per_connection_address(env, second_loopback):
    client, *_ = env
    body = {"msisdn": MSISDN, "code": "000000"}
    for _ in range(20):
        assert post_from(client, "127.0.0.1", "/otp/verify", body) == 401
    assert post_from(client, "127.0.0.1", "/otp/verify", body) == 429
    assert post_from(client, "127.0.0.2", "/otp/verify", body) == 401  # у второго IP своя квота


def test_events_record_connection_address(env, second_loopback):
    client, _, service, _ = env
    post_from(client, "127.0.0.2", "/otp/send", {"msisdn": MSISDN})
    assert service.history(MSISDN)[0]["ip"] == "127.0.0.2"


# ---------- доверенный прокси ----------

@pytest.mark.parametrize("peer, xff, expected", [
    ("203.0.113.5", "192.0.2.10", "203.0.113.5"),  # не доверенный источник: заголовок игнорируется
    ("127.0.0.1", "192.0.2.10", "192.0.2.10"),  # доверенный прокси
    ("127.0.0.1", "6.6.6.6, 192.0.2.10", "192.0.2.10"),  # адрес, добавленный самим прокси
    ("127.0.0.1", "not-an-ip", "127.0.0.1"),
    ("127.0.0.1", None, "127.0.0.1"),
])
def test_resolve_client_ip(peer, xff, expected):
    assert resolve_client_ip(peer, xff, frozenset({"127.0.0.1"})) == expected


def test_spoofed_forwarded_for_does_not_bypass_ip_limit(env):
    """Без OTP_TRUSTED_PROXIES смена X-Forwarded-For не даёт обойти лимит 20/мин."""
    client, *_ = env
    body = json.dumps({"msisdn": MSISDN, "code": "000000"}).encode()
    for i in range(25):
        headers = {"Content-Type": "application/json", "X-Forwarded-For": f"10.9.0.{i}"}
        req = urllib.request.Request(client.base + "/otp/verify", data=body, method="POST",
                                     headers=headers)
        resp = Client._request(req)
    assert resp.status_code == 429


# ---------- сценарии в формате жюри ----------

SCENARIOS_DIR = os.path.join(os.path.dirname(__file__), "..", "scenarios")
SCENARIO_FILES = sorted(glob.glob(os.path.join(SCENARIOS_DIR, "scenarios_*.json")))


@pytest.mark.parametrize("path", SCENARIO_FILES, ids=os.path.basename)
def test_jury_format_scenarios(path):
    passed, total = run_scenarios.run_file(path)
    assert total > 0 and passed == total


def test_scenario_runner_detects_failure(tmp_path):
    bad = [{"id": "BAD", "fixture": "", "overrides": {}, "steps": [
        {"op": "request", "method": "POST", "path": "/otp/send",
         "body": {"msisdn": "996770730000"}, "expected": {"status": 418}}]}]
    path = tmp_path / "scenarios_bad.json"
    path.write_text(json.dumps(bad), encoding="utf-8")
    assert run_scenarios.run_file(str(path)) == (0, 1)


# ---------- демо-страница ----------

def test_demo_page_served(env):
    client, *_ = env
    r = client.get("/demo")
    assert r.status_code == 200 and r.headers["Content-Type"].startswith("text/html")


def test_demo_send_disabled_by_default(env):
    """По умолчанию код никогда не возвращается через HTTP: маршрута /demo/send нет."""
    client, *_ = env
    assert client.post("/demo/send", {"msisdn": MSISDN}).status_code == 404
    assert "code" not in send(client).json()


def test_demo_send_returns_code_only_in_demo_mode(tmp_path):
    settings = make_settings(tmp_path, demo_show_code=True)
    with running_server(settings) as client:
        client.outbox = settings.outbox_path
        r = client.post("/demo/send", {"msisdn": MSISDN})
        assert r.status_code == 200
        assert r.json()["code"] == delivered_code(client.outbox)
        assert "code" not in send(client, "996555000001").json()  # обычный /otp/send — без кода
