"""Тесты личного кабинета абонента: вход по OTP, история, заморозка выдачи кодов."""
from __future__ import annotations

import hashlib

import pytest

from tests.helpers import MSISDN, delivered_code, issue, send, verify, wrong


def cabinet_code(client, msisdn=MSISDN) -> str:
    assert client.post("/cabinet/code", {"msisdn": msisdn}).status_code == 200
    return delivered_code(client.outbox, msisdn)


def login(client, msisdn=MSISDN) -> str:
    code = cabinet_code(client, msisdn)
    r = client.post("/cabinet/login", {"msisdn": msisdn, "code": code})
    assert r.status_code == 200
    return r.json()["token"]


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def me(client, token):
    return client.get("/cabinet/me", headers=auth(token))


def freeze(client, token, duration):
    return client.post("/cabinet/freeze", {"duration": duration}, headers=auth(token))


def events(overview: dict) -> list[str]:
    return [e["event"] for e in overview["history"]]


# ---------- вход и сессия ----------

def test_login_and_overview(env):
    client, *_ = env
    token = login(client)
    r = me(client, token)
    assert r.status_code == 200
    data = r.json()
    assert data["msisdn"] == MSISDN and data["frozen"] is None and data["blocked_until"] is None
    assert events(data)[:3] == ["cabinet_login", "verify_success", "otp_issued"]
    assert data["history"][2]["scope"] == "cabinet"


def test_cabinet_requires_valid_session(env):
    client, *_ = env
    assert client.get("/cabinet/me").status_code == 401
    assert me(client, "forged-token").status_code == 401
    assert client.post("/cabinet/freeze", {"duration": None}).status_code == 401


def test_logout_invalidates_token(env):
    client, *_ = env
    token = login(client)
    assert client.post("/cabinet/logout", {}, headers=auth(token)).status_code == 200
    assert me(client, token).status_code == 401


def test_session_token_stored_only_as_hash(env):
    client, _, service, _ = env
    token = login(client)
    assert service.store.get(f"session:{token}") is None
    digest = hashlib.sha256(token.encode()).hexdigest()
    assert service.store.get(f"session:{digest}") == MSISDN


def test_cabinet_login_has_brute_force_protection(env):
    client, *_ = env
    code = cabinet_code(client)
    for _ in range(4):
        r = client.post("/cabinet/login", {"msisdn": MSISDN, "code": wrong(code)})
        assert r.status_code == 401
    r = client.post("/cabinet/login", {"msisdn": MSISDN, "code": wrong(code)})
    assert r.status_code == 423 and "token" not in r.json()
    assert client.post("/cabinet/login", {"msisdn": MSISDN, "code": code}).status_code == 423


def test_flooding_service_codes_does_not_lock_owner_out_of_cabinet(env):
    """Злоумышленник исчерпал лимит выдач кодов сервисам — владелец всё равно входит в кабинет."""
    client, clock, *_ = env
    for delay in (0, 30, 60):
        clock.advance(delay)
        assert send(client).status_code == 200
    clock.advance(120)
    assert send(client).status_code == 429  # 3 выдачи за 10 минут исчерпаны
    assert me(client, login(client)).status_code == 200


def test_cabinet_codes_have_their_own_rate_limit(env):
    client, *_ = env
    cabinet_code(client)
    assert client.post("/cabinet/code", {"msisdn": MSISDN}).status_code == 429


def test_cabinet_login_bad_format_returns_400(env):
    client, *_ = env
    assert client.post("/cabinet/login", {"msisdn": MSISDN, "code": "12"}).status_code == 400
    assert client.post("/cabinet/code", {"msisdn": "+996555123456"}).status_code == 400


# ---------- заморозка ----------

def test_freeze_rejects_service_codes_with_423(env):
    client, *_ = env
    token = login(client)
    assert freeze(client, token, None).status_code == 200
    r = send(client)
    assert r.status_code == 423
    assert r.json()["status"] == "msisdn_frozen"
    assert "Retry-After" not in r.headers  # бессрочно — срок неизвестен


def test_timed_freeze_sets_retry_after_and_expires(env):
    client, clock, *_ = env
    token = login(client)
    assert freeze(client, token, 3600).json()["frozen"]["until"] is not None
    r = send(client)
    assert r.status_code == 423 and int(r.headers["Retry-After"]) == 3600
    clock.advance(3600)
    assert send(client).status_code == 200


def test_freeze_invalidates_active_code(env):
    client, clock, *_ = env
    code = issue(client)
    clock.advance(30)
    token = login(client)
    freeze(client, token, None)
    assert verify(client, code).status_code == 401


def test_cabinet_code_works_while_frozen_and_unfreeze_restores(env):
    client, clock, *_ = env
    token = login(client)
    freeze(client, token, None)
    client.post("/cabinet/logout", {}, headers=auth(token))

    clock.advance(30)
    token = login(client)  # вход в кабинет при заморозке работает
    assert me(client, token).json()["frozen"] is not None
    r = client.post("/cabinet/unfreeze", {}, headers=auth(token))
    assert r.status_code == 200 and r.json()["frozen"] is None

    clock.advance(60)
    assert verify(client, issue(client)).status_code == 200


def test_rejected_request_shows_service_in_history(env):
    client, *_ = env
    token = login(client)
    freeze(client, token, None)
    assert client.post("/otp/send", {"msisdn": MSISDN, "service": "INAI Bank"}).status_code == 423
    latest = me(client, token).json()["history"][0]
    assert latest["event"] == "send_rejected_frozen" and latest["service"] == "INAI Bank"


@pytest.mark.parametrize("duration", [123, "3600", True, -1, [3600]])
def test_invalid_freeze_duration_returns_400(env, duration):
    client, *_ = env
    token = login(client)
    assert freeze(client, token, duration).status_code == 400


def test_freeze_does_not_affect_other_numbers(env):
    client, *_ = env
    token = login(client)
    freeze(client, token, None)
    assert send(client, "996555000001").status_code == 200


# ---------- история и имя сервиса ----------

def test_service_name_recorded_in_history(env):
    client, clock, *_ = env
    assert client.post("/otp/send", {"msisdn": MSISDN, "service": "INAI Bank"}).status_code == 200
    clock.advance(30)
    token = login(client)
    issued = [e for e in me(client, token).json()["history"] if e["event"] == "otp_issued"]
    assert issued[-1]["service"] == "INAI Bank"


@pytest.mark.parametrize("service", ["", "   ", "x" * 41, 42, "bad\nname"])
def test_invalid_service_name_returns_400(env, service):
    client, *_ = env
    assert client.post("/otp/send", {"msisdn": MSISDN, "service": service}).status_code == 400


def test_history_keeps_last_50_events(env):
    client, clock, service, _ = env
    for i in range(60):
        if i and i % 20 == 0:
            clock.advance(60)  # сброс окна IP-лимита
        verify(client, "000000")  # без активного кода: 401, событие в истории
    assert len(service.history(MSISDN)) == 50


def test_history_has_no_codes(env):
    client, clock, service, _ = env
    code = issue(client)
    verify(client, wrong(code))
    verify(client, code)
    history = service.history(MSISDN)
    assert history and all("code" not in entry for entry in history)
    # сравниваем значения целиком: подстрокой код может случайно совпасть с цифрами времени
    assert all(code not in map(str, entry.values()) for entry in history)


def test_cabinet_page_served(env):
    client, *_ = env
    r = client.get("/cabinet")
    assert r.status_code == 200 and r.headers["Content-Type"].startswith("text/html")
