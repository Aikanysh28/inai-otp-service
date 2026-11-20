"""Тесты уведомлений Telegram: поток отправки не должен останавливаться ни при каком ответе.

В сеть тесты не ходят: urlopen и time.sleep подменяются.
"""
from __future__ import annotations

import io
import json
import logging
import time
from types import SimpleNamespace
from unittest import mock
from urllib.error import HTTPError

import pytest

from app.telegram_bot import MAX_RETRY_AFTER, TelegramAlerts, _retry_after

TOKEN = "123456:SECRET-TOKEN"
ALERT = SimpleNamespace(level="high", ip="198.51.100.9", score=70,
                        reasons=[SimpleNamespace(title="Массовая рассылка", points=20)])


def ok_response(body: object = None) -> io.BytesIO:
    return io.BytesIO(json.dumps({"ok": True} if body is None else body).encode())


def http_error(code: int, body: bytes) -> HTTPError:
    return HTTPError("https://api.telegram.org/bot<token>/sendMessage", code, "error", None,
                     io.BytesIO(body))


def drain(alerts: TelegramAlerts, timeout: float = 3.0) -> None:
    """Дождаться, пока поток обработает все поставленные сообщения."""
    deadline = time.monotonic() + timeout
    while alerts._messages.unfinished_tasks and time.monotonic() < deadline:
        time.sleep(0.01)
    assert alerts._messages.unfinished_tasks == 0, "поток отправки не обработал очередь"


@pytest.fixture
def alerts():
    return TelegramAlerts(TOKEN, "42")


@pytest.mark.parametrize("first", [
    ok_response([1, 2]),            # ответ — список, а не объект
    ok_response("ok"),              # ответ — строка
    io.BytesIO(b"<html>oops</html>"),  # не JSON
])
def test_unexpected_success_body_does_not_stop_thread(alerts, first):
    with mock.patch("app.telegram_bot.urlopen", side_effect=[first, ok_response()]) as urlopen, \
            mock.patch("app.telegram_bot.time"):
        alerts.enqueue(ALERT)
        alerts.enqueue(ALERT)
        drain(alerts)
    assert urlopen.call_count == 2  # второе сообщение тоже ушло


def test_unexpected_http_error_body_does_not_stop_thread(alerts):
    errors = [http_error(400, b"[1, 2]"), ok_response()]
    with mock.patch("app.telegram_bot.urlopen", side_effect=errors) as urlopen:
        alerts.enqueue(ALERT)
        alerts.enqueue(ALERT)
        drain(alerts)
    assert urlopen.call_count == 2  # 400 не повторяется, следующее сообщение доставлено


def test_any_exception_is_logged_without_token_and_thread_continues(alerts, caplog):
    boom = RuntimeError(f"failed https://api.telegram.org/bot{TOKEN}/sendMessage")
    with mock.patch("app.telegram_bot.urlopen", side_effect=[boom, ok_response()]) as urlopen, \
            caplog.at_level(logging.WARNING, logger="app.telegram_bot"):
        alerts.enqueue(ALERT)
        alerts.enqueue(ALERT)
        drain(alerts)
    assert urlopen.call_count == 2
    assert "RuntimeError" in caplog.text
    assert TOKEN not in caplog.text


def test_429_waits_retry_after_capped(alerts):
    body = json.dumps({"ok": False, "parameters": {"retry_after": 10_000}}).encode()
    responses = [http_error(429, body), ok_response()]
    with mock.patch("app.telegram_bot.urlopen", side_effect=responses), \
            mock.patch("app.telegram_bot.time") as fake_time:
        alerts.enqueue(ALERT)
        drain(alerts)
    fake_time.sleep.assert_called_once_with(MAX_RETRY_AFTER)


@pytest.mark.parametrize("details, expected", [
    ({"parameters": {"retry_after": 5}}, 5),
    ({"parameters": {"retry_after": 10_000}}, MAX_RETRY_AFTER),
    ({"parameters": {"retry_after": "5"}}, 2),
    ({"parameters": {"retry_after": True}}, 2),
    ({"parameters": {"retry_after": -1}}, 2),
    ({"parameters": [5]}, 2),
    ({}, 2),
])
def test_retry_after_parsing(details, expected):
    assert _retry_after(details, 2) == expected


def test_disabled_without_token_and_chat(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    assert TelegramAlerts.from_env() is None
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", TOKEN)
    assert TelegramAlerts.from_env() is None  # без chat_id тоже выключен
