"""Фикстуры pytest, общие для всех тестов."""
from __future__ import annotations

import pytest

from app.otp_service import OTPService
from app.security_log import SecurityLog
from run_scenarios import FakeClock
from tests.helpers import make_settings, make_store, running_server


# Все сценарии прогоняются на обоих хранилищах: в памяти и в Redis.
@pytest.fixture(params=["memory", "redis"])
def env(request, tmp_path):
    """Настоящий HTTP-сервер с подменяемыми часами: (client, clock, service, tmp_path)."""
    clock = FakeClock()
    settings = make_settings(tmp_path)
    service = OTPService(settings, SecurityLog(str(tmp_path), clock=clock), clock=clock,
                         store=make_store(request.param, clock))
    with running_server(settings, service) as client:
        client.outbox = settings.outbox_path
        yield client, clock, service, tmp_path
