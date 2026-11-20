"""Подключение модуля рисков к сервису и API /api/risk/* (unittest; работает и через pytest).

Без HTTP-сервера: запросы идут через OTPApi.handle, время — FakeClock.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import unittest
from typing import Optional
from unittest import mock

from app.api import OTPApi, Request
from app.config import Settings
from app.main import build_risk
from app.otp_service import OTPService
from app.risk import RiskEngine
from app.risk.simulate import FakeClock
from app.security_log import SecurityLog
from app.sms import SmsGateway
from app.store import MemoryStore

FULL_NUMBER = re.compile(r"996\d{9}")
IP = "192.0.2.10"
MSISDN = "996555123456"
RISK_PATHS = ("/api/risk/overview", "/api/risk/timeline", "/api/risk/ips",
              "/api/risk/scatter", "/api/risk/alerts", "/api/risk/meta")


class Stack:
    """OTPService + SecurityLog + OTPApi на подменённых часах, как в существующих тестах."""

    def __init__(self, workdir: str, *, risk: bool = True, token: str = "",
                 clock: Optional[FakeClock] = None):
        os.makedirs(workdir, exist_ok=True)
        self.clock = clock or FakeClock()
        self.outbox = os.path.join(workdir, "outbox", "sms.jsonl")
        self.settings = Settings(secret_key=b"test-secret", log_dir=workdir,
                                 outbox_path=self.outbox)
        self.log = SecurityLog(workdir, clock=self.clock, console=False)
        self.service = OTPService(self.settings, self.log, clock=self.clock,
                                  store=MemoryStore(self.clock),
                                  sms=SmsGateway(self.outbox, self.clock, echo=False))
        self.engine = RiskEngine(clock=self.clock, id_key=b"test-risk") if risk else None
        if self.engine is not None:
            self.log.add_sink(self.engine.sink)  # синхронно: детерминированно для тестов
        self.api = OTPApi(self.service, token, risk=self.engine)

    def call(self, method: str, path: str, body: Optional[dict] = None, ip: str = IP,
             headers: Optional[dict] = None):
        raw = json.dumps(body).encode() if body is not None else b""
        return self.api.handle(Request.build(method, path, headers or {}, raw, ip))

    def get(self, path: str, **kwargs):
        return self.call("GET", path, **kwargs)

    def send(self, msisdn: str = MSISDN, ip: str = IP):
        return self.call("POST", "/otp/send", {"msisdn": msisdn}, ip=ip)

    def verify(self, code: str, msisdn: str = MSISDN, ip: str = IP):
        return self.call("POST", "/otp/verify", {"msisdn": msisdn, "code": code}, ip=ip)

    def code(self, msisdn: str = MSISDN) -> str:
        """Последний код номера из тестового SMS-транспорта (как delivered_code в helpers)."""
        with open(self.outbox, encoding="utf-8") as f:
            records = [json.loads(line) for line in f]
        return [r for r in records if r["msisdn"] == msisdn][-1]["code"]

    def close(self) -> None:
        if self.engine is not None:
            self.engine.stop_worker()
        self.log.close()


def wrong(code: str) -> str:
    return f"{(int(code) + 1) % 1_000_000:06d}"


def otp_story(stack: Stack) -> list[tuple]:
    """send, ранний повторный send, 5 неверных verify, verify блокированного, send после паузы."""
    responses = [stack.send(), stack.send()]
    code = stack.code()
    for _ in range(5):
        responses.append(stack.verify(wrong(code)))
    responses.append(stack.verify(code))
    stack.clock.advance(901)
    responses.append(stack.send())
    responses.append(stack.call("POST", "/otp/verify", {"msisdn": "+996555123456", "code": "1"}))
    responses.append(stack.verify(stack.code()))
    return [(r.status, r.body, r.headers) for r in responses]


class StackTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="risk_api_")
        self.stacks: list[Stack] = []

    def tearDown(self):
        for stack in self.stacks:
            stack.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def stack(self, name: str = "main", **kwargs) -> Stack:
        stack = Stack(os.path.join(self.tmp, name), **kwargs)
        self.stacks.append(stack)
        return stack


class IntegrationTest(StackTestCase):
    def test_send_and_verify_reach_engine(self):
        s = self.stack()
        self.assertEqual(s.send().status, 200)
        self.assertEqual(s.verify(s.code()).status, 200)
        overview = s.get("/api/risk/overview").body
        self.assertEqual((overview["sms_sent"], overview["conversion"]), (1, 1.0))

    def test_sequential_sends_make_ip_high_with_alert(self):
        s = self.stack()
        for i in range(6):
            self.assertEqual(s.send(f"99670073{1200 + i:04d}").status, 200)
            s.clock.advance(2)
        rows = s.get("/api/risk/ips?min_level=high").body
        self.assertEqual([(r["ip"], r["level"]) for r in rows], [(IP, "high")])
        alerts = s.get("/api/risk/alerts").body
        self.assertTrue(any(a["ip"] == IP and a["severity"] == "high" for a in alerts))

    def test_ip_rate_limit_reaches_engine(self):
        s = self.stack()
        statuses = [s.verify("123456", msisdn=f"99655512{i:04d}").status for i in range(21)]
        self.assertEqual(statuses[-1], 429)
        detail = s.get(f"/api/risk/ip?ip={IP}").body
        self.assertGreaterEqual(detail["stats"]["ip_limited"], 1)
        self.assertIn("ip_limited", {r["name"] for r in detail["reasons"]})


class NonInterferenceTest(StackTestCase):
    def test_same_responses_with_and_without_risk(self):
        with_risk = otp_story(self.stack("with", risk=True))
        without = otp_story(self.stack("without", risk=False))
        self.assertEqual(with_risk, without)
        self.assertEqual([r[0] for r in with_risk],
                         [200, 429, 401, 401, 401, 401, 423, 423, 200, 400, 200])

    def test_failing_sink_does_not_change_responses(self):
        baseline = otp_story(self.stack("base", risk=False))
        broken = self.stack("broken", risk=False)

        def explode(*args, **kwargs):
            raise RuntimeError("модуль рисков сломан")

        broken.log.add_sink(explode)
        self.assertEqual(otp_story(broken), baseline)

    def test_full_async_queue_drops_without_blocking(self):
        baseline = otp_story(self.stack("base", risk=False))
        s = self.stack("async", risk=False)
        engine = RiskEngine(clock=s.clock, id_key=b"k")
        engine.start_worker(maxsize=1)
        engine.stop_worker()  # обработчика нет: очередь заполнится после первого события
        s.log.add_sink(engine.async_sink)
        self.assertEqual(otp_story(s), baseline)
        self.assertGreater(engine.dropped, 0)
        self.assertEqual(engine.meta()["queue_size"], 1)


class ApiTest(StackTestCase):
    def test_token_required_like_security_events(self):
        s = self.stack(token="dev")
        reference = s.get("/api/security/events")
        for path in RISK_PATHS + ("/api/risk/ip?ip=1.2.3.4",):
            with self.subTest(path=path):
                denied = s.get(path)
                self.assertEqual((denied.status, denied.body), (reference.status, reference.body))
        self.assertEqual(s.get("/api/risk/meta", headers={"X-Dashboard-Token": "dev"}).status, 200)
        self.assertEqual(s.get("/api/risk/meta?token=dev").status, 200)
        self.assertEqual(s.get("/api/risk/meta?token=wrong").status, 401)

    def test_invalid_params_return_400(self):
        s = self.stack()
        cases = {
            "/api/risk/overview?window=abc": "window",
            "/api/risk/overview?window=10": "window",
            "/api/risk/timeline?step=30": "step",
            "/api/risk/timeline?window=90000": "window",
            "/api/risk/ips?limit=0": "limit",
            "/api/risk/ips?limit=201": "limit",
            "/api/risk/ips?min_level=extreme": "min_level",
            "/api/risk/ip?ip=": "ip",
            "/api/risk/ip": "ip",
            "/api/risk/ip?ip=" + "1" * 65: "ip",
            "/api/risk/scatter?window=59": "window",
            "/api/risk/alerts?limit=501": "limit",
            "/api/risk/alerts?since_id=-1": "since_id",
        }
        for path, param in cases.items():
            with self.subTest(path=path):
                r = s.get(path)
                self.assertEqual((r.status, r.body["status"]), (400, "bad_request"))
                self.assertIn(param, r.body["error"])

    def test_unknown_ip_and_disabled_risk(self):
        s = self.stack()
        r = s.get("/api/risk/ip?ip=0.0.0.0")
        self.assertEqual((r.status, r.body), (404, {"status": "not_found"}))
        off = self.stack("off", risk=False)
        for path in RISK_PATHS:
            with self.subTest(path=path):
                r = off.get(path)
                self.assertEqual((r.status, r.body), (503, {"status": "risk_disabled"}))

    def test_engine_exception_is_isolated(self):
        s = self.stack()
        with mock.patch.object(s.engine, "overview", side_effect=RuntimeError("сбой")):
            r = s.get("/api/risk/overview")
        self.assertEqual((r.status, r.body), (503, {"status": "risk_error"}))

    def test_responses_have_no_full_numbers_and_no_store(self):
        s = self.stack()
        otp_story(s)
        for i in range(6):
            s.send(f"99670073{1200 + i:04d}", ip="198.51.100.20")
        paths = RISK_PATHS + (f"/api/risk/ip?ip={IP}", "/api/risk/ip?ip=198.51.100.20")
        for path in paths:
            with self.subTest(path=path):
                r = s.get(path)
                self.assertEqual(r.status, 200)
                self.assertEqual(r.headers.get("Cache-Control"), "no-store")
                self.assertIsNone(FULL_NUMBER.search(json.dumps(r.body, ensure_ascii=False)))

    def test_cabinet_scope_visible_in_ip_detail(self):
        s = self.stack()
        self.assertEqual(s.call("POST", "/cabinet/code", {"msisdn": MSISDN}).status, 200)
        events = s.get(f"/api/risk/ip?ip={IP}").body["events"]
        self.assertEqual([(e["event"], e["scope"]) for e in events], [("send_ok", "cabinet")])

    def test_current_score_decays_but_score_stays(self):
        s = self.stack()
        for i in range(6):
            s.send(f"99670073{1200 + i:04d}")
            s.clock.advance(2)
        before = s.get("/api/risk/ips").body[0]
        self.assertEqual(before["current_score"], before["score"])
        s.clock.advance(601)
        after = s.get("/api/risk/ips").body[0]
        self.assertEqual((after["score"], after["current_score"]), (before["score"], 0))
        self.assertEqual(s.get(f"/api/risk/ip?ip={IP}").body["current_score"], 0)


class AsyncWorkerTest(unittest.TestCase):
    def test_worker_processes_all_events(self):
        clock = FakeClock()
        engine = RiskEngine(clock=clock, id_key=b"k")
        sink = engine.start_worker()
        try:
            for i in range(100):
                sink({"event": "otp_issued", "ip": "192.0.2.1"}, msisdn=f"99670073{i:04d}",
                     ts=clock() + i)
            self.assertTrue(engine.drain(timeout=5))
            meta = engine.meta()
            self.assertEqual((engine.ingested, engine.dropped, meta["mode"]), (100, 0, "async"))
        finally:
            engine.stop_worker()
        self.assertEqual(engine.mode, "sync")

    def test_async_sink_never_raises(self):
        engine = RiskEngine(clock=FakeClock(), id_key=b"k")
        engine.async_sink(None)  # обработчик не запущен — отброшено
        engine.start_worker(maxsize=10)
        engine.async_sink(42)  # dict(42) падает — отброшено
        engine.stop_worker()
        self.assertEqual(engine.dropped, 2)


class BuildRiskTest(StackTestCase):
    def test_enabled_by_default_and_wired_to_log(self):
        s = self.stack(risk=False)
        with mock.patch.dict(os.environ, {"RISK_ENABLED": "1"}):
            engine = build_risk(s.settings, s.service)
        try:
            self.assertIsNotNone(engine)
            self.assertIs(engine.clock, s.service.clock)
            s.send()
            self.assertTrue(engine.drain(timeout=5))
            self.assertEqual(engine.ingested, 1)
        finally:
            engine.stop_worker()

    def test_disabled_and_broken_config(self):
        s = self.stack(risk=False)
        with mock.patch.dict(os.environ, {"RISK_ENABLED": "0"}):
            self.assertIsNone(build_risk(s.settings, s.service))
        with mock.patch.dict(os.environ, {"RISK_ENABLED": "1", "RISK_WINDOW": "много"}), \
                mock.patch("sys.stderr"):
            self.assertIsNone(build_risk(s.settings, s.service))


if __name__ == "__main__":
    unittest.main()
