"""Спринт 4: граф, сводка инцидента (шаблон и LLM), маршруты, attack.py --only pumping, дашборд.

unittest, FakeClock, без внешней сети (LLM подменяется; attack.py ходит в локальный тестовый сервер).
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import tempfile
import threading
import time
import unittest
from unittest import mock

import attack
from app.api import OTPApi, Request
from app.config import Settings
from app.main import create_server
from app.otp_service import OTPService
from app.risk import RiskEngine, RiskSettings
from app.risk.simulate import FakeClock, Traffic, demo_story
from app.security_log import SecurityLog
from app.sms import SmsGateway
from app.store import MemoryStore

FULL_NUMBER = re.compile(r"996\d{9}")
KEY = b"test-risk-key"


def engine_with(clock=None, **settings) -> RiskEngine:
    return RiskEngine(RiskSettings(**settings), clock=clock or FakeClock(), id_key=KEY)


class GraphTest(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.engine = engine_with(self.clock)
        self.traffic = Traffic(self.engine.sink, self.clock, seed=4)

    def test_pumping_bot_is_a_star(self):
        self.traffic.pumping_bot("45.13.7.200", count=12)
        graph = self.engine.graph()
        ips = [n for n in graph["nodes"] if n["type"] == "ip"]
        numbers = [n for n in graph["nodes"] if n["type"] == "number"]
        self.assertEqual([(n["label"], n["level"]) for n in ips], [("45.13.7.200", "high")])
        self.assertEqual(len(numbers), 12)
        self.assertEqual(len(graph["edges"]), 12)
        self.assertTrue(all(e["source"] == "ip:45.13.7.200" and e["sends"] == 1 for e in graph["edges"]))
        self.assertEqual(numbers[0]["label"], "+996700***200")
        self.assertFalse(graph["truncated"])

    def test_number_with_two_ips_is_one_node(self):
        _, msisdn = self.traffic.normal_user(ip="192.0.2.1")
        self.clock.advance(60)
        self.traffic.normal_user(ip="192.0.2.2", msisdn=msisdn)
        graph = self.engine.graph()
        numbers = [n for n in graph["nodes"] if n["type"] == "number"]
        self.assertEqual(len(numbers), 1)
        self.assertEqual(sorted(e["source"] for e in graph["edges"]), ["ip:192.0.2.1", "ip:192.0.2.2"])
        self.assertTrue(all(e["verifies"] >= 1 for e in graph["edges"]))

    def test_limits_and_truncation(self):
        self.traffic.pumping_bot("45.13.7.200", count=6)
        self.traffic.normal_user(ip="192.0.2.1")
        one_ip = self.engine.graph(max_ips=1)
        self.assertEqual([n["label"] for n in one_ip["nodes"] if n["type"] == "ip"], ["45.13.7.200"])
        self.assertTrue(one_ip["truncated"])
        few_numbers = self.engine.graph(max_numbers=3)
        self.assertEqual(sum(n["type"] == "number" for n in few_numbers["nodes"]), 3)
        self.assertTrue(few_numbers["truncated"])
        self.assertEqual(len(few_numbers["edges"]), 3)

    def test_window_and_no_full_numbers(self):
        demo_story(self.engine.sink, self.clock)
        graph = self.engine.graph(window=3600, max_ips=50, max_numbers=500)
        self.assertIsNone(FULL_NUMBER.search(json.dumps(graph, ensure_ascii=False)))
        self.clock.advance(3601)
        self.assertEqual(self.engine.graph()["nodes"], [])


class SummaryTemplateTest(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.engine = engine_with(self.clock)
        self.ips = demo_story(self.engine.sink, self.clock)

    def test_three_incident_types_with_right_ips(self):
        summary = self.engine.summary(window=3600)
        self.assertEqual(summary["source"], "template")
        types = {inc["type"]: inc["ip"] for inc in summary["incidents"]}
        self.assertEqual(types, {"pumping": self.ips["pumping_bot"],
                                 "distributed": self.ips["distributed"],
                                 "bruteforce": self.ips["bruteforce"]})
        text = summary["text"]
        for phrase in ("SMS-флуд", "распределённый подбор кодов", "подбор кода к номеру",
                       "сом", "на 6-м номере", "в боевом режиме", "Рекомендации"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase.lower(), text.lower())

    def test_detection_moment_and_range(self):
        pumping = next(i for i in self.engine.incidents(3600) if i["type"] == "pumping")
        self.assertEqual(pumping["first_high"]["at_number"], 6)
        self.assertGreater(pumping["first_high"]["after_seconds"], 0)
        self.assertEqual(pumping["number_range"], {"first": "+996700***200", "last": "+996700***239"})
        self.assertEqual(pumping["sms_cost"], 40.0)

    def test_no_full_numbers(self):
        summary = self.engine.summary(window=3600)
        self.assertIsNone(FULL_NUMBER.search(json.dumps(summary, ensure_ascii=False)))

    def test_quiet_period(self):
        engine = engine_with()
        summary = engine.summary()
        self.assertEqual(summary["incidents"], [])
        self.assertIn("инцидентов не обнаружено", summary["text"])


class _FakeResponse:
    def __init__(self, payload: dict):
        self.payload = payload

    def read(self) -> bytes:
        return json.dumps(self.payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


LLM_TEXT = ("Идёт SMS pumping с IP-1: коды запрошены на 12 номеров подряд, отправлено 12 SMS, "
            "потери 12 сом. Тревога высокого уровня поднялась на 6-м номере; в боевом режиме "
            "источник получил бы блокировку.")
LLM_OK = {"content": [{"type": "thinking", "thinking": ""}, {"type": "text", "text": LLM_TEXT}],
          "stop_reason": "end_turn"}


class SummaryLlmTest(unittest.TestCase):
    def make(self, opener, **settings):
        clock = FakeClock()
        engine = engine_with(clock, **settings)
        Traffic(engine.sink, clock, seed=1).pumping_bot("45.13.7.200", count=12)
        engine._summary.opener = opener
        return engine, clock

    def test_without_key_network_is_not_called(self):
        opener = mock.Mock(side_effect=AssertionError("сеть вызвана"))
        engine, _ = self.make(opener)
        summary = engine.summary()
        self.assertEqual(summary["source"], "template")
        opener.assert_not_called()
        self.assertFalse(engine.meta()["llm_enabled"])

    def test_error_falls_back_to_template(self):
        engine, _ = self.make(mock.Mock(side_effect=OSError("нет сети")), llm_api_key="k")
        self.assertEqual(engine.summary()["source"], "template")

    def test_refusal_falls_back_to_template(self):
        refusal = {"content": [], "stop_reason": "refusal"}
        engine, _ = self.make(mock.Mock(return_value=_FakeResponse(refusal)), llm_api_key="k")
        self.assertEqual(engine.summary()["source"], "template")

    def test_hanging_call_respects_timeout(self):
        release = threading.Event()

        def hang(*args, **kwargs):
            release.wait(5)
            return _FakeResponse(LLM_OK)

        engine, _ = self.make(hang, llm_api_key="k", llm_timeout=0.2)
        started = time.monotonic()
        summary = engine.summary()
        release.set()
        self.assertEqual(summary["source"], "template")
        self.assertLess(time.monotonic() - started, 2)

    def test_success_uses_llm_text_and_safe_request(self):
        opener = mock.Mock(return_value=_FakeResponse(LLM_OK))
        engine, _ = self.make(opener, llm_api_key="secret-key", llm_model="claude-haiku-5-5")
        summary = engine.summary()
        self.assertEqual((summary["source"], summary["text"]),
                         ("llm", LLM_TEXT.replace("IP-1", "45.13.7.200")))
        request = opener.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.anthropic.com/v1/messages")
        self.assertEqual(request.get_header("X-api-key"), "secret-key")
        self.assertEqual(request.get_header("Anthropic-version"), "2023-06-01")
        self.assertEqual(opener.call_args.kwargs["timeout"], engine.settings.llm_timeout)
        body = request.data.decode("utf-8")
        self.assertIsNone(FULL_NUMBER.search(body))
        payload = json.loads(body)
        self.assertEqual(payload["model"], "claude-haiku-5-5")
        facts = json.loads(payload["messages"][0]["content"])
        keys = set()

        def collect(value):
            if isinstance(value, dict):
                keys.update(value)
                for item in value.values():
                    collect(item)
            elif isinstance(value, list):
                for item in value:
                    collect(item)

        collect(facts)
        self.assertEqual(keys & {"code", "codes", "msisdn", "msisdn_id", "events", "hash"}, set())
        self.assertIn("incidents", facts)

    def test_cache_for_30_seconds(self):
        opener = mock.Mock(return_value=_FakeResponse(LLM_OK))
        engine, clock = self.make(opener, llm_api_key="k")
        first = engine.summary()
        second = engine.summary()
        self.assertEqual(opener.call_count, 1)
        self.assertTrue(second["cached"])
        self.assertEqual(first["text"], second["text"])
        clock.advance(31)
        engine.summary()
        self.assertEqual(opener.call_count, 2)


class RiskApiSprint4Test(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="risk_s4_")
        self.clock = FakeClock()
        settings = Settings(secret_key=b"test-secret", log_dir=self.tmp,
                            outbox_path=os.path.join(self.tmp, "sms.jsonl"))
        self.log = SecurityLog(self.tmp, clock=self.clock, console=False)
        service = OTPService(settings, self.log, clock=self.clock, store=MemoryStore(self.clock),
                             sms=SmsGateway(settings.outbox_path, self.clock, echo=False))
        self.engine = RiskEngine(clock=self.clock, id_key=KEY)
        self.log.add_sink(self.engine.sink)
        self.api = OTPApi(service, "dev", risk=self.engine)
        self.off = OTPApi(service, "dev", risk=None)

    def tearDown(self):
        self.log.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def get(self, path, api=None, token="dev"):
        headers = {"X-Dashboard-Token": token} if token else {}
        return (api or self.api).handle(Request.build("GET", path, headers, b"", "127.0.0.1"))

    def test_routes(self):
        for i in range(6):
            body = json.dumps({"msisdn": f"99670073{1200 + i:04d}"}).encode()
            self.api.handle(Request.build("POST", "/otp/send", {}, body, "198.51.100.9"))
            self.clock.advance(2)
        graph = self.get("/api/risk/graph").body
        self.assertEqual(len(graph["edges"]), 6)
        summary = self.get("/api/risk/summary?window=600").body
        self.assertEqual(summary["source"], "template")
        self.assertEqual([i["ip"] for i in summary["incidents"]], ["198.51.100.9"])
        for path in ("/api/risk/graph", "/api/risk/summary"):
            with self.subTest(path=path):
                self.assertEqual(self.get(path, token=None).status, 401)
                self.assertEqual(self.get(path, api=self.off).body, {"status": "risk_disabled"})
                for bad in ("abc", "10", "4000"):
                    r = self.get(f"{path}?window={bad}")
                    self.assertEqual((r.status, r.body["status"]), (400, "bad_request"))
                    self.assertIn("window", r.body["error"])
                self.assertIsNone(FULL_NUMBER.search(json.dumps(self.get(path).body, ensure_ascii=False)))


class AttackScriptTest(unittest.TestCase):
    def test_only_choices_and_default_attacks(self):
        parser = attack.build_parser()
        for only in ("single", "distributed", "pumping"):
            self.assertEqual(parser.parse_args(["--only", only]).only, only)
        defaults = parser.parse_args([])
        self.assertIsNone(defaults.only)
        self.assertEqual(attack.selected_attacks(None), ["single", "distributed"])
        self.assertNotIn("pumping", attack.selected_attacks(None))
        self.assertEqual(attack.selected_attacks("pumping"), ["pumping"])
        self.assertEqual((defaults.pause, defaults.attempts, defaults.numbers), (61, 1000, 50))
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            parser.parse_args(["--only", "everything"])

    def test_pumping_against_test_server(self):
        tmp = tempfile.mkdtemp(prefix="risk_pump_")
        settings = Settings(secret_key=b"test-secret", log_dir=tmp, dashboard_token="t",
                            outbox_path=os.path.join(tmp, "sms.jsonl"),
                            trusted_proxies=frozenset({"127.0.0.1"}))
        # Дневной сценарий: ночью дополнительные баллы меняют момент тревоги.
        clock = FakeClock()
        log = SecurityLog(tmp, clock=clock, console=False)
        service = OTPService(settings, log, clock=clock, store=MemoryStore(clock),
                             sms=SmsGateway(settings.outbox_path, clock=clock, echo=False))
        with mock.patch.dict(os.environ, {"RISK_ENABLED": "1"}):
            server = create_server(settings, service, host="127.0.0.1", port=0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            result = attack.attack_pumping(base, "99670073", count=6, interval=0, jitter=0,
                                           client_ip="198.51.100.9", token="t", quiet=True)
            self.assertEqual(result["stats"], {200: 6})
            self.assertEqual(result["risk"]["level"], "high")
            self.assertEqual(result["first_high_at"], 6)
            self.assertTrue(result["trusts_forwarded"])
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertTrue(attack.report_pumping(result, "t"))
            self.assertIn("обнаружил бота на 6-м номере", out.getvalue())
            self.assertIn("Базовая защита не остановила рассылку", out.getvalue())
        finally:
            server.shutdown()
            server.server_close()
            log.close()
            shutil.rmtree(tmp, ignore_errors=True)

    def test_report_without_token_is_success_with_warning(self):
        result = {"ip": "198.51.100.9", "count": 3, "sent": 3, "stats": {200: 3}, "price": 1.0,
                  "currency": "сом", "risk": None, "first_high_at": None, "trusts_forwarded": None}
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertTrue(attack.report_pumping(result, None))
        self.assertIn("Токен админки не передан", out.getvalue())


class DashboardSprint4Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.path.join(os.path.dirname(__file__), "..", "app", "static", "dashboard.html")
        with open(path, encoding="utf-8") as f:
            html = f.read()
        cls.js = re.search(r'<script id="risk-script">(.*?)</script>', html, re.S).group(1)
        cls.html = html

    def test_new_blocks_and_paths(self):
        for element_id in ("risk-summary-btn", "risk-summary", "risk-graph-svg", "risk-scatter-window"):
            self.assertIn(f'id="{element_id}"', self.html)
        for path in ("/api/risk/graph", "/api/risk/summary"):
            self.assertIn(path, self.js)

    def test_no_local_storage_and_russian_levels(self):
        self.assertNotIn("localStorage", self.js)
        for name in ("Низкий", "Средний", "Критический"):
            self.assertIn(name, self.js)
        self.assertNotIn(".innerHTML", self.js)


if __name__ == "__main__":
    unittest.main()
