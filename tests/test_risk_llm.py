"""LLM-провайдеры для сводки инцидента (unittest; сеть не используется — urlopen подменён)."""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import socket
import tempfile
import unittest
import urllib.error
from unittest import mock

from app.api import OTPApi, Request
from app.config import Settings
from app.otp_service import OTPService
from app.risk import RiskEngine, RiskSettings
from app.risk import llm_check
from app.risk.llm import LLMProvider, build_request, providers_from_settings
from app.risk.simulate import FakeClock, Traffic, demo_story
from app.risk.summary import fact_check
from app.security_log import SecurityLog
from app.sms import SmsGateway
from app.store import MemoryStore

FULL_NUMBER = re.compile(r"996\d{9}")
KEYS = {"llm_groq_key": "gsk-SECRET-groq", "llm_gemini_key": "AIza-SECRET-gemini",
        "llm_openrouter_key": "sk-or-SECRET", "llm_anthropic_key": "sk-ant-SECRET",
        "llm_api_key": "SECRET-legacy"}
GOOD = ("Идёт SMS pumping с IP-1: коды запрошены на 12 номеров подряд, отправлено 12 SMS, "
        "потери 12 сом. Тревога высокого уровня поднялась на 6-м номере; в боевом режиме "
        "источник получил бы блокировку.")


class FakeClockMono:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class _Resp:
    status = 200

    def __init__(self, payload):
        self.payload = payload

    def read(self):
        return json.dumps(self.payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def openai_ok(text=GOOD):
    return _Resp({"choices": [{"message": {"role": "assistant", "content": text}}]})


def http_error(url, code, retry_after=None):
    headers = {"Retry-After": str(retry_after)} if retry_after is not None else {}
    return urllib.error.HTTPError(url, code, "error", headers, None)


class Router:
    """Подменённый urlopen: ответ выбирается по имени хоста провайдера; запросы записываются."""

    HOSTS = {"groq": "api.groq.com", "gemini": "generativelanguage.googleapis.com",
             "openrouter": "openrouter.ai", "ollama": "localhost:11434",
             "anthropic": "api.anthropic.com"}

    def __init__(self, **behaviour):
        # провайдер -> функция(request, timeout) -> ответ или исключение
        self.behaviour = behaviour
        self.calls: list[tuple[str, object]] = []

    def __call__(self, request, timeout=None):
        name = next(n for n, host in self.HOSTS.items() if host in request.full_url)
        self.calls.append((name, request))
        action = self.behaviour.get(name, lambda r, t: openai_ok())
        result = action(request, timeout)
        if isinstance(result, BaseException):
            raise result
        return result

    def names(self):
        return [name for name, _ in self.calls]


def engine_with(router, bot=True, clock=None, **settings) -> RiskEngine:
    clock = clock or FakeClock()
    engine = RiskEngine(RiskSettings(**settings), clock=clock, id_key=b"k")
    if bot:
        Traffic(engine.sink, clock, seed=1).pumping_bot("45.13.7.200", count=12)
    engine._summary.opener = router
    return engine


class PresetsTest(unittest.TestCase):
    def test_openai_request_shape(self):
        expected = {
            "groq": "https://api.groq.com/openai/v1/chat/completions",
            "gemini": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
            "openrouter": "https://openrouter.ai/api/v1/chat/completions",
        }
        s = RiskSettings(llm_providers="groq,gemini,openrouter", **KEYS)
        providers = providers_from_settings(s)
        self.assertEqual([p.name for p in providers], ["groq", "gemini", "openrouter"])
        for provider in providers:
            with self.subTest(provider=provider.name):
                request = build_request(provider, "system", "user")
                self.assertEqual(request.full_url, expected[provider.name])
                self.assertEqual(request.get_header("Authorization"), "Bearer " + provider.key)
                self.assertEqual(request.get_header("Content-type"), "application/json")
                # без своего User-Agent Groq отвечает 403 (защита от ботов режет «Python-urllib»)
                self.assertEqual(request.get_header("User-agent"), "otp-risk/1.0")
                body = json.loads(request.data)
                self.assertEqual((body["model"], body["temperature"], body["max_tokens"]),
                                 (provider.model, 0.2, 1500))
                self.assertEqual([m["role"] for m in body["messages"]], ["system", "user"])
        self.assertEqual(providers[0].model, "openai/gpt-oss-120b")
        groq_body = json.loads(build_request(providers[0], "s", "u").data)
        self.assertEqual(groq_body["reasoning_effort"], "low")  # gpt-oss: короткое рассуждение
        body = json.loads(build_request(providers[1], "s", "u").data)
        self.assertNotIn("reasoning_effort", body)
        self.assertEqual(providers[2].model, "openrouter/free")

    def test_ollama_without_key_and_skipping_keyless(self):
        s = RiskSettings(llm_providers="groq,ollama,gemini")  # ключей нет
        providers = providers_from_settings(s)
        self.assertEqual([p.name for p in providers], ["ollama"])
        request = build_request(providers[0], "s", "u")
        self.assertEqual(request.full_url, "http://localhost:11434/v1/chat/completions")
        self.assertIsNone(request.get_header("Authorization"))
        self.assertEqual(request.get_header("User-agent"), "otp-risk/1.0")
        self.assertEqual(providers[0].model, "qwen2.5:7b")

    def test_model_and_base_url_override_first_only(self):
        s = RiskSettings(llm_providers="groq,gemini", llm_model="llama-3.1-8b-instant",
                         llm_base_url="http://127.0.0.1:9/v1/", **KEYS)
        first, second = providers_from_settings(s)
        self.assertEqual((first.model, first.base_url),
                         ("llama-3.1-8b-instant", "http://127.0.0.1:9/v1"))
        self.assertEqual(second.base_url,
                         "https://generativelanguage.googleapis.com/v1beta/openai")

    def test_backward_compatible_anthropic(self):
        s = RiskSettings(llm_api_key="SECRET-legacy")
        (provider,) = providers_from_settings(s)
        self.assertEqual((provider.name, provider.kind, provider.model),
                         ("anthropic", "anthropic", "claude-haiku-5-5"))
        request = build_request(provider, "s", "u")
        self.assertEqual(request.full_url, "https://api.anthropic.com/v1/messages")
        self.assertEqual(request.get_header("X-api-key"), "SECRET-legacy")
        self.assertEqual(request.get_header("User-agent"), "otp-risk/1.0")
        self.assertIsNone(request.get_header("Authorization"))

    def test_keys_hidden_from_repr(self):
        text = repr(RiskSettings(llm_providers="groq", **KEYS)) + repr(
            providers_from_settings(RiskSettings(llm_providers="groq", **KEYS)))
        for key in KEYS.values():
            self.assertNotIn(key, text)


class ChainTest(unittest.TestCase):
    def test_rate_limit_falls_through_to_next_provider(self):
        router = Router(groq=lambda r, t: http_error(r.full_url, 429, 30))
        engine = engine_with(router, llm_providers="groq,gemini", llm_cache_seconds=0, **KEYS)
        summary = engine.summary()
        self.assertEqual(router.names(), ["groq", "gemini"])
        self.assertEqual((summary["source"], summary["provider"], summary["fallback_reason"]),
                         ("llm", "gemini", None))
        self.assertIn("45.13.7.200", summary["text"])
        self.assertIsInstance(summary["latency_ms"], int)

    def test_all_fail_gives_template_with_reason(self):
        cases = {
            "auth": lambda r, t: http_error(r.full_url, 401),
            "network": lambda r, t: urllib.error.URLError(ConnectionRefusedError()),
            "rate_limited": lambda r, t: http_error(r.full_url, 429),
            "bad_response": lambda r, t: _Resp({"unexpected": True}),
        }
        for reason, action in cases.items():
            with self.subTest(reason=reason):
                router = Router(groq=action, gemini=action)
                engine = engine_with(router, llm_providers="groq,gemini", **KEYS)
                summary = engine.summary()
                self.assertEqual((summary["source"], summary["fallback_reason"]),
                                 ("template", reason))
                self.assertIsNone(summary["provider"])
                self.assertEqual(engine.meta()["llm"]["fallbacks"], {reason: 1})

    def test_server_error_counts_as_network(self):
        router = Router(groq=lambda r, t: http_error(r.full_url, 503))
        summary = engine_with(router, llm_providers="groq", **KEYS).summary()
        self.assertEqual(summary["fallback_reason"], "network")

    def test_cooldown_after_429_respects_retry_after(self):
        router = Router(groq=lambda r, t: http_error(r.full_url, 429, 30))
        engine = engine_with(router, llm_providers="groq,gemini", llm_cache_seconds=0, **KEYS)
        mono = FakeClockMono()
        engine._summary.chain.monotonic = mono
        engine.summary()
        engine.summary()
        self.assertEqual(router.names(), ["groq", "gemini", "gemini"])
        mono.now += 31
        engine.summary()
        self.assertEqual(router.names()[-2:], ["groq", "gemini"])

    def test_cooldown_after_auth_until_restart(self):
        router = Router(groq=lambda r, t: http_error(r.full_url, 403))
        engine = engine_with(router, llm_providers="groq,gemini", llm_cache_seconds=0, **KEYS)
        mono = FakeClockMono()
        engine._summary.chain.monotonic = mono
        engine.summary()
        mono.now += 10 ** 7
        engine.summary()
        self.assertEqual(router.names(), ["groq", "gemini", "gemini"])
        self.assertEqual(engine.meta()["llm"]["providers"][0]["cooling"], "auth")

    def test_time_budget_for_whole_chain(self):
        mono = FakeClockMono()

        def slow(request, timeout):
            mono.now += timeout  # провайдер «висел» весь свой таймаут
            return socket.timeout("timed out")

        router = Router(groq=slow, gemini=slow, openrouter=slow)
        engine = engine_with(router, llm_providers="groq,gemini,openrouter", llm_timeout=6, **KEYS)
        engine._summary.chain.monotonic = mono
        started = mono.now
        summary = engine.summary()
        self.assertEqual(router.names(), ["groq", "gemini"])  # на третьего бюджета не осталось
        self.assertLessEqual(mono.now - started, 2 * 6)
        self.assertEqual(summary["fallback_reason"], "timeout")

    def test_cache_covers_whole_chain(self):
        router = Router(groq=lambda r, t: http_error(r.full_url, 429))
        engine = engine_with(router, llm_providers="groq,gemini", **KEYS)
        first = engine.summary()
        second = engine.summary()
        self.assertEqual(router.names(), ["groq", "gemini"])
        self.assertTrue(second["cached"])
        self.assertEqual((first["text"], first["provider"]), (second["text"], second["provider"]))
        engine.clock.advance(31)
        engine.summary()
        self.assertEqual(len(router.calls), 3)  # groq ещё отдыхает после 429, вызван только gemini

    def test_disabled_and_no_incidents_do_not_call(self):
        router = Router()
        disabled = engine_with(router).summary()
        self.assertEqual((disabled["source"], disabled["fallback_reason"]),
                         ("template", "disabled"))
        quiet = engine_with(router, bot=False, llm_providers="groq", **KEYS).summary()
        self.assertEqual((quiet["source"], quiet["fallback_reason"]), ("template", "no_incidents"))
        self.assertIn("инцидентов не обнаружено", quiet["text"])
        self.assertEqual(router.calls, [])


class PrivacyTest(unittest.TestCase):
    def test_only_aggregates_with_pseudonyms_leave(self):
        text = ("За период обнаружено 3 инцидента. IP-1 вёл распределённый подбор, "
                "IP-2 рассылал SMS pumping, IP-3 подбирал код к номеру. "
                "В боевом режиме источники получили бы отказ или более строгие задержки.")
        router = Router(groq=lambda r, t: openai_ok(text))
        clock = FakeClock()
        engine = RiskEngine(RiskSettings(llm_providers="groq", **KEYS), clock=clock, id_key=b"k")
        ips = demo_story(engine.sink, clock)
        engine._summary.opener = router
        summary = engine.summary(window=3600)
        body = router.calls[0][1].data.decode("utf-8")
        real_ips = [inc["ip"] for inc in summary["incidents"]]
        for ip in real_ips + list(ips.values()):
            self.assertNotIn(ip, body)
        self.assertIsNone(FULL_NUMBER.search(body))
        user = json.loads(json.loads(body)["messages"][1]["content"])
        keys: set[str] = set()

        def collect(value):
            if isinstance(value, dict):
                keys.update(value)
                [collect(v) for v in value.values()]
            elif isinstance(value, list):
                [collect(v) for v in value]

        collect(user)
        self.assertEqual(keys & {"code", "codes", "msisdn", "msisdn_id", "events", "hash", "ts",
                                 "first_seen", "last_seen"}, set())
        self.assertEqual([i["ip"] for i in user["incidents"]], ["IP-1", "IP-2", "IP-3"])
        self.assertEqual(summary["source"], "llm")
        for ip in real_ips:
            self.assertIn(ip, summary["text"])
        self.assertNotIn("IP-1", summary["text"])


class FactCheckTest(unittest.TestCase):
    def run_with(self, text):
        router = Router(groq=lambda r, t: openai_ok(text))
        return engine_with(router, llm_providers="groq", **KEYS).summary()

    def test_correct_answer_accepted(self):
        summary = self.run_with(GOOD)
        self.assertEqual((summary["source"], summary["provider"], summary["model"]),
                         ("llm", "groq", "openai/gpt-oss-120b"))

    def test_invented_number_rejected(self):
        summary = self.run_with(GOOD.replace("потери 12 сом", "потери 999 сом"))
        self.assertEqual((summary["source"], summary["fallback_reason"]),
                         ("template", "fact_check"))

    def test_invented_alias_rejected(self):
        summary = self.run_with(GOOD + " Похожая активность была с IP-9.")
        self.assertEqual(summary["fallback_reason"], "fact_check")

    def test_markdown_cleaned_or_rejected(self):
        cleaned = self.run_with("## Сводка\n**Внимание:** " + GOOD + "\n- источник: IP-1")
        self.assertEqual(cleaned["source"], "llm")
        self.assertNotIn("**", cleaned["text"])
        self.assertNotIn("##", cleaned["text"])
        table = self.run_with(GOOD + "\n| IP | SMS |\n|---|---|\n| IP-1 | 12 |")
        self.assertEqual(table["fallback_reason"], "fact_check")
        code = self.run_with(GOOD + "\n```json\n{}\n```")
        self.assertEqual(code["fallback_reason"], "fact_check")

    def test_masks_survive_markdown_cleanup(self):
        text = GOOD + " Номера от +996700***200 до +996700***211, **важно**."
        facts = {"n": [12, 6, 200, 211, 996700], "c": "сом"}
        cleaned = fact_check(text, facts, {"IP-1": "1.2.3.4"})
        self.assertIsNotNone(cleaned)
        self.assertIn("+996700***200", cleaned)
        self.assertIn("+996700***211", cleaned)
        self.assertNotIn("**важно**", cleaned)

    def test_length_limits(self):
        self.assertEqual(self.run_with("IP-1: SMS pumping.")["fallback_reason"], "fact_check")
        self.assertEqual(self.run_with(GOOD * 10)["fallback_reason"], "fact_check")

    def test_number_formats(self):
        payload = {"sms": 1200, "cost": 1200.5, "period": {"from": "23:32"}}
        aliases = {"IP-1": "1.2.3.4"}
        base = ("Текст для проверки формата чисел, он достаточно длинный, "
                "чтобы пройти минимальную длину. ")
        for number in ("1 200", "1200", "1 200,5", "1200.5", "23:32"):
            with self.subTest(number=number):
                text = base + f"Значение {number} от IP-1."
                self.assertIsNotNone(fact_check(text, payload, aliases))
        self.assertIsNone(fact_check(base + "Значение 1 201.", payload, aliases))


class MetaAndApiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="risk_llm_")
        self.clock = FakeClock()
        settings = Settings(secret_key=b"test-secret", log_dir=self.tmp,
                            outbox_path=os.path.join(self.tmp, "sms.jsonl"))
        self.log = SecurityLog(self.tmp, clock=self.clock, console=False)
        service = OTPService(settings, self.log, clock=self.clock, store=MemoryStore(self.clock),
                             sms=SmsGateway(settings.outbox_path, self.clock, echo=False))
        self.engine = RiskEngine(RiskSettings(llm_providers="groq,gemini,ollama", **KEYS),
                                 clock=self.clock, id_key=b"k")
        self.log.add_sink(self.engine.sink)
        eight = (GOOD.replace("12 номеров", "8 номеров").replace("12 SMS", "8 SMS")
                 .replace("12 сом", "8 сом"))
        self.router = Router(groq=lambda r, t: http_error(r.full_url, 401),
                             gemini=lambda r, t: openai_ok(eight))
        self.engine._summary.opener = self.router
        self.api = OTPApi(service, "dev", risk=self.engine)
        for i in range(8):
            body = json.dumps({"msisdn": f"99670073{1200 + i:04d}"}).encode()
            self.api.handle(Request.build("POST", "/otp/send", {}, body, "198.51.100.9"))
            self.clock.advance(2)

    def tearDown(self):
        self.log.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def get(self, path):
        request = Request.build("GET", path, {"X-Dashboard-Token": "dev"}, b"", "127.0.0.1")
        return self.api.handle(request)

    def test_meta_llm_block_and_no_keys_anywhere(self):
        summary = self.get("/api/risk/summary").body
        self.assertEqual((summary["source"], summary["provider"]), ("llm", "gemini"))
        meta = self.get("/api/risk/meta").body
        llm = meta["llm"]
        self.assertEqual([(p["name"], p["has_key"]) for p in llm["providers"]],
                         [("groq", True), ("gemini", True), ("ollama", False)])
        self.assertEqual(llm["providers"][0]["cooling"], "auth")
        self.assertEqual(llm["calls_ok"], 1)
        self.assertTrue(meta["llm_enabled"])
        dumped = json.dumps([summary, meta, self.engine.meta(), repr(self.engine.settings)],
                            ensure_ascii=False)
        for key in KEYS.values():
            self.assertNotIn(key, dumped)


class LlmCheckTest(unittest.TestCase):
    def test_check_reports_without_keys(self):
        def fake_urlopen(request, timeout=None):
            if request.full_url.endswith("/models"):
                models = [{"id": "llama-3.3-70b-versatile"}, {"id": "whisper-large"}]
                return _Resp({"data": models})
            text = ("За период обнаружено 3 инцидента. IP-1 вёл распределённый подбор, "
                    "IP-2 рассылал SMS pumping, IP-3 подбирал код к номеру. "
                    "В боевом режиме источники получили бы отказ или более строгие задержки.")
            return openai_ok(text)

        env = {"RISK_LLM_PROVIDERS": "groq,gemini", "RISK_LLM_GROQ_KEY": KEYS["llm_groq_key"]}
        out = io.StringIO()
        with mock.patch.dict(os.environ, env, clear=False), \
                mock.patch("urllib.request.urlopen", fake_urlopen), \
                contextlib.redirect_stdout(out):
            code = llm_check.main()
        text = out.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("ключ задан: да", text)
        self.assertIn("gemini: ключ задан: нет", text)
        self.assertIn("llama-3.3-70b-versatile", text)
        self.assertNotIn("whisper", text)
        self.assertIn("проверка фактов: пройдена", text)
        self.assertNotIn(KEYS["llm_groq_key"], text)


class ProviderPublicTest(unittest.TestCase):
    def test_public_has_no_key(self):
        provider = LLMProvider("groq", "https://x", "m", key="SECRET-x")
        self.assertNotIn("SECRET-x", json.dumps(provider.public()) + repr(provider))
        self.assertTrue(provider.public()["has_key"])


if __name__ == "__main__":
    unittest.main()
