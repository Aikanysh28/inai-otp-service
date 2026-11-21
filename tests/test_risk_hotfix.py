"""Hot-fix 1: .env для модуля рисков, автоцепочка LLM, точные причины, навигация и прыжки скролла."""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import tempfile
import unittest
from unittest import mock

from app.config import Settings
from app.main import build_risk
from app.otp_service import OTPService
from app.risk import RiskEngine, RiskSettings
from app.risk.envfile import parse_env, risk_environment
from app.risk.llm import (
    LLMError, LLMProvider, build_request, complete, configured_names, disabled_reason,
    providers_from_settings, startup_line,
)
from app.security_log import SecurityLog
from app.sms import SmsGateway
from app.store import MemoryStore

ROOT = os.path.join(os.path.dirname(__file__), "..")
SECRET = "gsk-TEST-SECRET-123"


class EnvFileTest(unittest.TestCase):
    def test_parser(self):
        text = ("# комментарий\r\n"
                "\r\n"
                "RISK_LLM_PROVIDERS=groq\r\n"
                "  RISK_LLM_GROQ_KEY = \"gsk-quoted\"  \r\n"
                "export RISK_LLM_MODEL='openai/gpt-oss-120b'\n"
                "RISK_SMS_PRICE=2.5 # цена\n"
                "OTP_SECRET=not-mine\n"
                "DASHBOARD_TOKEN=demo\n"
                "строка без равенства\n")
        self.assertEqual(parse_env(text), {
            "RISK_LLM_PROVIDERS": "groq", "RISK_LLM_GROQ_KEY": "gsk-quoted",
            "RISK_LLM_MODEL": "openai/gpt-oss-120b", "RISK_SMS_PRICE": "2.5"})

    def test_environment_wins_and_missing_file_is_fine(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, ".env")
            with open(path, "w", encoding="utf-8") as f:
                f.write("RISK_LLM_PROVIDERS=groq\nRISK_LLM_GROQ_KEY=from-file\nOTP_SECRET=x\n")
            merged, info = risk_environment({"RISK_ENV_FILE": path, "RISK_LLM_GROQ_KEY": "from-env"})
            self.assertEqual(merged["RISK_LLM_GROQ_KEY"], "from-env")       # окружение важнее
            self.assertEqual(merged["RISK_LLM_PROVIDERS"], "groq")          # недостающее — из файла
            self.assertNotIn("OTP_SECRET", merged)                          # чужие переменные не трогаем
            self.assertEqual((info["source"], info["path"]), ("env", os.path.abspath(path)))
            only_file, info = risk_environment({"RISK_ENV_FILE": path})
            self.assertEqual((info["source"], only_file["RISK_LLM_GROQ_KEY"]), (".env", "from-file"))
            nothing, info = risk_environment({"RISK_ENV_FILE": os.path.join(tmp, "нет.env")})
            self.assertEqual((info["source"], info["path"]), ("none", None))
        finally:
            shutil.rmtree(tmp)

    def test_settings_from_env_file(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, ".env")
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"RISK_LLM_GROQ_KEY={SECRET}\r\n")
            s = RiskSettings.from_env(environ={"RISK_ENV_FILE": path}, read_env_file=True)
            self.assertEqual((s.llm_groq_key, s.llm_config_source, s.llm_env_file), (SECRET, ".env", path))
            self.assertNotIn(SECRET, repr(s))
            plain = RiskSettings.from_env(environ={})
            self.assertEqual(plain.llm_config_source, "none")
        finally:
            shutil.rmtree(tmp)


class ChainConfigTest(unittest.TestCase):
    def test_auto_chain_from_keys(self):
        self.assertEqual(configured_names(RiskSettings(llm_groq_key="g")), ["groq"])
        self.assertEqual(configured_names(RiskSettings(llm_gemini_key="m", llm_groq_key="g",
                                                       llm_anthropic_key="a", llm_openrouter_key="o")),
                         ["groq", "openrouter", "gemini", "anthropic"])
        self.assertEqual(configured_names(RiskSettings(llm_api_key="legacy")), ["anthropic"])
        self.assertEqual(configured_names(RiskSettings()), [])
        self.assertEqual([p.name for p in providers_from_settings(RiskSettings(llm_groq_key="g"))], ["groq"])

    def test_precise_disabled_reasons(self):
        self.assertEqual(disabled_reason(RiskSettings())[0], "no_env")
        code, text = disabled_reason(RiskSettings(llm_providers="groq"))
        self.assertEqual(code, "no_key")
        self.assertIn("RISK_LLM_GROQ_KEY", text)
        code, text = disabled_reason(RiskSettings(llm_providers="grok"))
        self.assertEqual(code, "unknown_provider")
        self.assertIn("grok", text)
        self.assertIsNone(disabled_reason(RiskSettings(llm_providers="ollama")))
        summary = RiskEngine(RiskSettings(llm_providers="groq"), id_key=b"k").summary()
        self.assertEqual(summary["fallback_reason"], "no_key")
        self.assertIn("RISK_LLM_GROQ_KEY", summary["fallback_detail"])

    def test_meta_and_startup_line_without_keys(self):
        s = RiskSettings(llm_providers="groq,gemini", llm_groq_key=SECRET, llm_config_source=".env",
                         llm_env_file="/srv/.env")
        llm = RiskEngine(s, id_key=b"k").meta()["llm"]
        self.assertEqual((llm["source_of_config"], llm["env_file"], llm["status"]["code"]),
                         (".env", "/srv/.env", "enabled"))
        self.assertEqual([(p["name"], p["has_key"]) for p in llm["configured_providers"]],
                         [("groq", True), ("gemini", False)])
        self.assertNotIn(SECRET, json.dumps(llm, ensure_ascii=False))
        line = startup_line(s)
        self.assertEqual(line, "[risk] LLM: groq (openai/gpt-oss-120b), ключ задан; источник: .env")
        self.assertEqual(startup_line(RiskSettings()), "[risk] LLM выключена: нет RISK_LLM_PROVIDERS и ключей")

    def test_build_risk_reads_env_file_and_logs_no_key(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, ".env")
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"RISK_LLM_PROVIDERS=groq\nRISK_LLM_GROQ_KEY={SECRET}\n")
            settings = Settings(secret_key=b"s", log_dir=tmp, outbox_path=os.path.join(tmp, "o.jsonl"))
            service = OTPService(settings, SecurityLog(tmp, console=False), store=MemoryStore(),
                                 sms=SmsGateway(settings.outbox_path, echo=False))
            env = {k: v for k, v in os.environ.items() if not k.startswith("RISK_LLM_")}
            env.update(RISK_ENABLED="1", RISK_ENV_FILE=path)
            err = io.StringIO()
            with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stderr(err):
                engine = build_risk(settings, service)
            try:
                self.assertTrue(engine.meta()["llm_enabled"])
                self.assertIn("[risk] LLM: groq", err.getvalue())
                self.assertIn("источник: .env", err.getvalue())
                self.assertNotIn(SECRET, err.getvalue())
            finally:
                engine.stop_worker()
                service.log.close()
        finally:
            shutil.rmtree(tmp)


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


class ClientTest(unittest.TestCase):
    def test_user_agent_everywhere(self):
        for kind in ("openai", "anthropic"):
            request = build_request(LLMProvider("x", "https://example.invalid/v1", "m", key="k", kind=kind), "s", "u")
            self.assertEqual(request.get_header("User-agent"), "otp-risk/1.0")

    def test_empty_content_is_bad_response(self):
        provider = LLMProvider("groq", "https://example.invalid/v1", "openai/gpt-oss-120b", key="k")
        empty = {"choices": [{"message": {"content": "", "reasoning": "думаю…"}, "finish_reason": "length"}]}
        with self.assertRaises(LLMError) as error:
            complete(provider, "s", "u", 1, lambda request, timeout=None: _Resp(empty))
        self.assertEqual(error.exception.kind, "bad_response")


class DashboardAndComposeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, "app", "static", "dashboard.html"), encoding="utf-8") as f:
            cls.html = f.read()
        cls.js = re.search(r'<script id="risk-script">(.*?)</script>', cls.html, re.S).group(1)
        with open(os.path.join(ROOT, "docker-compose.yml"), encoding="utf-8") as f:
            cls.compose = f.read()

    def test_sticky_tabs_and_history(self):
        self.assertRegex(self.html, r"\.wrap > \.hero \{ position: sticky; top: 0;")
        self.assertIn('id="tabbtn-risk" role="tab"', self.html)
        self.assertIn('addEventListener("hashchange"', self.js)
        self.assertIn('addEventListener("popstate"', self.js)
        self.assertIn("history.pushState", self.js)

    def test_no_scroll_jumps_in_code(self):
        self.assertNotIn("scrollIntoView", self.js)
        self.assertNotIn("scrollTo(0", self.js)
        self.assertEqual(re.findall(r"\.focus\(\)", self.js), [])
        self.assertNotIn(".innerHTML", self.js)
        self.assertIn("function patchList", self.js)       # списки обновляются по ключу
        self.assertIn("function keepScroll", self.js)      # страховка для цикла опроса
        self.assertRegex(self.html, r"#risk-alerts \{ max-height: \d+px; overflow-y: auto;")

    def test_compose_passes_risk_llm(self):
        for line in ("RISK_LLM_PROVIDERS: ${RISK_LLM_PROVIDERS:-}", "RISK_LLM_GROQ_KEY: ${RISK_LLM_GROQ_KEY:-}",
                     "RISK_LLM_OPENROUTER_KEY: ${RISK_LLM_OPENROUTER_KEY:-}",
                     "RISK_LLM_GEMINI_KEY: ${RISK_LLM_GEMINI_KEY:-}", "RISK_LLM_MODEL: ${RISK_LLM_MODEL:-}"):
            self.assertIn(line, self.compose)


if __name__ == "__main__":
    unittest.main()
