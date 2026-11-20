"""Вкладка «Риски» в админке (unittest; работает и через pytest). Без браузера: проверки HTML/JS."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from html.parser import HTMLParser

from app.api import OTPApi, Request
from app.config import Settings
from app.otp_service import OTPService
from app.security_log import SecurityLog
from app.store import MemoryStore

# id и элементы старой вкладки «Журнал» (из версии файла до спринта 3)
LEGACY_IDS = ("meta", "live", "tiles", "tableToggle", "legend", "chartBox", "chart", "tooltip",
              "chartTable", "topIps", "blocks", "filters", "events")
LEGACY_SNIPPETS = (
    "async function load()", "function renderChart()", "function renderTiles()",
    "function renderTopIps()", "function renderBlocks()", "function renderEvents()",
    'fetch(API, { cache: "no-store" })', "/api/security/events?limit=300",
)


class _Collector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.elements: list[tuple[str, dict]] = []

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


class DashboardTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="risk_dash_")
        settings = Settings(secret_key=b"test-secret", log_dir=cls.tmp,
                            outbox_path=os.path.join(cls.tmp, "outbox", "sms.jsonl"))
        cls.log = SecurityLog(cls.tmp, console=False)
        cls.api = OTPApi(OTPService(settings, cls.log, store=MemoryStore()))
        response = cls.api.handle(Request.build("GET", "/dashboard", {}, b"", "127.0.0.1"))
        cls.status = response.status
        cls.html = response.body.decode("utf-8")
        parser = _Collector()
        parser.feed(cls.html)
        cls.elements = parser.elements
        cls.ids = {attrs["id"]: (tag, attrs) for tag, attrs in cls.elements if "id" in attrs}
        cls.scripts = re.findall(r"<script([^>]*)>(.*?)</script>", cls.html, re.S)
        cls.risk_js = next(body for attrs, body in cls.scripts if 'id="risk-script"' in attrs)

    @classmethod
    def tearDownClass(cls):
        cls.log.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_page_has_tabs(self):
        self.assertEqual(self.status, 200)
        for panel in ("tab-security", "tab-risk"):
            self.assertEqual(self.ids[panel][1].get("role"), "tabpanel")
        tabs = [attrs for tag, attrs in self.elements if attrs.get("role") == "tab"]
        self.assertEqual([t["aria-controls"] for t in tabs], ["tab-security", "tab-risk"])
        self.assertIn("hidden", self.ids["tab-risk"][1])
        self.assertTrue(any(attrs.get("role") == "tablist" for _, attrs in self.elements))

    def test_legacy_tab_untouched(self):
        for element_id in LEGACY_IDS:
            with self.subTest(id=element_id):
                self.assertIn(element_id, self.ids)
        for snippet in LEGACY_SNIPPETS:
            with self.subTest(snippet=snippet):
                self.assertIn(snippet, self.html)
        # старые секции лежат внутри панели «Журнал», до панели «Риски»
        start, end = self.html.index('id="tab-security"'), self.html.index('id="tab-risk"')
        for element_id in ("tiles", "chartBox", "topIps", "blocks", "events"):
            self.assertTrue(start < self.html.index(f'id="{element_id}"') < end, element_id)

    def test_risk_blocks_present(self):
        for element_id in ("risk-mode", "risk-tiles", "risk-timeline-svg", "risk-scatter-svg",
                           "risk-sources", "risk-lowlist", "risk-dialog", "risk-alerts",
                           "risk-footer", "risk-tech", "risk-count", "risk-notice"):
            with self.subTest(id=element_id):
                self.assertIn(element_id, self.ids)

    def test_no_external_resources(self):
        external = re.findall(r"""(?:src|href)\s*=\s*["']?\s*(?:https?:)?//""", self.html, re.I)
        imports = re.findall(r"@import", self.html, re.I)
        self.assertEqual((external, imports), ([], []))
        urls = set(re.findall(r"https?://[^\s\"'<>)]+", self.html))
        self.assertLessEqual(urls, {"http://www.w3.org/2000/svg"})

    def test_risk_api_paths_exist(self):
        used = set(re.findall(r"/api/risk/[a-z]+", self.risk_js))
        routes = {path for method, path in self.api._routes if method == "GET"}
        self.assertTrue(used)
        self.assertLessEqual(used, routes)

    def test_risk_script_does_not_use_html_injection(self):
        for pattern in (r"\.innerHTML", r"\.outerHTML", r"insertAdjacentHTML", r"document\.write",
                        r"\beval\(", r"new Function"):
            with self.subTest(pattern=pattern):
                self.assertIsNone(re.search(pattern, self.risk_js))

    def test_new_css_classes_use_prefix(self):
        style = re.search(r"<style>(.*?)</style>", self.html, re.S).group(1)
        new_part = style[style.index("вкладка «Риски»"):]
        classes = set(re.findall(r"\.([a-zA-Z][\w-]*)", new_part))
        existing = {"tile", "tiles", "value", "badge", "card", "chips", "bar", "chart", "spacer", "mono"}
        self.assertEqual({c for c in classes if not c.startswith("risk-")} - existing, set())

    def test_no_new_colors_in_risk_part(self):
        style = re.search(r"<style>(.*?)</style>", self.html, re.S).group(1)
        new_part = style[style.index("вкладка «Риски»"):]
        self.assertEqual(re.findall(r"#[0-9a-fA-F]{3,8}\b|rgba?\(", new_part), [])
        self.assertIsNone(re.search(r"#[0-9a-fA-F]{3,8}\b|rgba?\(", self.risk_js))

    @unittest.skipUnless(shutil.which("node"), "node не установлен")
    def test_scripts_pass_node_check(self):
        for index, (_, body) in enumerate(self.scripts):
            with self.subTest(script=index), tempfile.NamedTemporaryFile(
                    "w", suffix=".js", delete=False, encoding="utf-8") as f:
                f.write(body)
                path = f.name
            try:
                result = subprocess.run(["node", "--check", path], capture_output=True, text=True,
                                        timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
            finally:
                os.unlink(path)


if __name__ == "__main__":
    unittest.main()
