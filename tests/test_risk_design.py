"""Тексты модуля рисков: язык для жюри, тип атаки, честные формулировки (unittest)."""
from __future__ import annotations

import os
import re
import unittest

from app.risk import RiskEngine
from app.risk.signals import INCIDENT_TYPES, SIGNAL_TITLES, classify
from app.risk.simulate import FakeClock, demo_story

HTML_PATH = os.path.join(os.path.dirname(__file__), "..", "app", "static", "dashboard.html")
AFFIRMATIVE = re.compile(
    r"\bзаблокирован\b|\bзаблокированы\b|\bотклон[её]н\b|отклоняются|сохранено", re.IGNORECASE)


class IncidentTypeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clock = FakeClock()
        cls.engine = RiskEngine(clock=cls.clock, id_key=b"k")
        cls.ips = demo_story(cls.engine.sink, cls.clock)
        cls.expected = {"pumping_bot": "sms_pumping", "bruteforce": "code_bruteforce",
                        "distributed": "distributed_bruteforce", "user": "none", "office": "none"}

    def test_same_type_in_ips_ip_and_summary(self):
        rows = {r["ip"]: r for r in self.engine.top_ips(limit=200)}
        incidents = {i["ip"]: i for i in self.engine.summary(window=3600)["incidents"]}
        for name, code in self.expected.items():
            with self.subTest(name=name):
                ip = self.ips[name]
                self.assertEqual(rows[ip]["incident_type"], code)
                self.assertEqual(self.engine.ip_detail(ip)["incident_type"], code)
                self.assertEqual(rows[ip]["incident_title"], INCIDENT_TYPES[code][0])
                if code != "none":
                    self.assertEqual(incidents[ip]["incident_type"], code)

    def test_alerts_carry_type_at_alert_moment(self):
        alerts = self.engine.alerts(limit=100)
        by_ip = {}
        for alert in alerts:  # новые сверху: первая встреченная — последняя по времени
            by_ip.setdefault(alert["ip"], alert)
        self.assertEqual(by_ip[self.ips["pumping_bot"]]["incident_type"], "sms_pumping")
        self.assertEqual(by_ip[self.ips["bruteforce"]]["incident_type"], "code_bruteforce")
        self.assertTrue(all(a["incident_title"] for a in alerts))
        # ранняя тревога «Средний» бота (5 номеров подряд, коды не вводятся) — уже SMS-флуд
        pumping = [a for a in alerts if a["ip"] == self.ips["pumping_bot"]]
        self.assertEqual({a["incident_type"] for a in pumping}, {"sms_pumping"})

    def test_existing_fields_unchanged_and_new_added(self):
        row = self.engine.top_ips(limit=1)[0]
        for field in ("ip", "score", "level", "would_action", "would_action_text", "reasons",
                      "numbers", "sms_sent", "verify_attempts", "last_seen", "current_score",
                      "sparkline"):
            self.assertIn(field, row)
        for field in ("incident_type", "incident_title", "incident_subtitle", "level_title",
                      "would_action_title", "detected", "savings"):
            self.assertIn(field, row)
        self.assertEqual(row["level"], "high")
        self.assertEqual(row["level_title"], "Критический")

    def test_savings_only_for_pumping(self):
        bot = self.engine.ip_detail(self.ips["pumping_bot"])
        self.assertEqual(bot["savings"], {"sms": 34, "cost": 34.0, "currency": "сом"})
        self.assertIsNone(self.engine.ip_detail(self.ips["bruteforce"])["savings"])
        brute = self.engine.ip_detail(self.ips["bruteforce"])
        self.assertIsNone(brute["first_high"])
        self.assertEqual(brute["detected"]["level"], "medium")

    def test_classify_rules(self):
        self.assertEqual(classify(["fan_out"], "low"), "none")
        self.assertEqual(classify(["sequential", "no_conversion"], "medium"), "sms_pumping")
        reasons = ["fan_out", "sequential", "no_conversion", "ip_limited"]
        self.assertEqual(classify(reasons, "high"), "distributed_bruteforce")
        self.assertEqual(classify(["fail_rate", "hammering_locked"], "medium"), "code_bruteforce")
        self.assertEqual(classify(["new_ip", "night"], "medium"), "suspicious")


class WordingTest(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.engine = RiskEngine(clock=self.clock, id_key=b"k")
        self.ips = demo_story(self.engine.sink, self.clock)

    def test_reason_titles_from_source(self):
        detail = self.engine.ip_detail(self.ips["pumping_bot"])
        self.assertEqual([r["title"] for r in detail["reasons"]],
                         ["Массовая рассылка", "Перебор номеров по порядку", "Коды не вводятся"])
        self.assertEqual(detail["reasons"][0]["detail"],
                         "коды на 40 номеров с одного IP за 10 мин")
        meta_titles = {s["name"]: s["title"] for s in self.engine.meta()["signals"]}
        self.assertEqual(meta_titles, SIGNAL_TITLES)

    def test_detail_phrases(self):
        brute_reasons = self.engine.ip_detail(self.ips["bruteforce"])["reasons"]
        brute = {r["name"]: r["detail"] for r in brute_reasons}
        self.assertEqual(brute["fail_rate"], "20 неудачных проверок кода (100% попыток)")
        self.assertEqual(brute["hammering_locked"], "15 попыток после блокировки")
        dist_reasons = self.engine.ip_detail(self.ips["distributed"])["reasons"]
        dist = {r["name"]: r["detail"] for r in dist_reasons}
        self.assertEqual(dist["ip_limited"], "лимит 20 проверок/мин сработал 80 раз")
        self.assertEqual(dist["sequential"], "100% номеров идут подряд")

    def test_template_summary_is_conditional(self):
        text = self.engine.summary(window=3600)["text"]
        self.assertIsNone(AFFIRMATIVE.search(text), text)
        self.assertIn("в боевом режиме: блокировка", text)
        self.assertIn("можно было сэкономить", text)
        self.assertIn("риск 90 / 100", text)
        self.assertNotIn("(429)", text)


class DashboardWordingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(HTML_PATH, encoding="utf-8") as f:
            cls.html = f.read()
        script = re.search(r'<script id="risk-script">(.*?)</script>', cls.html, re.S)
        cls.risk_js = script.group(1)
        start = cls.html.index('<div id="tab-risk"')
        cls.risk_markup = cls.html[start:cls.html.index("<script", start)]

    def test_no_forbidden_strings(self):
        for bad in ("Заблокирован", "отклоняются", "Сохранено", "98%", "#94a3b8", "rgba(239"):
            with self.subTest(bad=bad):
                self.assertNotIn(bad, self.html)
        for jargon in ("Веер", "Атака на блок", "Лимит IP", "Без подтверждений", "Топ IP",
                       "Лента тревог", "В бою:", "(429)", "×2"):
            with self.subTest(jargon=jargon):
                self.assertNotIn(jargon, self.risk_js + self.risk_markup)
        self.assertNotIn(".innerHTML", self.risk_js)

    def test_risk_wording_present(self):
        for phrase in ("Источники атак", "Журнал срабатываний защиты", "Потрачено на ботов",
                       "Почему такой риск", "Критический", "/ 100", "Режим наблюдения.",
                       "Как бот перебирает номера", "Кто на какие номера запрашивал коды"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, self.risk_js + self.risk_markup)
        self.assertNotIn("Клик или Enter", self.risk_markup + self.risk_js)

    def test_technical_details_collapsed(self):
        match = re.search(r'<details class="risk-tech" id="risk-tech"([^>]*)>', self.html)
        self.assertIsNotNone(match)
        self.assertNotIn("open", match.group(1))
        self.assertIn('id="risk-footer"', self.html[match.start():])

    def test_legacy_journal_untouched(self):
        start = self.html.index("<script>")
        journal = self.html[start:self.html.index('<script id="risk-script">')]
        for snippet in ("async function load()", "function renderTiles()",
                        "function renderTopIps()", "function renderBlocks()",
                        "function renderEvents()", "/api/security/events?limit=300"):
            self.assertIn(snippet, journal)
        for element_id in ("meta", "live", "tiles", "tableToggle", "legend", "chartBox", "chart",
                           "tooltip", "chartTable", "topIps", "blocks", "filters", "events"):
            self.assertIn(f'id="{element_id}"', self.html)

    def test_colors_only_tokens_in_risk_css(self):
        style = re.search(r"<style>(.*?)</style>", self.html, re.S).group(1)
        risk_css = style[style.index("вкладка «Риски»"):]
        self.assertEqual(re.findall(r"#[0-9a-fA-F]{3,8}\b|rgba?\(", risk_css), [])


if __name__ == "__main__":
    unittest.main()
