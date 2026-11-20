"""Окно «Почему такой риск?»: хронология группами, факты базовой защиты, шрифты (unittest)."""
from __future__ import annotations

import json
import os
import re
import unittest

from app.risk import RiskEngine
from app.risk.engine import timeline_groups
from app.risk.schema import RiskEvent
from app.risk.simulate import FakeClock, Traffic, demo_story

HTML_PATH = os.path.join(os.path.dirname(__file__), "..", "app", "static", "dashboard.html")
FULL_NUMBER = re.compile(r"996\d{9}")
MAX_RISK_FONT_PX = 20  # предел font-size в CSS вкладки «Риски»


def ev(kind, ts, number=None, status=None):
    return (RiskEvent(ts=ts, kind=kind, raw_event=kind, ip="198.51.100.1", msisdn_id=number,
                      msisdn_tail=None, msisdn_masked=number, status=status, reason=None), False)


class TimelineGroupsTest(unittest.TestCase):
    def test_many_ip_limits_are_one_group(self):
        events = [ev("send_ok", 0, "+996700***001", 200)]
        events += [ev("ip_rate_limited", 1 + i * 0.01, None, 429) for i in range(1960)]
        result = timeline_groups(events)
        self.assertEqual([(g["event"], g["count"]) for g in result["timeline_groups"]],
                         [("send_ok", 1), ("ip_rate_limited", 1960)])
        self.assertEqual(result["timeline_skipped"], 0)

    def test_head_and_tail_when_more_than_eight(self):
        kinds = ["send_ok", "verify_fail"] * 7  # 14 групп, соседние различаются
        result = timeline_groups([ev(k, i, "+996700***001", 200) for i, k in enumerate(kinds)])
        groups = result["timeline_groups"]
        self.assertEqual(len(groups), 8)
        self.assertEqual(result["timeline_skipped"], 6)
        self.assertEqual([g["first_ts"] for g in groups], [0, 1, 2, 3, 10, 11, 12, 13])

    def test_fail_then_block_is_one_row(self):
        number = "+996700***051"
        events = [ev("send_ok", 0, number, 200)]
        events += [ev("verify_fail", 1 + i, number, 401) for i in range(5)]
        events += [ev("number_blocked", 5.2, number, 423)]
        events += [ev("verify_locked", 6 + i, number, 423) for i in range(3)]
        groups = timeline_groups(events)["timeline_groups"]
        self.assertEqual([(g["event"], g["count"]) for g in groups],
                         [("send_ok", 1), ("verify_fail", 4), ("verify_fail_blocked", 1),
                          ("verify_locked", 3)])

    def test_different_numbers_merge_with_range(self):
        events = [ev("send_ok", i, f"+996700***{i:03d}", 200) for i in range(60)]
        (group,) = timeline_groups(events)["timeline_groups"]
        self.assertEqual((group["count"], group["numbers"], group["msisdn"]), (60, 60, None))
        self.assertEqual((group["msisdn_first"], group["msisdn_last"]),
                         ("+996700***000", "+996700***059"))


class DemoDetailTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        clock = FakeClock()
        cls.engine = RiskEngine(clock=clock, id_key=b"k")
        cls.ips = demo_story(cls.engine.sink, clock)

    def detail(self, name):
        return self.engine.ip_detail(self.ips[name])

    def test_pumping_bot(self):
        d = self.detail("pumping_bot")
        self.assertEqual(d["timeline_groups"][0]["event"], "send_ok")
        self.assertEqual([(g["event"], g["count"]) for g in d["timeline_groups"]],
                         [("send_ok", 40)])
        facts = d["defense_facts"]
        self.assertEqual((facts["numbers_blocked"], facts["locked_attempts"], facts["ip_limited"],
                          facts["send_rejected"]), (0, 0, 0, 0))
        self.assertEqual(d["weights_sum"], 90)

    def test_code_bruteforce(self):
        d = self.detail("bruteforce")
        self.assertEqual(d["defense_facts"]["numbers_blocked"], 1)
        self.assertEqual(len(d["defense_facts"]["blocked_numbers"]), 1)
        self.assertEqual([g["event"] for g in d["timeline_groups"]],
                         ["send_ok", "verify_fail", "verify_fail_blocked", "verify_locked"])

    def test_distributed_limit_count_and_sum(self):
        d = self.detail("distributed")
        self.assertEqual(d["defense_facts"]["ip_limited"], 80)
        self.assertEqual(d["timeline_groups"][-1]["event"], "ip_rate_limited")
        self.assertEqual(d["weights_sum"], 130)
        self.assertEqual(d["score"], 100)

    def test_existing_fields_kept_and_no_full_numbers(self):
        for name in self.ips:
            with self.subTest(name=name):
                d = self.detail(name)
                for field in ("events", "stats", "reasons", "score", "level", "first_seen",
                              "last_seen"):
                    self.assertIn(field, d)
                self.assertIsNone(FULL_NUMBER.search(json.dumps(d, ensure_ascii=False)))

    def test_all_events_not_last_fifty(self):
        clock = FakeClock()
        engine = RiskEngine(clock=clock, id_key=b"k")
        Traffic(engine.sink, clock, seed=3).distributed("91.200.3.4", count=50, attempts=300)
        d = engine.ip_detail("91.200.3.4")
        self.assertEqual(sum(g["count"] for g in d["timeline_groups"]), 50 + 300)
        self.assertEqual(d["timeline_groups"][-1]["count"], 280)


class DialogDashboardTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(HTML_PATH, encoding="utf-8") as f:
            cls.html = f.read()
        cls.js = re.search(r'<script id="risk-script">(.*?)</script>', cls.html, re.S).group(1)
        style = re.search(r"<style>(.*?)</style>", cls.html, re.S).group(1)
        cls.risk_css = style[style.index("вкладка «Риски»"):]

    def test_dialog_and_handlers(self):
        self.assertIn('<dialog class="risk-dialog" id="risk-dialog"', self.html)
        self.assertIn('aria-label="Закрыть"', self.html)
        self.assertIn("showModal()", self.js)
        self.assertIn('addEventListener("close"', self.js)       # Esc закрывает <dialog>
        self.assertIn("e.target === dialog", self.js)             # клик по фону
        self.assertIn("target.focus()", self.js)                  # фокус возвращается
        self.assertNotIn('id="risk-detail"', self.html)           # старой встроенной карточки нет
        # replaceChildren превращает null в текст «null» — в окне все списки детей фильтруются
        self.assertIn('state.detailMissing ? el("span", { class: "risk-stale", '
                      'text: "данные устарели" }) : null].filter(Boolean)', self.js)

    def test_forbidden_wording(self):
        for bad in ("Трафик с IP заблокирован", "остановила атаку", "предотвратила",
                    "Сумма причин", "сейчас 0", "Статус защиты"):
            with self.subTest(bad=bad):
                self.assertNotIn(bad, self.html)
        self.assertNotIn(".innerHTML", self.js)
        for phrase in ("Что уже сделала защита сервиса", "Модуль рисков (режим наблюдения)",
                       "Базовая защита не сработала: лимит отправок считается по номеру",
                       "В боевом режиме: блокировка всех запросов с этого IP", "Хронология",
                       "Все счётчики", "данные устарели", "30 — средний", "60 — критический"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, self.js + self.html)

    def test_fonts(self):
        sizes = [int(x) for x in re.findall(r"font-size:\s*(\d+)px", self.risk_css)]
        self.assertLessEqual(max(sizes), MAX_RISK_FONT_PX)
        self.assertRegex(self.risk_css,
                         r"\.risk-dialog, \.risk-dialog button \{ font: inherit; \}")
        self.assertRegex(self.risk_css, r"#tab-risk button[^{]*\{ font-family: inherit; \}")
        self.assertRegex(self.risk_css, r"#tab-risk h2[^{]*\{ font-family: inherit; \}")
        self.assertNotRegex(self.risk_css, r"font-family:\s*var\(--font-serif\)")
        self.assertEqual(re.findall(r"#[0-9a-fA-F]{3,8}\b|rgba?\(", self.risk_css), [])


if __name__ == "__main__":
    unittest.main()
