"""Тесты модуля оценки рисков (unittest; работают и через pytest). Время — только FakeClock."""
from __future__ import annotations

import json
import re
import threading
import unittest
from datetime import datetime, timezone
from unittest import mock

from app.risk import RiskEngine, RiskSettings, normalize
from app.risk import engine as engine_module
from app.risk.schema import make_msisdn_id
from app.risk.simulate import FakeClock, Traffic, demo_story

KEY = b"test-risk-key"
FULL_NUMBER = re.compile(r"996\d{9}")
NIGHT_START = datetime.fromisoformat("2026-11-20T03:00:00+06:00").timestamp()


def record(event: str, **fields) -> dict:
    base = {"ts": "2026-11-20T06:00:00.123+00:00", "event": event, "ip": "10.0.0.1"}
    base.update(fields)
    return base


def reason_names(assessment) -> set[str]:
    return {reason.name for reason in assessment.reasons}


class NormalizeTest(unittest.TestCase):
    def test_current_names_map_to_target_kind_and_status(self):
        expected = {
            "otp_issued": ("send_ok", 200),
            "send_rate_limited": ("send_rejected", 429),
            "send_rejected_blocked": ("send_rejected", 423),
            "verify_success": ("verify_ok", 200),
            "verify_failed": ("verify_fail", 401),
            "verify_expired": ("verify_expired", 410),
            "msisdn_blocked": ("number_blocked", 423),
            "verify_rejected_blocked": ("verify_locked", 423),
            "verify_ip_rate_limited": ("ip_rate_limited", 429),
            "bad_request": ("bad_request", 400),
            "store_unavailable": ("store_unavailable", 503),
        }
        for raw, (kind, status) in expected.items():
            with self.subTest(raw=raw):
                ev = normalize(record(raw), id_key=KEY)
                self.assertEqual((ev.kind, ev.status, ev.raw_event), (kind, status, raw))

    def test_target_names_accepted_as_is(self):
        for kind in ("send_ok", "verify_fail", "verify_locked", "ip_rate_limited"):
            with self.subTest(kind=kind):
                self.assertEqual(normalize(record(kind), id_key=KEY).kind, kind)

    def test_status_from_record_wins(self):
        ev = normalize(record("send_rate_limited", status=423), id_key=KEY)
        self.assertEqual(ev.status, 423)

    def test_reasons(self):
        cooldown = normalize(record("send_rate_limited", reason="resend_delay"), id_key=KEY)
        limit = normalize(record("send_rate_limited", reason="send_limit"), id_key=KEY)
        blocked = normalize(record("send_rejected_blocked", retry_after=10), id_key=KEY)
        self.assertEqual(cooldown.reason, "cooldown")
        self.assertEqual(limit.reason, "limit")
        self.assertEqual((blocked.kind, blocked.reason, blocked.status),
                         ("send_rejected", "blocked", 423))

    def test_iso_time_in_utc(self):
        ev = normalize(record("otp_issued"), id_key=KEY)
        expected = datetime(2026, 11, 20, 6, 0, 0, 123000, tzinfo=timezone.utc).timestamp()
        self.assertAlmostEqual(ev.ts, expected, places=3)

    def test_time_priority_ts_argument_then_epoch_then_iso(self):
        rec = record("otp_issued", ts_epoch=1000.0)
        self.assertEqual(normalize(rec, id_key=KEY, ts=5.0).ts, 5.0)
        self.assertEqual(normalize(rec, id_key=KEY).ts, 1000.0)

    def test_unknown_event_and_missing_time_are_skipped(self):
        self.assertIsNone(normalize(record("cabinet_login"), id_key=KEY))
        self.assertIsNone(normalize({"event": "otp_issued", "ip": "1.1.1.1"}, id_key=KEY))
        self.assertIsNone(normalize({"event": "otp_issued", "ts": "вчера"}, id_key=KEY))

    def test_msisdn_id_tail_and_mask(self):
        first = normalize(record("otp_issued"), id_key=KEY, msisdn="996700123456")
        second = normalize(record("otp_issued"), id_key=KEY, msisdn="+996 700 123 456")
        other_key = normalize(record("otp_issued"), id_key=b"other", msisdn="996700123456")
        self.assertEqual(first.msisdn_id, second.msisdn_id)
        self.assertNotEqual(first.msisdn_id, other_key.msisdn_id)
        self.assertEqual(len(first.msisdn_id), 16)
        self.assertNotIn("996700123456", first.msisdn_id)
        self.assertNotIn("123456", first.msisdn_id)
        self.assertEqual(first.msisdn_masked, "+996700***456")
        self.assertEqual(first.msisdn_tail, "3456")
        self.assertEqual(first.msisdn_id, make_msisdn_id("996700123456", KEY))

    def test_without_raw_number_uses_colleague_mask(self):
        ev = normalize(record("verify_failed", msisdn="9967*****456"), id_key=KEY)
        self.assertEqual(ev.msisdn_id, "m:9967*****456")
        self.assertIsNone(ev.msisdn_tail)

    def test_event_does_not_keep_raw_number(self):
        ev = normalize(record("otp_issued"), id_key=KEY, msisdn="996700123456")
        self.assertIsNone(FULL_NUMBER.search(repr(ev)))


class SettingsTest(unittest.TestCase):
    def test_defaults(self):
        s = RiskSettings()
        self.assertEqual((s.window, s.medium_at, s.high_at, s.tz_offset_hours), (600, 30, 60, 6))

    def test_from_env(self):
        s = RiskSettings.from_env(environ={"RISK_WINDOW": "300", "RISK_SMS_PRICE": "2.5",
                                           "RISK_CURRENCY": "KGS", "OTHER": "1"})
        self.assertEqual((s.window, s.sms_price, s.currency), (300, 2.5, "KGS"))
        with self.assertRaises(ValueError):
            RiskSettings.from_env(environ={"RISK_WINDOW": "много"})


class RiskTestCase(unittest.TestCase):
    start = None

    def setUp(self):
        self.clock = FakeClock() if self.start is None else FakeClock(self.start)
        self.engine = RiskEngine(clock=self.clock, id_key=KEY)
        self.traffic = Traffic(self.engine.sink, self.clock, seed=1)


class SignalsTest(RiskTestCase):
    def test_normal_users_are_low_without_alerts(self):
        ips = [self.traffic.normal_user(typo=i % 3 == 0)[0] for i in range(10)]
        for ip in ips:
            a = self.engine.assess(ip)
            self.assertEqual((a.level, a.score), ("low", 0), a.reasons)
        self.assertEqual(self.engine.alerts(), [])

    def test_office_nat_has_fan_out_but_stays_low(self):
        self.traffic.office_nat("192.0.2.10", users=12)
        a = self.engine.assess("192.0.2.10")
        self.assertIn("fan_out", reason_names(a))
        self.assertEqual(a.level, "low")

    def test_single_user_at_night_only_night(self):
        clock = FakeClock(NIGHT_START)
        engine = RiskEngine(clock=clock, id_key=KEY)
        ip, _ = Traffic(engine.sink, clock, seed=2).normal_user()
        a = engine.assess(ip)
        self.assertEqual(reason_names(a), {"night"})
        self.assertEqual(a.level, "low")
        self.assertIn("по Бишкеку", a.reasons[0].detail)

    def test_pumping_bot_on_six_numbers_is_high(self):
        self.traffic.pumping_bot("45.13.7.200", count=6)
        a = self.engine.assess("45.13.7.200")
        self.assertEqual(a.level, "high")
        self.assertTrue({"fan_out", "sequential", "no_conversion"} <= reason_names(a))
        self.assertTrue(any("подряд" in alert["message"] for alert in self.engine.alerts()))

    def test_random_numbers_are_not_sequential(self):
        ip = "198.51.100.20"
        for _ in range(10):
            self.traffic.send_ok(self.traffic.new_number(), ip)
            self.clock.advance(5)
        self.assertNotIn("sequential", reason_names(self.engine.assess(ip)))

    def test_bruteforce_single_number_is_medium(self):
        self.traffic.bruteforce_single("203.0.113.5", attempts=20)
        a = self.engine.assess("203.0.113.5")
        self.assertEqual(a.level, "medium")
        self.assertTrue({"fail_rate", "hammering_locked"} <= reason_names(a))

    def test_distributed_attack_is_high_with_full_score(self):
        self.traffic.distributed("185.220.101.7", count=50)
        a = self.engine.assess("185.220.101.7")
        self.assertEqual((a.level, a.score), ("high", 100))
        self.assertIn("ip_limited", reason_names(a))

    def test_new_ip_for_previously_confirmed_number(self):
        _, msisdn = self.traffic.normal_user(ip="192.0.2.1")
        self.clock.advance(120)
        self.traffic.normal_user(ip="192.0.2.2", msisdn=msisdn)
        self.assertNotIn("new_ip", reason_names(self.engine.assess("192.0.2.1")))
        self.assertIn("new_ip", reason_names(self.engine.assess("192.0.2.2")))

    def test_score_decays_after_window(self):
        self.traffic.distributed("185.220.101.7", count=50)
        self.assertEqual(self.engine.assess("185.220.101.7").score, 100)
        self.clock.advance(601)
        a = self.engine.assess("185.220.101.7")
        self.assertEqual((a.score, a.level, a.reasons), (0, "low", ()))

    def test_bot_on_forty_numbers_raises_exactly_two_alerts(self):
        self.traffic.pumping_bot("45.13.7.200", count=40)
        alerts = self.engine.alerts()
        self.assertEqual([a["severity"] for a in alerts], ["high", "medium"])
        self.assertTrue(all(a["ip"] == "45.13.7.200" for a in alerts))
        self.assertIn("В боевом режиме", alerts[0]["message"])


class EngineTest(RiskTestCase):
    def test_sink_never_raises(self):
        garbage = [None, 42, "строка", [], {}, {"event": 5}, {"event": "otp_issued"},
                   {"event": "otp_issued", "ts": float("nan")},
                   {"event": "otp_issued", "ts": "2026-11-20T06:00:00+00:00", "ip": ["x"]},
                   {"event": "otp_issued", "ts": "2026-11-20T06:00:00+00:00", "msisdn": 1}]
        for item in garbage:
            self.engine.sink(item)
            self.engine.sink(item, msisdn=12345, ts="мусор")
        self.engine.sink(record("otp_issued"), msisdn=object())
        with mock.patch.object(engine_module, "normalize", side_effect=RuntimeError("сбой")):
            self.engine.sink(record("otp_issued"))
        self.assertEqual(self.engine.errors, 1)

    def test_no_full_numbers_in_responses(self):
        ips = demo_story(self.engine.sink, self.clock)
        responses = [self.engine.overview(), self.engine.timeline(), self.engine.top_ips(100),
                     self.engine.scatter(), self.engine.alerts(500), self.engine.meta()]
        responses += [self.engine.ip_detail(ip, events_limit=500) for ip in ips.values()]
        for response in responses:
            text = json.dumps(response, ensure_ascii=False)
            self.assertIsNone(FULL_NUMBER.search(text), text[:200])

    def test_timeline_and_overview_are_consistent(self):
        demo_story(self.engine.sink, self.clock)
        overview = self.engine.overview()
        timeline = self.engine.timeline()
        self.assertEqual(len(timeline), 60)
        self.assertEqual(sum(row["send_ok"] for row in timeline), overview["sms_sent"])
        levels = sum(row["low"] + row["medium"] + row["high"] for row in timeline)
        self.assertEqual(levels, self.engine.ingested)
        self.assertTrue(0 < overview["sms_suspicious"] < overview["sms_sent"])
        self.assertEqual(overview["threat_level"], "high")
        self.assertEqual(overview["ips_high"], 2)

    def test_demo_story_levels(self):
        ips = demo_story(self.engine.sink, self.clock)
        level = {name: self.engine.ip_detail(ip)["level"] for name, ip in ips.items()}
        self.assertEqual(level["pumping_bot"], "high")
        self.assertEqual(level["distributed"], "high")
        self.assertEqual(level["bruteforce"], "medium")
        self.assertEqual(level["office"], "low")
        self.assertEqual(level["user"], "low")
        top = [row["ip"] for row in self.engine.top_ips(limit=2)]
        self.assertEqual(set(top), {ips["pumping_bot"], ips["distributed"]})

    def test_scatter_and_unknown_ip(self):
        self.traffic.pumping_bot("45.13.7.200", start=1200, count=10)
        tails = sorted(p["tail"] for p in self.engine.scatter() if p["ip"] == "45.13.7.200")
        self.assertEqual(tails, list(range(1200, 1210)))
        self.assertIsNone(self.engine.ip_detail("203.0.113.99"))

    def test_ip_detail_events_are_masked_newest_first(self):
        self.traffic.pumping_bot("45.13.7.200", start=1200, count=3)
        detail = self.engine.ip_detail("45.13.7.200")
        self.assertEqual(detail["events"][0]["msisdn"], "+996700***202")
        self.assertEqual(detail["stats"]["sms_sent"], 3)
        times = [event["ts"] for event in detail["events"]]
        self.assertEqual(times, sorted(times, reverse=True))

    def test_alerts_since_id(self):
        self.traffic.pumping_bot("45.13.7.200", count=40)
        first, second = sorted(a["id"] for a in self.engine.alerts())
        self.assertEqual([a["id"] for a in self.engine.alerts(since_id=first)], [second])

    def test_parallel_sinks(self):
        def worker(n: int) -> None:
            for i in range(500):
                self.engine.sink(record("otp_issued", ip=f"10.0.{n}.{i % 50}"),
                                 msisdn=f"996700{n:02d}{i:04d}", ts=self.clock() + i * 0.01)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual((self.engine.ingested, self.engine.errors), (4000, 0))


if __name__ == "__main__":
    unittest.main()
