"""RiskEngine: принимает события журнала, считает риск по IP и отвечает на запросы дашборда.

Модуль только наблюдает: ничего не блокирует и не пишет в хранилище сервиса.
Всё состояние — в памяти процесса под одним threading.Lock (сервер многопоточный).
"""
from __future__ import annotations

import math
import os
import queue
import secrets
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .config import RiskSettings
from .schema import RiskEvent, normalize
from .signals import (
    ACTIONS, LEVEL_RANK, LEVELS, SIGNAL_INFO, Signal, WindowStats, evaluate, level_of, score_of,
)

SEND_KINDS = frozenset({"send_ok", "send_rejected"})
# События, к которым относится признак «новый IP для номера»
NEW_IP_KINDS = frozenset({"send_ok", "send_rejected", "verify_ok", "verify_fail",
                          "verify_expired", "verify_locked"})
TIMELINE_KINDS = ("send_ok", "send_rejected", "verify_ok", "verify_fail", "verify_locked",
                  "ip_rate_limited")
# Сколько хранить неактивный IP: дольше окна признаков, чтобы топ IP и разбор жили час
IP_RETENTION = 3600
SPARKLINE_MINUTES = 10
_STOP = object()  # сигнал остановки обработчика очереди


@dataclass(frozen=True)
class Assessment:
    ip: str
    ts: float
    score: int
    level: str
    reasons: tuple[Signal, ...]
    stats: WindowStats = field(repr=False, compare=False, default_factory=WindowStats)

    @property
    def would_action(self) -> str:
        return ACTIONS[self.level][0]

    @property
    def would_action_text(self) -> str:
        return ACTIONS[self.level][1]

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "ts": _round_ts(self.ts),
            "score": self.score,
            "level": self.level,
            "would_action": self.would_action,
            "would_action_text": self.would_action_text,
            "reasons": [reason.to_dict() for reason in self.reasons],
        }


@dataclass
class _IpState:
    events: deque  # (RiskEvent, new_ip: bool)
    first_seen: float
    last_seen: float
    last: Assessment
    level_seen: dict[str, float] = field(default_factory=dict)  # уровень -> когда был последний раз


def _round_ts(ts: float) -> float:
    return round(ts, 3)


def _default_id_key() -> bytes:
    secret = os.getenv("RISK_ID_SECRET")
    return secret.encode() if secret else secrets.token_bytes(32)


class RiskEngine:
    def __init__(self, settings: Optional[RiskSettings] = None, *,
                 clock: Callable[[], float] = time.time, id_key: Optional[bytes] = None):
        self.settings = settings or RiskSettings()
        self.clock = clock
        self._id_key = id_key if id_key is not None else _default_id_key()
        self._lock = threading.Lock()
        self._ips: dict[str, _IpState] = {}
        self._known: dict[str, dict[str, float]] = {}  # msisdn_id -> {ip: ts последнего verify_ok}
        self._minutes: dict[int, Counter] = {}  # начало минуты -> счётчики
        self._points: deque = deque(maxlen=self.settings.max_points)
        self._alerts: deque = deque(maxlen=self.settings.max_alerts)
        self._alert_seq = 0
        self.ingested = 0
        self.ignored = 0
        self.errors = 0
        # Асинхронная доставка: очередь и поток-обработчик (start_worker)
        self._queue: Optional[queue.Queue] = None
        self._worker: Optional[threading.Thread] = None
        self._dropped_lock = threading.Lock()  # только для счётчика, держится на одно сложение
        self.dropped = 0

    # ---------- приём событий ----------

    def sink(self, record: Any, msisdn: Optional[str] = None, ts: Optional[float] = None) -> None:
        """Точка входа из журнала безопасности. Никогда не бросает исключений."""
        try:
            event = normalize(record, id_key=self._id_key, msisdn=msisdn, ts=ts)
            if event is None:
                with self._lock:
                    self.ignored += 1
                return
            self.ingest(event)
        except Exception:  # noqa: BLE001 — ошибка модуля рисков не должна ронять OTP
            with self._lock:
                self.errors += 1

    # ---------- асинхронная доставка ----------

    def start_worker(self, maxsize: int = 10000) -> Callable[..., None]:
        """Запустить поток-обработчик; вернуть асинхронный синк (record, msisdn=None, ts=None).

        Асинхронный синк только кладёт событие в очередь без ожидания: если очередь полна,
        событие отбрасывается и растёт self.dropped. Так модуль рисков не задерживает запрос.
        """
        if self._worker is not None and self._worker.is_alive():
            return self.async_sink
        self._queue = queue.Queue(maxsize=maxsize)
        self._worker = threading.Thread(target=self._run_worker, args=(self._queue,),
                                        name="risk-worker", daemon=True)
        self._worker.start()
        return self.async_sink

    def async_sink(self, record: Any, msisdn: Optional[str] = None,
                   ts: Optional[float] = None) -> None:
        try:
            pending = self._queue
            if pending is None:
                raise queue.Full
            pending.put_nowait((dict(record), msisdn, ts))
        except Exception:  # noqa: BLE001 — полная очередь, мусор вместо записи и т.п.
            with self._dropped_lock:
                self.dropped += 1

    def _run_worker(self, pending: queue.Queue) -> None:
        while True:
            item = pending.get()
            try:
                if item is _STOP:
                    return
                record, msisdn, ts = item
                self.sink(record, msisdn=msisdn, ts=ts)
            finally:
                pending.task_done()

    def drain(self, timeout: float = 2.0) -> bool:
        """Дождаться, пока очередь опустеет. True — все события обработаны."""
        pending = self._queue
        if pending is None:
            return True
        deadline = time.monotonic() + timeout
        with pending.all_tasks_done:
            while pending.unfinished_tasks:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                pending.all_tasks_done.wait(remaining)
        return True

    def stop_worker(self, timeout: float = 2.0) -> None:
        """Остановить обработчик: уже поставленные события обрабатываются, затем поток выходит."""
        worker, pending = self._worker, self._queue
        if worker is None or pending is None:
            return
        try:
            pending.put(_STOP, timeout=timeout)
        except queue.Full:
            pass
        worker.join(timeout)
        self._worker = None

    @property
    def mode(self) -> str:
        worker = self._worker
        return "async" if worker is not None and worker.is_alive() else "sync"

    # ---------- обработка ----------

    def ingest(self, ev: RiskEvent) -> Assessment:
        s = self.settings
        with self._lock:
            state = self._ips.get(ev.ip)
            if state is None:
                empty = Assessment(ev.ip, ev.ts, 0, "low", ())
                state = _IpState(deque(), ev.ts, ev.ts, empty)
                self._ips[ev.ip] = state

            flag = self._is_new_ip(ev)
            state.events.append((ev, flag))
            if ev.kind == "verify_ok" and ev.msisdn_id is not None:
                self._known.setdefault(ev.msisdn_id, {})[ev.ip] = ev.ts

            now = max(state.last_seen, ev.ts)
            self._trim(state, now)
            state.last_seen = now
            state.first_seen = min(state.first_seen, ev.ts)

            assessment = self._assess_events(ev.ip, state.events, now)
            previous = state.last.level
            state.last = assessment
            state.level_seen[assessment.level] = now
            if LEVEL_RANK[assessment.level] > LEVEL_RANK[previous]:
                self._raise_alert(assessment)

            minute = self._minutes.setdefault(int(ev.ts // 60) * 60, Counter())
            minute[ev.kind] += 1
            minute["lvl:" + assessment.level] += 1
            if ev.kind == "send_ok" and assessment.level == "high":
                minute["sms_suspicious"] += 1

            if ev.kind in SEND_KINDS and ev.msisdn_tail is not None and ev.msisdn_tail.isdigit():
                self._points.append((ev.ts, int(ev.msisdn_tail), ev.ip, assessment.level, ev.kind))

            self.ingested += 1
            if self.ingested % s.cleanup_every == 0:
                self._cleanup(max(now, self.clock()))
            return assessment

    def _is_new_ip(self, ev: RiskEvent) -> bool:
        """Номер раньше подтверждался с других IP, а с этого — нет. Считается ДО учёта verify_ok."""
        if ev.kind not in NEW_IP_KINDS or ev.msisdn_id is None:
            return False
        known = self._known.get(ev.msisdn_id)
        if not known:
            return False
        horizon = ev.ts - self.settings.known_ip_ttl
        fresh = {ip for ip, seen in known.items() if seen >= horizon}
        return bool(fresh) and ev.ip not in fresh

    def _trim(self, state: _IpState, now: float) -> None:
        horizon = now - self.settings.window
        events = state.events
        while events and events[0][0].ts < horizon:
            events.popleft()
        while len(events) > self.settings.max_events_per_ip:
            events.popleft()

    def _assess_events(self, ip: str, events, now: float) -> Assessment:
        s = self.settings
        stats = WindowStats(window=s.window)
        horizon = now - s.window
        for ev, flag in events:
            if horizon <= ev.ts <= now:
                stats.add(ev.kind, ev.ts, ev.msisdn_id, ev.msisdn_tail, flag)
        reasons = tuple(evaluate(stats, s)) if stats.events else ()
        score = score_of(list(reasons), s)
        return Assessment(ip, now, score, level_of(score, s), reasons, stats)

    def _raise_alert(self, a: Assessment) -> None:
        self._alert_seq += 1
        details = "; ".join(reason.detail for reason in a.reasons) or "балл вырос"
        self._alerts.append({
            "id": self._alert_seq,
            "ts": _round_ts(a.ts),
            "ip": a.ip,
            "severity": a.level,
            "score": a.score,
            "reasons": [reason.to_dict() for reason in a.reasons],
            "would_action": a.would_action,
            "message": f"IP {a.ip}: {details}. В боевом режиме: {a.would_action_text}.",
        })

    def _cleanup(self, now: float) -> None:
        """Вызывается под self._lock: старые IP, знакомые IP, счётчики."""
        s = self.settings
        stale = now - max(s.window, IP_RETENTION)
        for ip in [ip for ip, st in self._ips.items() if st.last_seen < stale]:
            del self._ips[ip]
        known_horizon = now - s.known_ip_ttl
        for msisdn_id in list(self._known):
            ips = {ip: t for ip, t in self._known[msisdn_id].items() if t >= known_horizon}
            if ips:
                self._known[msisdn_id] = ips
            else:
                del self._known[msisdn_id]
        minute_horizon = now - s.history_hours * 3600
        for minute in [m for m in self._minutes if m < minute_horizon]:
            del self._minutes[minute]

    def cleanup(self) -> None:
        with self._lock:
            self._cleanup(self.clock())

    # ---------- запросы ----------

    def assess(self, ip: str) -> Assessment:
        """Текущая оценка IP по событиям за последнее окно (now = clock())."""
        now = self.clock()
        with self._lock:
            state = self._ips.get(ip)
            if state is None:
                return Assessment(ip, now, 0, "low", ())
            return self._assess_events(ip, state.events, now)

    def overview(self, window: int = 3600) -> dict:
        now = self.clock()
        horizon = now - window
        s = self.settings
        with self._lock:
            totals: Counter = Counter()
            # Те же минуты, что попадают в timeline(window, step=60)
            for minute, counter in self._minutes.items():
                if horizon < minute <= now:
                    totals.update(counter)
            active = [st for st in self._ips.values() if st.last_seen >= horizon]
            high = sum(1 for st in active if st.level_seen.get("high", -math.inf) >= horizon)
            medium = sum(1 for st in active
                         if st.level_seen.get("high", -math.inf) < horizon
                         and st.level_seen.get("medium", -math.inf) >= horizon)
            alerts = sum(1 for alert in self._alerts if alert["ts"] >= horizon)
        sent = totals["send_ok"]
        suspicious = totals["sms_suspicious"]
        return {
            "now": _round_ts(now),
            "window": window,
            "threat_level": "high" if high else "medium" if medium else "low",
            "ips_active": len(active),
            "ips_medium": medium,
            "ips_high": high,
            "alerts": alerts,
            "sms_sent": sent,
            "sms_suspicious": suspicious,
            "sms_cost_suspicious": round(suspicious * s.sms_price, 2),
            "currency": s.currency,
            "conversion": round(totals["verify_ok"] / sent, 3) if sent else None,
        }

    def timeline(self, window: int = 3600, step: int = 60) -> list[dict]:
        """Счётчики по шагам времени (шаг кратен минуте), включая пустые шаги."""
        step = max(60, int(step) // 60 * 60)
        now = self.clock()
        last = int(now // step) * step
        count = max(1, math.ceil(window / step))
        starts = [last - step * k for k in range(count - 1, -1, -1)]
        buckets = {t: Counter() for t in starts}
        first = starts[0]
        with self._lock:
            for minute, counter in self._minutes.items():
                bucket = minute // step * step
                if first <= bucket <= last:
                    buckets[bucket].update(counter)
        rows = []
        for t in starts:
            c = buckets[t]
            row = {"t": t}
            row.update({level: c["lvl:" + level] for level in LEVELS})
            row.update({kind: c[kind] for kind in TIMELINE_KINDS})
            rows.append(row)
        return rows

    def top_ips(self, limit: int = 20, min_level: str = "low") -> list[dict]:
        """IP, активные за последний час, с оценкой на момент их последней активности."""
        now = self.clock()
        horizon = now - IP_RETENTION
        threshold = LEVEL_RANK.get(min_level, 0)
        with self._lock:
            rows = [self._ip_row(st, now) for st in self._ips.values()
                    if st.last_seen >= horizon and LEVEL_RANK[st.last.level] >= threshold]
        rows.sort(key=lambda row: (row["score"], row["last_seen"]), reverse=True)
        return rows[:max(0, limit)]

    def _ip_row(self, state: _IpState, now: float) -> dict:
        a = state.last
        row = a.to_dict()
        del row["ts"]
        row.update({
            "numbers": len(a.stats.numbers),
            "sms_sent": a.stats.sends_ok,
            "verify_attempts": a.stats.verify_attempts,
            "last_seen": _round_ts(state.last_seen),
            "current_score": self._assess_events(state.last.ip, state.events, now).score,
            "sparkline": self._sparkline(state, now),
        })
        return row

    @staticmethod
    def _sparkline(state: _IpState, now: float) -> list[int]:
        current = int(now // 60)
        counts = [0] * SPARKLINE_MINUTES
        for ev, _ in state.events:
            age = current - int(ev.ts // 60)
            if 0 <= age < SPARKLINE_MINUTES:
                counts[SPARKLINE_MINUTES - 1 - age] += 1
        return counts

    def ip_detail(self, ip: str, events_limit: int = 50) -> Optional[dict]:
        now = self.clock()
        s = self.settings
        with self._lock:
            state = self._ips.get(ip)
            if state is None:
                return None
            a = state.last
            st = a.stats
            events = list(state.events)[-max(0, events_limit):] if events_limit > 0 else []
            detail = a.to_dict()
            detail.update({
                "current_score": self._assess_events(ip, state.events, now).score,
                "first_seen": _round_ts(state.first_seen),
                "last_seen": _round_ts(state.last_seen),
                "stats": {
                    "numbers": len(st.numbers),
                    "sms_sent": st.sends_ok,
                    "sms_rejected": st.sends_rejected,
                    "verify_ok": st.verify_ok,
                    "verify_fail": st.verify_fail,
                    "verify_expired": st.verify_expired,
                    "verify_locked": st.verify_locked,
                    "ip_limited": st.ip_limited,
                },
                "sms_cost": round(st.sends_ok * s.sms_price, 2),
                "currency": s.currency,
                "sparkline": self._sparkline(state, now),
                "events": [
                    {"ts": _round_ts(ev.ts), "event": ev.kind, "msisdn": ev.msisdn_masked,
                     "status": ev.status, "reason": ev.reason, "scope": ev.scope,
                     "new_ip": flag}
                    for ev, flag in reversed(events)
                ],
            })
            return detail

    def scatter(self, window: int = 1800) -> list[dict]:
        horizon = self.clock() - window
        with self._lock:
            points = [p for p in self._points if p[0] >= horizon]
        return [{"t": _round_ts(t), "tail": tail, "ip": ip, "level": level, "event": kind}
                for t, tail, ip, level, kind in points]

    def alerts(self, limit: int = 50, since_id: int = 0) -> list[dict]:
        with self._lock:
            fresh = [dict(alert) for alert in self._alerts if alert["id"] > since_id]
        fresh.reverse()
        return fresh[:max(0, limit)]

    def meta(self) -> dict:
        s = self.settings
        points = {
            "fan_out": [s.fan_out_low_points, s.fan_out_high_points],
            "sequential": [s.sequential_points],
            "no_conversion": [s.no_conversion_points],
            "fail_rate": [s.fail_rate_points],
            "new_ip": [s.new_ip_points],
            "hammering_locked": [s.hammering_points],
            "ip_limited": [s.ip_limited_points],
            "night": [s.night_points],
        }
        with self._lock:
            counters = {
                "ingested": self.ingested,
                "ignored": self.ignored,
                "errors": self.errors,
                "ips_tracked": len(self._ips),
                "alerts_total": self._alert_seq,
            }
        with self._dropped_lock:
            counters["dropped"] = self.dropped
        pending = self._queue
        return {
            "now": _round_ts(self.clock()),
            "mode": self.mode,
            "observe_only": True,
            "queue_size": pending.qsize() if pending is not None else 0,
            "window": s.window,
            "tz_offset_hours": s.tz_offset_hours,
            "levels": {"medium_at": s.medium_at, "high_at": s.high_at, "max_score": s.max_score},
            "actions": {level: {"action": a, "text": t} for level, (a, t) in ACTIONS.items()},
            "signals": [{"name": name, "points": points[name], "description": text}
                        for name, text in SIGNAL_INFO],
            "sms_price": s.sms_price,
            "currency": s.currency,
            **counters,
        }
