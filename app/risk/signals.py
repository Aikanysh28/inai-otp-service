"""Признаки риска: чистые функции (WindowStats, RiskSettings) -> Signal | None.

Каждый признак объясняет себя одной строкой на русском с конкретными цифрами,
чтобы любое решение можно было понять без чтения кода.
"""
from __future__ import annotations

from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from .config import RiskSettings

LEVELS = ("low", "medium", "high")
LEVEL_RANK = {level: rank for rank, level in enumerate(LEVELS)}

# Рекомендуемое действие — только подпись, модуль ничего не применяет.
ACTIONS = {
    "low": ("allow", "обычный режим"),
    "medium": ("stricter_delay", "задержки строже (×2)"),
    "high": ("deny", "отказ (429) и тревога"),
}


@dataclass(frozen=True, slots=True)
class Signal:
    name: str
    points: int
    detail: str

    def to_dict(self) -> dict:
        return {"name": self.name, "points": self.points, "detail": self.detail}


@dataclass(slots=True)
class WindowStats:
    """Сводка событий одного IP за окно."""

    window: int = 600
    send_numbers: dict[str, Optional[str]] = field(default_factory=dict)  # msisdn_id -> tail
    numbers: set[str] = field(default_factory=set)
    sends_ok: int = 0
    sends_rejected: int = 0
    verify_ok: int = 0
    verify_fail: int = 0
    verify_expired: int = 0
    verify_locked: int = 0
    ip_limited: int = 0
    bad_requests: int = 0
    new_ip_numbers: set[str] = field(default_factory=set)
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    events: int = 0

    @property
    def verify_attempts(self) -> int:
        return self.verify_ok + self.verify_fail + self.verify_expired + self.verify_locked

    def add(self, kind: str, ts: float, msisdn_id: Optional[str], tail: Optional[str],
            new_ip: bool = False) -> None:
        self.events += 1
        self.first_ts = ts if self.first_ts is None else min(self.first_ts, ts)
        self.last_ts = ts if self.last_ts is None else max(self.last_ts, ts)
        if msisdn_id is not None:
            self.numbers.add(msisdn_id)
            if new_ip:
                self.new_ip_numbers.add(msisdn_id)
        if kind in ("send_ok", "send_rejected") and msisdn_id is not None:
            if tail is not None or msisdn_id not in self.send_numbers:
                self.send_numbers[msisdn_id] = tail
        if kind == "send_ok":
            self.sends_ok += 1
        elif kind == "send_rejected":
            self.sends_rejected += 1
        elif kind == "verify_ok":
            self.verify_ok += 1
        elif kind == "verify_fail":
            self.verify_fail += 1
        elif kind == "verify_expired":
            self.verify_expired += 1
        elif kind == "verify_locked":
            self.verify_locked += 1
        elif kind == "ip_rate_limited":
            self.ip_limited += 1
        elif kind == "bad_request":
            self.bad_requests += 1
        # number_blocked и store_unavailable в счётчики попыток не входят


def plural(n: int, one: str, few: str, many: str) -> str:
    """Русское склонение: 1 номер, 2 номера, 5 номеров."""
    if n % 10 == 1 and n % 100 != 11:
        return one
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return few
    return many


def _minutes(seconds: int) -> str:
    return f"{seconds // 60} мин" if seconds % 60 == 0 else f"{seconds} с"


def fan_out(stats: WindowStats, s: RiskSettings) -> Optional[Signal]:
    count = len(stats.send_numbers)
    if count > s.fan_out_high:
        points = s.fan_out_high_points
    elif count > s.fan_out_low:
        points = s.fan_out_low_points
    else:
        return None
    return Signal("fan_out", points,
                  f"коды запрошены на {count} {plural(count, 'номер', 'номера', 'номеров')} "
                  f"за {_minutes(stats.window)}")


def sequential(stats: WindowStats, s: RiskSettings) -> Optional[Signal]:
    tails = [int(t) for t in stats.send_numbers.values() if t is not None and t.isdigit()]
    if len(tails) < s.sequential_min_numbers:
        return None
    unique = sorted(set(tails))
    with_neighbour = 0
    for tail in tails:
        if any(other != tail and abs(other - tail) <= s.sequential_max_gap
               for other in _near(unique, tail, s.sequential_max_gap)):
            with_neighbour += 1
    share = with_neighbour / len(tails)
    if share <= s.sequential_share:
        return None
    return Signal("sequential", s.sequential_points,
                  f"{round(share * 100)}% номеров идут подряд ({with_neighbour} из {len(tails)})")


def _near(sorted_tails: list[int], tail: int, gap: int) -> list[int]:
    return sorted_tails[bisect_left(sorted_tails, tail - gap):bisect_right(sorted_tails, tail + gap)]


def no_conversion(stats: WindowStats, s: RiskSettings) -> Optional[Signal]:
    if stats.sends_ok < s.no_conversion_min_sends:
        return None
    if stats.verify_ok / stats.sends_ok >= s.no_conversion_ratio:
        return None
    return Signal("no_conversion", s.no_conversion_points,
                  f"{stats.sends_ok} SMS отправлено, подтверждено {stats.verify_ok}")


def fail_rate(stats: WindowStats, s: RiskSettings) -> Optional[Signal]:
    attempts = stats.verify_attempts
    if attempts < s.fail_rate_min_attempts:
        return None
    share = (stats.verify_fail + stats.verify_locked) / attempts
    if share < s.fail_rate_share:
        return None
    return Signal("fail_rate", s.fail_rate_points,
                  f"{round(share * 100)}% проверок неудачны ({attempts} попыток)")


def new_ip(stats: WindowStats, s: RiskSettings) -> Optional[Signal]:
    if not stats.new_ip_numbers:
        return None
    return Signal("new_ip", s.new_ip_points,
                  f"новый IP для ранее подтверждённых номеров: {len(stats.new_ip_numbers)}")


def hammering_locked(stats: WindowStats, s: RiskSettings) -> Optional[Signal]:
    if stats.verify_locked < s.hammering_min:
        return None
    return Signal("hammering_locked", s.hammering_points,
                  f"попыток к заблокированному номеру: {stats.verify_locked}")


def ip_limited(stats: WindowStats, s: RiskSettings) -> Optional[Signal]:
    if stats.ip_limited < 1:
        return None
    return Signal("ip_limited", s.ip_limited_points,
                  f"лимит проверок по IP срабатывал: {stats.ip_limited}")


def night(stats: WindowStats, s: RiskSettings) -> Optional[Signal]:
    if stats.last_ts is None:
        return None
    local = local_time(stats.last_ts, s)
    if not s.night_start_hour <= local.hour < s.night_end_hour:
        return None
    return Signal("night", s.night_points, f"активность ночью ({local:%H:%M} по Бишкеку)")


def local_time(ts: float, s: RiskSettings) -> datetime:
    return datetime.fromtimestamp(ts, timezone(timedelta(hours=s.tz_offset_hours)))


SIGNALS: tuple[Callable[[WindowStats, RiskSettings], Optional[Signal]], ...] = (
    fan_out, sequential, no_conversion, fail_rate, new_ip, hammering_locked, ip_limited, night,
)

# Описание признаков для meta() и README
SIGNAL_INFO = (
    ("fan_out", "коды запрошены на много разных номеров"),
    ("sequential", "номера идут подряд (последние 4 цифры отличаются на 1..10)"),
    ("no_conversion", "SMS отправлены, но почти не подтверждены"),
    ("fail_rate", "большинство проверок кода неудачны"),
    ("new_ip", "номер раньше подтверждался с другого IP"),
    ("hammering_locked", "попытки проверить заблокированный номер"),
    ("ip_limited", "срабатывал лимит проверок по IP"),
    ("night", "активность ночью по Бишкеку"),
)


def evaluate(stats: WindowStats, s: RiskSettings) -> list[Signal]:
    return [signal for check in SIGNALS if (signal := check(stats, s)) is not None]


def score_of(signals: list[Signal], s: RiskSettings) -> int:
    return min(s.max_score, sum(signal.points for signal in signals))


def level_of(score: int, s: RiskSettings) -> str:
    if score >= s.high_at:
        return "high"
    if score >= s.medium_at:
        return "medium"
    return "low"
