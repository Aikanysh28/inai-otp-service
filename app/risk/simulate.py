"""Симуляция трафика для тестов и демо: события в ТЕКУЩЕМ формате журнала безопасности.

Traffic вызывает sink(record, msisdn=<сырой номер>, ts=clock()) — так же, как будет
вызывать журнал сервиса после подключения. Время — только через FakeClock, без sleep.
"""
from __future__ import annotations

import random
from datetime import datetime, timezone
from typing import Callable, Optional

# Демо-сюжет и тесты стартуют днём по Бишкеку, чтобы не срабатывал признак «ночь»
DEFAULT_START = datetime.fromisoformat("2026-11-20T14:00:00+06:00").timestamp()

Sink = Callable[..., None]


class FakeClock:
    """Подменяемые часы: время стоит, пока его явно не сдвинут."""

    def __init__(self, start: float = DEFAULT_START):
        self.now = float(start)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def colleague_mask(msisdn: str) -> str:
    """Маска из журнала сервиса: 996770730000 -> 9967*****000."""
    return msisdn[:4] + "*" * (len(msisdn) - 7) + msisdn[-3:]


class Traffic:
    OPERATOR_PREFIXES = ("99670", "99677", "99655", "99622", "99650", "99699")

    def __init__(self, sink: Sink, clock: FakeClock, seed: int = 0):
        self.sink = sink
        self.clock = clock
        self.rng = random.Random(seed)
        self._used_ips: set[str] = set()
        self._used_numbers: set[str] = set()

    # ---------- примитивы ----------

    def emit(self, event: str, msisdn: Optional[str], ip: Optional[str], **details) -> None:
        now = self.clock()
        record = {
            "ts": datetime.fromtimestamp(now, timezone.utc).isoformat(timespec="milliseconds"),
            "event": event,
        }
        if msisdn is not None:
            record["msisdn"] = colleague_mask(msisdn)
        if ip is not None:
            record["ip"] = ip
        record.update(details)
        self.sink(record, msisdn=msisdn, ts=now)

    def wait(self, low: float, high: float) -> None:
        self.clock.advance(self.rng.uniform(low, high))

    def new_ip(self) -> str:
        while True:
            ip = (f"{self.rng.randint(11, 223)}.{self.rng.randint(0, 255)}."
                  f"{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}")
            if ip not in self._used_ips:
                self._used_ips.add(ip)
                return ip

    def new_number(self) -> str:
        while True:
            number = self.rng.choice(self.OPERATOR_PREFIXES) + f"{self.rng.randrange(10 ** 7):07d}"
            if number not in self._used_numbers:
                self._used_numbers.add(number)
                return number

    def send_ok(self, msisdn: str, ip: str, send_no: int = 1) -> None:
        self.emit("otp_issued", msisdn, ip, send_no=send_no, expires_in=120)

    # ---------- поведения ----------

    def normal_user(self, ip: Optional[str] = None, msisdn: Optional[str] = None,
                    typo: bool = False) -> tuple[str, str]:
        """Человек: send -> (иногда одна опечатка) -> verify_success."""
        ip = ip or self.new_ip()
        msisdn = msisdn or self.new_number()
        self.send_ok(msisdn, ip)
        self.wait(8, 30)
        if typo:
            self.emit("verify_failed", msisdn, ip, failed_attempts=1, has_active_code=True)
            self.wait(4, 12)
        self.emit("verify_success", msisdn, ip)
        return ip, msisdn

    def office_nat(self, ip: str, users: int = 8) -> list[str]:
        """Много разных людей за одним IP (офис, NAT мобильного оператора)."""
        numbers = []
        for _ in range(users):
            _, msisdn = self.normal_user(ip=ip, typo=self.rng.random() < 0.25)
            numbers.append(msisdn)
            self.wait(3, 15)
        return numbers

    def pumping_bot(self, ip: str, prefix: str = "99670073", start: int = 1200,
                    count: int = 40) -> list[str]:
        """SMS pumping: только send на номера подряд, коды никто не вводит."""
        numbers = []
        for i in range(count):
            msisdn = f"{prefix}{start + i:04d}"
            self.send_ok(msisdn, ip)
            numbers.append(msisdn)
            self.wait(1.5, 4)
        return numbers

    def bruteforce_single(self, ip: str, attempts: int = 20,
                          msisdn: Optional[str] = None) -> str:
        """Перебор кода к одному номеру: 4 ошибки, 5-я + блокировка, дальше 423."""
        msisdn = msisdn or self.new_number()
        self.send_ok(msisdn, ip)
        self.wait(2, 5)
        for attempt in range(1, attempts + 1):
            if attempt < 5:
                self.emit("verify_failed", msisdn, ip, failed_attempts=attempt,
                          has_active_code=True)
            elif attempt == 5:
                self.emit("verify_failed", msisdn, ip, failed_attempts=5, has_active_code=True)
                self.emit("msisdn_blocked", msisdn, ip, duration=900,
                          reason="too_many_failed_attempts")
            else:
                self.emit("verify_rejected_blocked", msisdn, ip, retry_after=900)
            self.wait(0.2, 0.6)
        return msisdn

    def distributed(self, ip: str, count: int = 50, attempts: int = 100,
                    prefix: Optional[str] = None) -> list[str]:
        """Как attack.py distributed: send на count номеров подряд, 20 ошибок, дальше лимит IP."""
        base = prefix or f"9967{self.rng.randrange(10 ** 4):04d}"
        first = self.rng.randrange(0, 10 ** 4 - count)
        numbers = [f"{base}{first + i:04d}" for i in range(count)]
        for msisdn in numbers:
            self.send_ok(msisdn, ip)
            self.wait(0.3, 1.0)
        for attempt in range(attempts):
            if attempt < 20:
                msisdn = numbers[attempt % count]
                self.emit("verify_failed", msisdn, ip, failed_attempts=1, has_active_code=True)
            else:
                self.emit("verify_ip_rate_limited", None, ip, retry_after=60)
            self.wait(0.05, 0.3)
        return numbers

    def resend_spam(self, ip: str, msisdn: Optional[str] = None, tries: int = 6) -> str:
        """Нетерпеливый клиент: send, затем серия отказов «слишком рано»."""
        msisdn = msisdn or self.new_number()
        self.send_ok(msisdn, ip)
        for _ in range(tries):
            self.wait(2, 6)
            self.emit("send_rate_limited", msisdn, ip, reason="resend_delay", retry_after=20)
        return msisdn


def demo_story(sink: Sink, clock: FakeClock, seed: int = 7) -> dict[str, str]:
    """Сюжет демо примерно на 45 минут. Возвращает {название: ip}."""
    traffic = Traffic(sink, clock, seed)
    ips: dict[str, str] = {}

    changer_number = None
    for i in range(25):
        ip, msisdn = traffic.normal_user(typo=traffic.rng.random() < 0.2)
        if i == 0:
            changer_number = msisdn
            ips["user"] = ip
        traffic.wait(5, 20)

    ips["office"] = traffic.new_ip()
    traffic.office_nat(ips["office"], users=8)

    ips["resend_spam"] = traffic.new_ip()
    traffic.resend_spam(ips["resend_spam"])
    traffic.wait(20, 40)

    ips["bruteforce"] = traffic.new_ip()
    traffic.bruteforce_single(ips["bruteforce"], attempts=20)
    traffic.wait(20, 40)

    for _ in range(10):
        traffic.normal_user(typo=traffic.rng.random() < 0.2)
        traffic.wait(5, 20)

    ips["pumping_bot"] = "45.13.7.200"
    traffic.pumping_bot(ips["pumping_bot"], prefix="99670073", start=1200, count=40)
    traffic.wait(30, 60)

    ips["distributed"] = "185.220.101.7"
    traffic.distributed(ips["distributed"], count=50)
    traffic.wait(30, 60)

    # Первый пользователь сюжета подтверждает тот же номер с нового IP
    ips["ip_changer"] = traffic.new_ip()
    traffic.normal_user(ip=ips["ip_changer"], msisdn=changer_number)
    return ips
