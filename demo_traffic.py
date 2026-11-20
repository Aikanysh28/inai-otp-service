"""Демо-трафик для защиты: обычные пользователи с разных IP и сюжет атаки (только stdlib).

Разные IP на одной машине — через X-Forwarded-For: сервер должен доверять 127.0.0.1
(OTP_TRUSTED_PROXIES=127.0.0.1), иначе заголовок игнорируется и все события придут с 127.0.0.1.

  python3 demo_traffic.py --users 10 --interval 3            # фон из обычных пользователей
  python3 demo_traffic.py --scenario demo --token demo        # сюжет на 3–4 минуты для защиты

Код пользователя берётся из outbox/sms.jsonl — так же, как его «перехватывает» attack.py.
"""
from __future__ import annotations

import argparse
import os
import random
import sys
import threading
import time
from collections import Counter
from typing import Optional

from attack import DEFAULT_OUTBOX, attack_pumping, get_json, post, read_outbox, report_pumping

# Операторы КР и «правдоподобные» адреса; бот pumping ходит по 99670073xxxx — туда не попадаем
USER_PREFIXES = ("99655", "99677", "99650", "99622", "99699", "99670")
USER_NETS = ("5.59", "92.62", "212.42", "46.251", "176.123", "31.186")
BOT_PREFIX = "99670073"

BRUTEFORCE_IP = "77.88.1.15"
DISTRIBUTED_IP = "91.200.3.4"
PUMPING_IP = "45.13.7.200"


class Background:
    """Поток обычных пользователей: каждый — свой IP, свой номер, свой поток выполнения."""

    def __init__(self, base: str, outbox: str, interval: float, rng: random.Random):
        self.base, self.outbox, self.interval, self.rng = base, outbox, interval, rng
        self.stats: Counter = Counter()
        self._lock = threading.Lock()
        self._no_more = threading.Event()  # больше не запускать новых пользователей
        self._abort = threading.Event()  # прервать тех, кто ещё входит
        self._threads: list[threading.Thread] = []
        self._used_numbers: set[str] = set()
        self._changer_done = False
        self.started = 0

    # ---------- случайные данные ----------

    def new_ip(self) -> str:
        with self._lock:
            return f"{self.rng.choice(USER_NETS)}.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}"

    def new_number(self) -> str:
        with self._lock:
            while True:
                number = self.rng.choice(USER_PREFIXES) + f"{self.rng.randrange(10 ** 7):07d}"
                if not number.startswith(BOT_PREFIX) and number not in self._used_numbers:
                    self._used_numbers.add(number)
                    return number

    def count(self, key: str) -> None:
        with self._lock:
            self.stats[key] += 1

    # ---------- поведение одного пользователя ----------

    def _send(self, msisdn: str, ip: str) -> bool:
        status, _ = post(f"{self.base}/otp/send", {"msisdn": msisdn}, {"X-Forwarded-For": ip})
        self.count(f"send {status}")
        return status == 200

    def _verify(self, msisdn: str, ip: str, code: str) -> int:
        status, _ = post(f"{self.base}/otp/verify", {"msisdn": msisdn, "code": code},
                         {"X-Forwarded-For": ip})
        self.count(f"verify {status}")
        return status

    def _sleep(self, low: float, high: float) -> bool:
        """Пауза; False, если демо остановили."""
        return not self._abort.wait(self.rng.uniform(low, high))

    def user(self, changer: bool) -> None:
        try:
            ip, msisdn = self.new_ip(), self.new_number()
            if not self._send(msisdn, ip):
                return
            if not self._sleep(5, 20):
                return
            roll = self.rng.random()
            if roll < 0.10:  # так и не ввёл код
                self.count("abandoned")
                return
            code = read_outbox(self.outbox).get(msisdn)
            if code is None:
                self.count("no_code_in_outbox")
                return
            if roll < 0.25:  # сначала ошибся
                self._verify(msisdn, ip, f"{(int(code) + 1) % 10 ** 6:06d}")
                self._sleep(2, 5)
            if self._verify(msisdn, ip, code) == 200 and changer:
                # тот же человек позже входит с другого IP (признак «новый IP»)
                self._sleep(35, 45)
                new_ip = self.new_ip()
                if self._send(msisdn, new_ip) and self._sleep(5, 10):
                    fresh = read_outbox(self.outbox).get(msisdn)
                    if fresh:
                        self._verify(msisdn, new_ip, fresh)
                        self.count("ip_changer")
        except Exception as error:  # noqa: BLE001 — фон не должен ронять демо
            self.count(f"error {type(error).__name__}")

    # ---------- управление ----------

    def spawn(self) -> None:
        changer = not self._changer_done and self.started >= 2
        if changer:
            self._changer_done = True
        thread = threading.Thread(target=self.user, args=(changer,), daemon=True)
        thread.start()
        self.started += 1
        self._threads.append(thread)

    def run_for(self, seconds: float, limit: Optional[int] = None) -> None:
        """Запускать пользователей каждые interval±30% секунд в течение seconds (или limit штук)."""
        deadline = time.monotonic() + seconds
        launched = 0
        while (time.monotonic() < deadline and not self._no_more.is_set()
               and (limit is None or launched < limit)):
            self.spawn()
            launched += 1
            self._no_more.wait(max(0.2, self.interval * self.rng.uniform(0.7, 1.3)))

    def start_async(self) -> threading.Thread:
        thread = threading.Thread(target=self.run_for, args=(10 ** 9,), daemon=True)
        thread.start()
        return thread

    def stop_spawning(self) -> None:
        self._no_more.set()

    def stop(self, wait: float = 60.0) -> None:
        """Не запускать новых и дать начатым войти; кто не успел за wait — прервать."""
        self._no_more.set()
        deadline = time.monotonic() + wait
        for thread in list(self._threads):
            thread.join(max(0.0, deadline - time.monotonic()))
        self._abort.set()


# ---------- атаки сюжета ----------

def bruteforce(base: str, ip: str, attempts: int = 25) -> Counter:
    """Подбор кода к одному номеру с одного IP."""
    msisdn = f"99655{random.randrange(10 ** 7):07d}"
    headers = {"X-Forwarded-For": ip}
    stats: Counter = Counter()
    post(f"{base}/otp/send", {"msisdn": msisdn}, headers)
    for _ in range(attempts):
        status, _ = post(f"{base}/otp/verify",
                         {"msisdn": msisdn, "code": f"{random.randrange(10 ** 6):06d}"}, headers)
        stats[status] += 1
        time.sleep(0.25)
    return stats


def distributed(base: str, ip: str, count: int = 50, attempts: int = 100) -> Counter:
    """Как attack.py distributed: send на count номеров подряд, затем verify по кругу."""
    first = random.randrange(0, 10 ** 4 - count)
    prefix = f"996777{random.randrange(10 ** 2):02d}"
    numbers = [f"{prefix}{first + i:04d}" for i in range(count)]
    headers = {"X-Forwarded-For": ip}
    stats: Counter = Counter()
    for msisdn in numbers:
        status, _ = post(f"{base}/otp/send", {"msisdn": msisdn}, headers)
        stats[f"send {status}"] += 1
        time.sleep(0.05)
    for i in range(attempts):
        status, _ = post(f"{base}/otp/verify",
                         {"msisdn": numbers[i % count], "code": f"{random.randrange(10 ** 6):06d}"},
                         headers)
        stats[f"verify {status}"] += 1
        time.sleep(0.05)
    return stats


def stage(number: int, title: str, watch: str) -> None:
    line = "=" * 72
    print(f"\n{line}\n  ЭТАП {number}. {title.upper()}\n  Смотрите на дашборде: {watch}\n{line}",
          flush=True)


def check_forwarding(base: str, token: Optional[str]) -> None:
    if not token:
        return
    status, rows = get_json(f"{base}/api/risk/ips?limit=200", token)
    if status == 200 and isinstance(rows, list) and rows and {r.get("ip") for r in rows} == {"127.0.0.1"}:
        print("ВНИМАНИЕ: все события пришли с 127.0.0.1 — сервер не доверяет X-Forwarded-For. "
              "Перезапустите его с OTP_TRUSTED_PROXIES=127.0.0.1.", flush=True)


def scenario_demo(base: str, outbox: str, token: Optional[str], interval: float,
                  rng: random.Random, pumping_interval: float = 1.5) -> Background:
    bg = Background(base, outbox, interval, rng)
    print("Сюжет демо: ~3,5 минуты. Откройте /dashboard?token=...#risk", flush=True)

    stage(1, "Обычные пользователи (60 с)",
          "плитки и «Подметание» — случайное облако зелёных точек, у каждого IP один луч на графе.")
    bg.run_for(60)
    check_forwarding(base, token)

    stage(2, f"SMS pumping с {PUMPING_IP} на фоне пользователей",
          "линия на «Подметании» (окно 5 мин), звезда на графе, тревога «Высокий» на ~6-м номере, "
          "растёт «потрачено ботами».")
    feeder = bg.start_async()
    result = attack_pumping(base, BOT_PREFIX, 60, pumping_interval, 0.5, PUMPING_IP, token)
    report_pumping(result, token)

    stage(3, f"Подбор кода к одному номеру с {BRUTEFORCE_IP}",
          "в топе IP — «Ошибки ввода» и «Атака на блок», уровень «Средний».")
    stats = bruteforce(base, BRUTEFORCE_IP)
    print("  ответы verify:", dict(stats), flush=True)

    stage(4, f"Распределённая атака с {DISTRIBUTED_IP}",
          "балл 100: «Веер», «Подряд», «Ошибки ввода», «Лимит IP»; на графе — вторая звезда.")
    stats = distributed(base, DISTRIBUTED_IP)
    print("  ответы:", dict(stats), flush=True)

    stage(5, "Снова обычные пользователи (30 с)",
          "нажмите «Сводка за 10 минут» — три инцидента; откройте карточку бота и разбор балла.")
    time.sleep(30)
    bg.stop_spawning()
    feeder.join(5)
    return bg


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Демо-трафик OTP-сервиса")
    p.add_argument("--base", "--url", dest="base", default=os.getenv("OTP_URL", "http://127.0.0.1:8000"))
    p.add_argument("--outbox", default=DEFAULT_OUTBOX, help="файл тестового SMS-транспорта сервиса")
    p.add_argument("--token", default=os.getenv("DASHBOARD_TOKEN"), help="токен админки")
    p.add_argument("--users", type=int, default=10, help="обычных пользователей (без --scenario)")
    p.add_argument("--interval", type=float, default=3.0, help="пауза между пользователями, с")
    p.add_argument("--scenario", choices=["demo"], help="готовый сюжет для защиты")
    p.add_argument("--pumping-interval", type=float, default=1.5,
                   help="пауза бота между номерами в сюжете, с")
    p.add_argument("--seed", type=int, help="зерно генератора (воспроизводимые номера и IP)")
    args = p.parse_args(argv)
    base = args.base.rstrip("/")
    rng = random.Random(args.seed)

    status, _ = get_json(f"{base}/health")
    if status not in (200, 503):
        print(f"Сервис не отвечает по адресу {base} — запустите python3 run.py", file=sys.stderr)
        return 2

    if args.scenario == "demo":
        bg = scenario_demo(base, args.outbox, args.token, args.interval, rng, args.pumping_interval)
    else:
        bg = Background(base, args.outbox, args.interval, rng)
        print(f"Обычные пользователи: {args.users}, интервал ~{args.interval} с", flush=True)
        bg.run_for(10 ** 9, limit=args.users)
        check_forwarding(base, args.token)

    print("\n... ждём, пока пользователи завершат вход ...", flush=True)
    bg.stop(wait=60)
    stats = dict(sorted(bg.stats.items()))
    print(f"\nИТОГ фона: пользователей {bg.started}; ответы: {stats}")

    if args.scenario == "demo" and args.token:
        status, summary = get_json(f"{base}/api/risk/summary?window=600", args.token)
        if status == 200 and isinstance(summary, dict):
            source = "LLM по агрегатам" if summary.get("source") == "llm" else "по шаблону"
            print(f"\n=== Сводка инцидента за 10 минут ({source}) ===\n{summary.get('text', '')}")
    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
