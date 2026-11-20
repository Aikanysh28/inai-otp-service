"""Демонстрация атак на OTP-сервис (только стандартная библиотека).

  1. single      — перебор кода для одного номера;
  2. distributed — распределённый перебор по 50 номерам с одного IP.

Чтобы доказать, что защита реально останавливает атаку (а не просто «не повезло»),
скрипт подмешивает НАСТОЯЩИЙ код в середину перебора — «перехватывает» его из
тестового SMS-транспорта outbox/sms.jsonl (путь — OTP_OUTBOX или --outbox).
Атака считается успешной, если хоть один verify вернул 200.

Запуск:  python attack.py [--url http://127.0.0.1:8000] [--attempts 1000]
Код выхода 0 — обе атаки остановлены, 1 — хотя бы одна успешна.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUTBOX = os.getenv("OTP_OUTBOX", os.path.join(HERE, "outbox", "sms.jsonl"))
CODE_SPACE = 1_000_000  # все 6-значные коды

STATUS_LABELS = {
    200: "200 (код подошёл)",
    401: "401 (неверный)",
    410: "410 (истёк)",
    423: "423 (номер заблок.)",
    429: "429 (лимит по IP)",
}


def post(url: str, payload: dict) -> tuple[int, dict]:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    try:
        return status, json.loads(raw or b"{}")
    except ValueError:
        return status, {}


def read_outbox(outbox: str) -> dict[str, str]:
    """Последний доставленный код каждого номера из outbox ({"ts","msisdn","code"} в строке)."""
    try:
        with open(outbox, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return {}
    codes: dict[str, str] = {}
    for line in lines:
        try:
            record = json.loads(line)
            codes[record["msisdn"]] = record["code"]  # поздние строки перезаписывают ранние
        except (ValueError, KeyError, TypeError):
            continue
    return codes


def send_and_leak(base: str, msisdns: list[str], outbox: str) -> dict[str, Optional[str]]:
    """Запросить коды и узнать настоящие (имитация перехвата SMS) из outbox.

    Настоящий код подмешивается в перебор, чтобы проверить, что защита не пропустит даже его.
    Для номеров, которым код не выдан, возвращается None.
    """
    issued = set()
    for msisdn in msisdns:
        status, body = post(f"{base}/otp/send", {"msisdn": msisdn})
        if status == 200:
            issued.add(msisdn)
        else:
            print(f"  send {msisdn} -> {status} {body.get('status')}")
    leaked = read_outbox(outbox)  # файл читаем один раз на все номера
    return {m: leaked.get(m) if m in issued else None for m in msisdns}


def guesses(n: int, real: Optional[str], plant_at: int) -> list[str]:
    codes = [f"{i:06d}" for i in random.sample(range(CODE_SPACE), n)]
    if real is not None:
        codes = [c for c in codes if c != real]
        codes.insert(min(plant_at, len(codes)), real)
    return codes[:n]


def run_verifies(base: str, pairs: list[tuple[str, str]], workers: int) -> Counter:
    def verify(pair: tuple[str, str]) -> int:
        msisdn, code = pair
        status, _ = post(f"{base}/otp/verify", {"msisdn": msisdn, "code": code})
        return status

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return Counter(pool.map(verify, pairs))


def report(name: str, stats: Counter, planted: bool) -> bool:
    success = stats.get(200, 0) > 0
    print(f"\n=== {name} ===")
    print(f"  {'попыток всего':<21}: {sum(stats.values())}")
    for status, label in STATUS_LABELS.items():
        print(f"  {label:<21}: {stats.get(status, 0)}")
    others = {k: v for k, v in stats.items() if k not in STATUS_LABELS}
    if others:
        print(f"  {'прочие':<21}: {others}")
    print(f"  настоящий код подмешан: {'да' if planted else 'нет (не удалось узнать)'}")
    verdict = "АТАКА УСПЕШНА — защита не сработала!" if success else "атака остановлена"
    print(f"  РЕЗУЛЬТАТ: {verdict}")
    return not success


def attack_single(base: str, attempts: int, workers: int, outbox: str, msisdn: str) -> bool:
    print(f"[single] номер {msisdn}")
    real = send_and_leak(base, [msisdn], outbox)[msisdn]
    # Настоящий код ставим 16-м: в пределах лимита IP (20/мин), но после 5 неверных вводов.
    # При 10 потоках 16-я задача стартует не раньше, чем завершатся 6 предыдущих,
    # так что номер к этому моменту уже заблокирован — ответ должен быть 423.
    codes = guesses(attempts, real, plant_at=15)
    stats = run_verifies(base, [(msisdn, c) for c in codes], workers)
    return report("Атака 1: перебор кода для одного номера", stats, real is not None)


def attack_distributed(base: str, attempts: int, workers: int, outbox: str,
                       numbers: list[str]) -> bool:
    real_codes = send_and_leak(base, numbers, outbox)
    known = sum(code is not None for code in real_codes.values())
    print(f"[distributed] настоящие коды известны для {known}/{len(numbers)} номеров")

    # Номера перебираются по кругу (раунд = одна попытка на каждый номер), поэтому за первые
    # 20 проверок ни один номер не набирает 5 неверных и блокировка номера не срабатывает.
    # Настоящий код каждого номера стоит в 3-м раунде (проверки 101-150) —
    # его должен отсечь лимит по IP.
    rounds = max(1, attempts // len(numbers))
    per_number = {m: guesses(rounds, real_codes[m], plant_at=2) for m in numbers}
    pairs = [(m, per_number[m][r]) for r in range(rounds) for m in numbers][:attempts]
    stats = run_verifies(base, pairs, workers)
    title = f"Атака 2: распределённый перебор по {len(numbers)} номерам с одного IP"
    return report(title, stats, planted=known > 0)


def main() -> int:
    p = argparse.ArgumentParser(description="Brute-force атаки на OTP-сервис")
    p.add_argument("--url", default=os.getenv("OTP_URL", "http://127.0.0.1:8000"))
    p.add_argument("--attempts", type=int, default=1000, help="попыток на каждую атаку")
    p.add_argument("--workers", type=int, default=10, help="параллельных потоков")
    p.add_argument("--numbers", type=int, default=50, help="номеров в распределённой атаке")
    p.add_argument("--outbox", default=DEFAULT_OUTBOX,
                   help="файл тестового SMS-транспорта сервиса")
    p.add_argument("--only", choices=["single", "distributed"])
    p.add_argument("--pause", type=int, default=61,
                   help="пауза между атаками (сек), чтобы окно лимита по IP сбросилось")
    args = p.parse_args()
    base = args.url.rstrip("/")

    # случайный диапазон номеров, чтобы повторные запуски не упирались в лимиты send
    prefix = 996700000000 + random.randrange(0, 90_000_000, 100)
    ok = True
    if args.only in (None, "single"):
        ok &= attack_single(base, args.attempts, args.workers, args.outbox, str(prefix))
    if args.only is None and args.pause > 0:
        print(f"\n... пауза {args.pause} с, чтобы сбросилось окно лимита по IP ...")
        time.sleep(args.pause)
    if args.only in (None, "distributed"):
        numbers = [str(prefix + 1 + i) for i in range(args.numbers)]
        ok &= attack_distributed(base, args.attempts, args.workers, args.outbox, numbers)

    print("\nИТОГ:", "все атаки остановлены защитой" if ok else "есть успешные атаки!")
    return 0 if ok else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # кириллица в консоли Windows
    sys.exit(main())
