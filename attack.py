"""Демонстрация атак на OTP-сервис (только стандартная библиотека).

  1. single      — перебор кода для одного номера;
  2. distributed — распределённый перебор по 50 номерам с одного IP.

Чтобы доказать, что защита реально останавливает атаку (а не просто «не повезло»),
скрипт подмешивает НАСТОЯЩИЙ код в середину перебора, если может его узнать:
из ответа /otp/send (OTP_DEBUG_RETURN_CODE=1) или из logs/sms.log.
Атака считается успешной, если хоть один verify вернул 200.

Запуск:  python attack.py [--url http://127.0.0.1:8000] [--attempts 1000]
Код выхода 0 — обе атаки остановлены, 1 — хотя бы одна успешна.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor


def post(url: str, payload: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            return e.code, json.loads(body or b"{}")
        except ValueError:
            return e.code, {}


def leak_code(msisdn: str, send_body: dict, sms_log: str) -> str | None:
    """Узнать настоящий код (имитация утечки), чтобы проверить, что защита его не пропустит."""
    if "code" in send_body:
        return send_body["code"]
    try:
        with open(sms_log, encoding="utf-8") as f:
            found = re.findall(rf"to=\+{msisdn} code=(\d{{6}})", f.read())
        return found[-1] if found else None
    except OSError:
        return None


def guesses(n: int, real: str | None, plant_at: int) -> list[str]:
    codes = [f"{i:06d}" for i in random.sample(range(1_000_000), n)]
    if real is not None:
        codes = [c for c in codes if c != real]
        codes.insert(min(plant_at, len(codes)), real)
    return codes[:n]


def run_verifies(base: str, pairs: list[tuple[str, str]], workers: int) -> Counter:
    def one(pair):
        status, _ = post(f"{base}/otp/verify", {"msisdn": pair[0], "code": pair[1]})
        return status

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return Counter(pool.map(one, pairs))


def report(name: str, stats: Counter, planted: bool) -> bool:
    success = stats.get(200, 0) > 0
    print(f"\n=== {name} ===")
    print(f"  попыток всего        : {sum(stats.values())}")
    print(f"  200 (код подошёл)    : {stats.get(200, 0)}")
    print(f"  401 (неверный)       : {stats.get(401, 0)}")
    print(f"  410 (истёк)          : {stats.get(410, 0)}")
    print(f"  423 (номер заблок.)  : {stats.get(423, 0)}")
    print(f"  429 (лимит по IP)    : {stats.get(429, 0)}")
    others = {k: v for k, v in stats.items() if k not in (200, 401, 410, 423, 429)}
    if others:
        print(f"  прочие               : {others}")
    print(f"  настоящий код подмешан: {'да' if planted else 'нет (не удалось узнать)'}")
    print(f"  РЕЗУЛЬТАТ: {'АТАКА УСПЕШНА — защита не сработала!' if success else 'атака остановлена'}")
    return not success


def attack_single(base: str, attempts: int, workers: int, sms_log: str, msisdn: str) -> bool:
    status, body = post(f"{base}/otp/send", {"msisdn": msisdn})
    print(f"[single] send {msisdn} -> {status} {body.get('status')}")
    real = leak_code(msisdn, body, sms_log) if status == 200 else None
    # Настоящий код ставим 16-м: в пределах лимита IP (20/мин), но после 5 неверных вводов.
    # При 10 потоках 16-я задача стартует не раньше, чем завершатся 6 предыдущих,
    # так что номер к этому моменту уже заблокирован — ответ должен быть 423.
    codes = guesses(attempts, real, plant_at=15)
    stats = run_verifies(base, [(msisdn, c) for c in codes], workers)
    return report("Атака 1: перебор кода для одного номера", stats, real is not None)


def attack_distributed(base: str, attempts: int, workers: int, sms_log: str, numbers: list[str]) -> bool:
    real_codes: dict[str, str | None] = {}
    sent = 0
    for m in numbers:
        status, body = post(f"{base}/otp/send", {"msisdn": m})
        if status == 200:
            sent += 1
            real_codes[m] = leak_code(m, body, sms_log)
        else:
            real_codes[m] = None
    print(f"[distributed] коды выданы для {sent}/{len(numbers)} номеров")

    # По 1-4 попытки на номер (ниже порога блокировки номера), номера по кругу.
    # Настоящий код каждого номера подмешан в 3-й раунд — после 20 проверок/мин он не должен пройти.
    rounds = max(1, attempts // len(numbers))
    per_number = {m: guesses(rounds, real_codes[m], plant_at=2) for m in numbers}
    pairs = [(m, per_number[m][r]) for r in range(rounds) for m in numbers][:attempts]
    stats = run_verifies(base, pairs, workers)
    planted = any(c is not None for c in real_codes.values())
    return report("Атака 2: распределённый перебор по 50 номерам с одного IP", stats, planted)


def main() -> int:
    p = argparse.ArgumentParser(description="Brute-force атаки на OTP-сервис")
    p.add_argument("--url", default=os.getenv("OTP_URL", "http://127.0.0.1:8000"))
    p.add_argument("--attempts", type=int, default=1000, help="попыток на каждую атаку")
    p.add_argument("--workers", type=int, default=10, help="параллельных потоков")
    p.add_argument("--numbers", type=int, default=50, help="номеров в распределённой атаке")
    p.add_argument("--sms-log", default=os.path.join("logs", "sms.log"))
    p.add_argument("--only", choices=["single", "distributed"])
    p.add_argument("--pause", type=int, default=61,
                   help="пауза между атаками (сек), чтобы окно лимита по IP сбросилось")
    args = p.parse_args()
    base = args.url.rstrip("/")

    # случайный диапазон номеров, чтобы повторные запуски не упирались в лимиты send
    prefix = 996700000000 + random.randrange(0, 90_000_000, 100)
    ok = True
    if args.only in (None, "single"):
        ok &= attack_single(base, args.attempts, args.workers, args.sms_log, str(prefix))
    if args.only is None and args.pause > 0:
        print(f"\n... пауза {args.pause} с, чтобы сбросилось окно лимита по IP ...")
        time.sleep(args.pause)
    if args.only in (None, "distributed"):
        numbers = [str(prefix + 1 + i) for i in range(args.numbers)]
        ok &= attack_distributed(base, args.attempts, args.workers, args.sms_log, numbers)

    print("\nИТОГ:", "все атаки остановлены защитой" if ok else "есть успешные атаки!")
    return 0 if ok else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # кириллица в консоли Windows
    sys.exit(main())
