"""Демонстрация атак на OTP-сервис (только стандартная библиотека).

  1. single      — перебор кода для одного номера;
  2. distributed — распределённый перебор по 50 номерам с одного IP;
  3. pumping     — SMS pumping: медленные send на номера подряд без ввода кодов
                   (только с --only pumping, в запуск по умолчанию не входит).

Чтобы доказать, что защита реально останавливает атаку (а не просто «не повезло»),
скрипт подмешивает НАСТОЯЩИЙ код в середину перебора — «перехватывает» его из
тестового SMS-транспорта outbox/sms.jsonl (путь — OTP_OUTBOX или --outbox).
Атака считается успешной, если хоть один verify вернул 200.

Запуск:  python attack.py [--url http://127.0.0.1:8000] [--attempts 1000]
Код выхода 0 — обе атаки остановлены, 1 — хотя бы одна успешна.

Pumping:  python attack.py --only pumping --client-ip 45.13.7.200 --token <DASHBOARD_TOKEN>
(X-Forwarded-For учитывается, только если сервер запущен с OTP_TRUSTED_PROXIES=127.0.0.1.)
Код выхода 0 — модуль рисков поднял тревогу high на этот IP (или токен не передан), иначе 1.
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


def post(url: str, payload: dict, headers: Optional[dict] = None) -> tuple[int, dict]:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **(headers or {})})
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


# ---------- SMS pumping (только --only pumping) ----------

PUMPING_DEFAULTS = {"range_prefix": "99670073", "count": 60, "interval": 1.5, "jitter": 0.5}


def get_json(url: str, token: Optional[str] = None) -> tuple[int, Optional[object]]:
    """GET к API админки; (статус, JSON или None). Сетевая ошибка — (0, None)."""
    req = urllib.request.Request(url, headers={"X-Dashboard-Token": token} if token else {})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"null")
        except ValueError:
            return e.code, None
    except (OSError, ValueError):
        return 0, None


def wait_risk_queue(base: str, token: str, timeout: float = 5.0) -> None:
    """Дождаться, пока модуль рисков обработает очередь событий (meta.queue_size == 0)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status, meta = get_json(f"{base}/api/risk/meta", token)
        if status != 200 or not isinstance(meta, dict) or meta.get("queue_size", 0) == 0:
            return
        time.sleep(0.1)


def attack_pumping(base: str, prefix: str = "99670073", count: int = 60, interval: float = 1.5,
                   jitter: float = 0.5, client_ip: Optional[str] = None,
                   token: Optional[str] = None, quiet: bool = False) -> dict:
    """Только POST /otp/send на prefix+0000..count-1 подряд, без verify, с паузой interval±jitter."""
    headers = {"X-Forwarded-For": client_ip} if client_ip else None
    price, currency = 1.0, "сом"
    if token:
        status, meta = get_json(f"{base}/api/risk/meta", token)
        if status == 200 and isinstance(meta, dict):
            price, currency = float(meta.get("sms_price", 1.0)), meta.get("currency", currency)
    stats: Counter = Counter()
    sent = 0
    if not quiet:
        print(f"[pumping] IP {client_ip or '(без X-Forwarded-For)'}, номера {prefix}0000.."
              f"{prefix}{count - 1:04d}, пауза {interval}±{jitter} с")
    for i in range(count):
        status, _ = post(f"{base}/otp/send", {"msisdn": f"{prefix}{i:04d}"}, headers)
        stats[status] += 1
        sent += status == 200
        if not quiet:
            print(f"\r  номер {i + 1}/{count} · отправлено SMS {sent} · ≈{sent * price:g} {currency}   ",
                  end="", flush=True)
        if i < count - 1 and interval > 0:
            time.sleep(max(0.0, interval + random.uniform(-jitter, jitter)))
    if not quiet:
        print()
    result = {"ip": client_ip or "127.0.0.1", "count": count, "sent": sent, "stats": dict(stats),
              "price": price, "currency": currency, "risk": None, "first_high_at": None,
              "trusts_forwarded": None}
    if token:
        wait_risk_queue(base, token)
        status, detail = get_json(f"{base}/api/risk/ip?ip={result['ip']}", token)
        if status == 200 and isinstance(detail, dict):
            result["risk"] = detail
            first = detail.get("first_high") or {}
            result["first_high_at"] = first.get("at_number")
        if client_ip:
            _, rows = get_json(f"{base}/api/risk/ips?limit=200", token)
            ips = {row.get("ip") for row in rows} if isinstance(rows, list) else set()
            result["trusts_forwarded"] = not (client_ip not in ips and "127.0.0.1" in ips)
    return result


def report_pumping(result: dict, token: Optional[str]) -> bool:
    """Честный вердикт по pumping. True — модуль рисков поднял тревогу high (или токена нет)."""
    stats, sent, cur = result["stats"], result["sent"], result["currency"]
    rejected = sum(v for k, v in stats.items() if k != 200)
    print("\n=== Атака 3: SMS pumping — номера подряд, коды не вводятся ===")
    print(f"  {'запросов send':<21}: {result['count']}")
    print(f"  {'SMS выдано (200)':<21}: {sent}")
    print(f"  {'отказов':<21}: {rejected} {dict((k, v) for k, v in stats.items() if k != 200) or ''}")
    print(f"  {'оценка стоимости':<21}: ≈{sent * result['price']:g} {cur}")
    if result["trusts_forwarded"] is False:
        print("  ВНИМАНИЕ: сервер, похоже, не доверяет X-Forwarded-For — все события пришли с 127.0.0.1."
              " Запустите сервер с OTP_TRUSTED_PROXIES=127.0.0.1.")
    if not token:
        print("  Токен админки не передан (--token): вердикт модуля рисков не запрошен.")
        print("  Базовая защита не остановила рассылку (лимит send — только на номер).")
        return True
    risk = result["risk"]
    if not risk:
        print("  Модуль рисков не ответил по этому IP (выключен или IP не найден).")
        return False
    reasons = ", ".join(f"{r['name']}+{r['points']}" for r in risk.get("reasons", [])) or "—"
    print(f"  {'модуль рисков':<21}: уровень {risk['level']}, балл {risk['score']} ({reasons})")
    at = result["first_high_at"]
    if risk["level"] == "high" and at:
        rest = max(0, sent - at)
        print(f"  Базовая защита не остановила рассылку (лимит send — только на номер). "
              f"Модуль рисков обнаружил бота на {at}-м номере; в боевом режиме остальные {rest} SMS "
              f"были бы отклонены, экономия ≈{rest * result['price']:g} {cur}.")
        return True
    print("  Базовая защита не остановила рассылку (лимит send — только на номер), "
          "и модуль рисков не поднял тревогу high на этот IP.")
    return False


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Brute-force атаки на OTP-сервис")
    p.add_argument("--url", default=os.getenv("OTP_URL", "http://127.0.0.1:8000"))
    p.add_argument("--attempts", type=int, default=1000, help="попыток на каждую атаку")
    p.add_argument("--workers", type=int, default=10, help="параллельных потоков")
    p.add_argument("--numbers", type=int, default=50, help="номеров в распределённой атаке")
    p.add_argument("--outbox", default=DEFAULT_OUTBOX,
                   help="файл тестового SMS-транспорта сервиса")
    p.add_argument("--only", choices=["single", "distributed", "pumping"])
    p.add_argument("--pause", type=int, default=61,
                   help="пауза между атаками (сек), чтобы окно лимита по IP сбросилось")
    pumping = p.add_argument_group("pumping (только с --only pumping)")
    pumping.add_argument("--client-ip", help="отправлять X-Forwarded-For с этим IP")
    pumping.add_argument("--range-prefix", default=PUMPING_DEFAULTS["range_prefix"],
                         help="первые 8 цифр номеров (дальше 0000..count-1)")
    pumping.add_argument("--count", type=int, default=PUMPING_DEFAULTS["count"], help="номеров")
    pumping.add_argument("--interval", type=float, default=PUMPING_DEFAULTS["interval"],
                         help="пауза между номерами, с")
    pumping.add_argument("--jitter", type=float, default=PUMPING_DEFAULTS["jitter"],
                         help="разброс паузы, ± с")
    pumping.add_argument("--token", default=os.getenv("DASHBOARD_TOKEN"),
                         help="токен админки, чтобы запросить вердикт модуля рисков")
    return p


def selected_attacks(only: Optional[str]) -> list[str]:
    """Какие атаки запустить: по умолчанию — две старые; pumping — только явно."""
    return [only] if only else ["single", "distributed"]


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    base = args.url.rstrip("/")

    if args.only == "pumping":
        result = attack_pumping(base, args.range_prefix, args.count, args.interval, args.jitter,
                                args.client_ip, args.token)
        return 0 if report_pumping(result, args.token) else 1

    # случайный диапазон номеров, чтобы повторные запуски не упирались в лимиты send
    prefix = 996700000000 + random.randrange(0, 90_000_000, 100)
    attacks = selected_attacks(args.only)
    ok = True
    if "single" in attacks:
        ok &= attack_single(base, args.attempts, args.workers, args.outbox, str(prefix))
    if args.only is None and args.pause > 0:
        print(f"\n... пауза {args.pause} с, чтобы сбросилось окно лимита по IP ...")
        time.sleep(args.pause)
    if "distributed" in attacks:
        numbers = [str(prefix + 1 + i) for i in range(args.numbers)]
        ok &= attack_distributed(base, args.attempts, args.workers, args.outbox, numbers)

    print("\nИТОГ:", "все атаки остановлены защитой" if ok else "есть успешные атаки!")
    return 0 if ok else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # кириллица в консоли Windows
    sys.exit(main())
