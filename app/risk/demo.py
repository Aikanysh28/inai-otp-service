"""Демо модуля рисков на подменённых часах:  python3 -m app.risk.demo [--dump DIR]

Прогоняет сюжет simulate.demo_story и печатает сводку, топ IP и тревоги.
С --dump сохраняет JSON-фикстуры для вёрстки вкладки «Риски».
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .engine import RiskEngine
from .signals import local_time
from .simulate import DEFAULT_START, FakeClock, demo_story

DEMO_ID_KEY = b"risk-demo-key"  # только для демо: фикстуры воспроизводимы


def run() -> tuple[RiskEngine, dict[str, str]]:
    clock = FakeClock(DEFAULT_START)
    engine = RiskEngine(clock=clock, id_key=DEMO_ID_KEY)
    ips = demo_story(engine.sink, clock)
    return engine, ips


def print_report(engine: RiskEngine, ips: dict[str, str]) -> None:
    s = engine.settings
    o = engine.overview()
    names = {ip: name for name, ip in ips.items()}
    conversion = "—" if o["conversion"] is None else f"{o['conversion'] * 100:.1f}%"
    print("=== Сводка за час ===")
    print(f"  уровень угрозы      : {o['threat_level']}")
    print(f"  активных IP         : {o['ips_active']} "
          f"(medium: {o['ips_medium']}, high: {o['ips_high']})")
    print(f"  тревог              : {o['alerts']}")
    print(f"  SMS отправлено      : {o['sms_sent']}, подозрительных: {o['sms_suspicious']} "
          f"(≈{o['sms_cost_suspicious']:g} {o['currency']})")
    print(f"  конверсия           : {conversion}")

    print("\n=== Топ-10 IP ===")
    print(f"  {'IP':<16} {'роль':<12} {'балл':>4}  {'уровень':<7} {'действие':<15} причины")
    for row in engine.top_ips(limit=10):
        reasons = ", ".join(f"{r['name']}+{r['points']}" for r in row["reasons"]) or "—"
        print(f"  {row['ip']:<16} {names.get(row['ip'], ''):<12} {row['score']:>4}  "
              f"{row['level']:<7} {row['would_action']:<15} {reasons}")

    print("\n=== Тревоги (новые сверху) ===")
    for alert in engine.alerts(limit=s.max_alerts):
        when = local_time(alert["ts"], s).strftime("%H:%M:%S")
        print(f"  #{alert['id']} {when} [{alert['severity']}] {alert['message']}")
    meta = engine.meta()
    print(f"\nпринято событий: {meta['ingested']}, пропущено: {meta['ignored']}, "
          f"ошибок: {meta['errors']}")


def dump(engine: RiskEngine, ips: dict[str, str], directory: str) -> list[str]:
    os.makedirs(directory, exist_ok=True)
    payloads = {
        "overview": engine.overview(),
        "timeline": engine.timeline(),
        "ips": engine.top_ips(limit=50),
        "scatter": engine.scatter(),
        "alerts": engine.alerts(limit=engine.settings.max_alerts),
        "meta": engine.meta(),
    }
    for name, ip in ips.items():
        payloads[f"ip_{name}"] = engine.ip_detail(ip)
    written = []
    for name, payload in payloads.items():
        path = os.path.join(directory, f"{name}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
            f.write("\n")
        written.append(path)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Демо модуля оценки рисков OTP")
    parser.add_argument("--dump", metavar="DIR", help="сохранить JSON-фикстуры в папку")
    args = parser.parse_args(argv)
    engine, ips = run()
    print_report(engine, ips)
    if args.dump:
        files = dump(engine, ips, args.dump)
        print(f"\nфикстуры: {len(files)} файлов в {args.dump}")
    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
