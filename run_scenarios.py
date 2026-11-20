"""Прогон сценариев в формате жюри (scenarios_examples.json) против сервиса.

Каждый сценарий независим: свежий сервис, своё хранилище и outbox, подменяемые часы
(op "advance" сдвигает их мгновенно, без реального ожидания). Запросы идут через тот же
слой API, что и HTTP-сервер (валидация, маршруты, коды ответов), client_ip передаётся напрямую.

Поддерживаемые шаги:
  request          {method, path, body, client_ip?, expected: {status, body?}}
  capture_delivery {msisdn, bind}  — последняя строка outbox для номера; код -> переменная
  advance          {seconds}
  parallel         {requests: [...], expected: {count?, status_counts?}}
Подстановки в body: "$c1" — код из capture, "$wrong:c1" — заведомо другая 6-значная строка.

Запуск:  python run_scenarios.py [файлы.json ...]   (по умолчанию все scenarios/scenarios_*.json)
Код выхода 0 — все сценарии прошли.
"""
from __future__ import annotations

import argparse
import dataclasses
import glob
import json
import os
import secrets
import sys
import tempfile
import threading
from collections import Counter
from datetime import datetime
from typing import Any, Optional

from app.api import OTPApi, Request
from app.config import Settings
from app.otp_service import OTPService
from app.security_log import SecurityLog, SmsGateway

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SCENARIOS = sorted(glob.glob(os.path.join(HERE, "scenarios", "scenarios_*.json")))
DEFAULT_IP = "127.0.0.1"


class ScenarioFailed(Exception):
    pass


class FakeClock:
    def __init__(self, start: float):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def wrong_code(code: str) -> str:
    return f"{(int(code) + 1) % 10 ** len(code):0{len(code)}d}"


def substitute(value: Any, variables: dict[str, str]) -> Any:
    if isinstance(value, dict):
        return {k: substitute(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, variables) for v in value]
    if isinstance(value, str) and value.startswith("$"):
        name = value[1:]
        if name.startswith("wrong:"):
            return wrong_code(variables[name[len("wrong:"):]])
        if name in variables:
            return variables[name]
    return value


def last_delivery(outbox: str, msisdn: str) -> str:
    code = None
    with open(outbox, encoding="utf-8") as f:
        for line in f:
            record = json.loads(line)
            if record["msisdn"] == msisdn:
                code = record["code"]
    if code is None:
        raise ScenarioFailed(f"в outbox нет доставки для {msisdn}")
    return code


class ScenarioRun:
    def __init__(self, scenario: dict, fixture: dict, workdir: str):
        start = fixture.get("start_time")
        self.clock = FakeClock(datetime.fromisoformat(start).timestamp() if start else 1_800_000_000.0)
        self.outbox = os.path.join(workdir, "outbox", "sms.jsonl")
        settings = Settings(secret_key=secrets.token_bytes(32), log_dir=os.path.join(workdir, "logs"),
                            outbox_path=self.outbox)
        settings = self._apply_overrides(settings, scenario.get("overrides") or {})
        self.service = OTPService(
            settings,
            SecurityLog(settings.log_dir, clock=self.clock, console=False),
            clock=self.clock,
            sms=SmsGateway(self.outbox, self.clock, echo=False),
        )
        self.api = OTPApi(self.service)
        self.variables: dict[str, str] = {}

    @staticmethod
    def _apply_overrides(settings: Settings, overrides: dict) -> Settings:
        known = {f.name for f in dataclasses.fields(Settings)}
        unknown = set(overrides) - known
        if unknown:
            raise ScenarioFailed(f"неизвестные overrides: {sorted(unknown)}")
        values = {k: tuple(v) if isinstance(v, list) else v for k, v in overrides.items()}
        return dataclasses.replace(settings, **values)

    def call(self, req: dict) -> tuple[int, dict]:
        body = substitute(req.get("body"), self.variables)
        raw = json.dumps(body).encode() if body is not None else b""
        request = Request.build(req["method"], req["path"], {}, raw, req.get("client_ip", DEFAULT_IP))
        response = self.api.handle(request)
        return response.status, response.body if isinstance(response.body, dict) else {}

    def run_step(self, step: dict) -> None:
        op = step["op"]
        if op == "request":
            status, body = self.call(step)
            expected = step.get("expected", {})
            if "status" in expected and status != expected["status"]:
                raise ScenarioFailed(f"{step['method']} {step['path']}: ожидался {expected['status']}, "
                                     f"получен {status} {body}")
            for key, value in (expected.get("body") or {}).items():
                if body.get(key) != value:
                    raise ScenarioFailed(f"{step['path']}: body.{key}={body.get(key)!r}, ожидалось {value!r}")
        elif op == "capture_delivery":
            self.variables[step["bind"]] = last_delivery(self.outbox, step["msisdn"])
        elif op == "advance":
            self.clock.advance(float(step["seconds"]))
        elif op == "parallel":
            self._run_parallel(step)
        else:
            raise ScenarioFailed(f"неизвестный шаг {op!r}")

    def _run_parallel(self, step: dict) -> None:
        requests = step["requests"]
        statuses: list[int] = []
        lock = threading.Lock()
        barrier = threading.Barrier(len(requests))

        def worker(req: dict) -> None:
            barrier.wait()
            status, _ = self.call(req)
            with lock:
                statuses.append(status)

        threads = [threading.Thread(target=worker, args=(r,)) for r in requests]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        expected = step.get("expected", {})
        if "count" in expected and len(statuses) != expected["count"]:
            raise ScenarioFailed(f"parallel: {len(statuses)} ответов, ожидалось {expected['count']}")
        got = {str(k): v for k, v in Counter(statuses).items()}
        want = {str(k): v for k, v in (expected.get("status_counts") or {}).items()}
        if want and got != want:
            raise ScenarioFailed(f"parallel: статусы {got}, ожидалось {want}")

    def close(self) -> None:
        self.service.log.close()


def load_fixture(scenario_file: str, name: Optional[str]) -> dict:
    if not name:
        return {}
    path = os.path.join(os.path.dirname(os.path.abspath(scenario_file)), name)
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def run_file(path: str) -> tuple[int, int]:
    with open(path, encoding="utf-8") as f:
        scenarios = json.load(f)
    passed = 0
    for scenario in scenarios:
        label = f"{scenario.get('id', '?')} {scenario.get('title', '')}".strip()
        with tempfile.TemporaryDirectory(prefix="otp_scenario_") as workdir:
            run = None
            try:
                run = ScenarioRun(scenario, load_fixture(path, scenario.get("fixture")), workdir)
                for number, step in enumerate(scenario["steps"], 1):
                    try:
                        run.run_step(step)
                    except ScenarioFailed as e:
                        raise ScenarioFailed(f"шаг {number}: {e}") from None
                print(f"  PASS  {label}")
                passed += 1
            except (ScenarioFailed, KeyError, ValueError, OSError) as e:
                print(f"  FAIL  {label}: {e}")
            finally:
                if run is not None:
                    run.close()
    return passed, len(scenarios)


def main() -> int:
    parser = argparse.ArgumentParser(description="Прогон сценариев жюри против OTP-сервиса")
    parser.add_argument("files", nargs="*", default=DEFAULT_SCENARIOS)
    args = parser.parse_args()

    total_passed = total = 0
    for path in args.files:
        print(f"{path}:")
        passed, count = run_file(path)
        total_passed += passed
        total += count
    print(f"\nИТОГ: {total_passed}/{total} сценариев пройдено")
    return 0 if total_passed == total else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
