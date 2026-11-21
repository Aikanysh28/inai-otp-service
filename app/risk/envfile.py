"""Чтение `.env` для модуля рисков (stdlib): только переменные RISK_*.

Сервер на stdlib сам `.env` не читает, поэтому ключ LLM, записанный в файл, раньше не доходил
до процесса, если сервер запускали без `set -a; . ./.env`. Здесь — минимальный парсер:
KEY=VALUE, комментарии `#`, пустые строки, необязательные кавычки, пробелы и `\\r` обрезаются.
Значения из окружения важнее файла. Остальные переменные (OTP_*, DASHBOARD_TOKEN, …) не трогаем.
"""
from __future__ import annotations

import os
from typing import Mapping, Optional

PREFIX = "RISK_"
DEFAULT_FILE = ".env"


def parse_env(text: str, prefix: str = PREFIX) -> dict[str, str]:
    """Пары KEY=VALUE из текста .env, только с именами на prefix."""
    result: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip().lstrip("﻿")
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, _, value = line.partition("=")
        key = key.strip()
        if not key.startswith(prefix) or not key.replace("_", "").isalnum():
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        elif " #" in value:  # комментарий в конце строки без кавычек
            value = value.split(" #", 1)[0].rstrip()
        result[key] = value
    return result


def env_file_path(environ: Mapping[str, str]) -> str:
    return environ.get("RISK_ENV_FILE") or DEFAULT_FILE


def risk_environment(environ: Optional[Mapping[str, str]] = None) -> tuple[dict[str, str], dict]:
    """Окружение для RiskSettings: os.environ, дополненное RISK_* из .env (окружение важнее).

    Второй элемент — откуда взялась настройка LLM (без значений):
    {"source": "env" | ".env" | "none", "path": путь к прочитанному файлу или None,
     "from_file": имена переменных, взятых из файла}.
    """
    env = dict(os.environ if environ is None else environ)
    path = env_file_path(env)
    file_values: dict[str, str] = {}
    read_path: Optional[str] = None
    try:
        with open(path, encoding="utf-8") as f:
            file_values = parse_env(f.read())
        read_path = os.path.abspath(path)
    except (OSError, UnicodeDecodeError):
        file_values = {}
    taken = {k: v for k, v in file_values.items() if k not in env}
    merged = {**env, **taken}
    llm_in_env = any(k.startswith("RISK_LLM_") and env.get(k) for k in env)
    llm_in_file = any(k.startswith("RISK_LLM_") and v for k, v in taken.items())
    source = "env" if llm_in_env else ".env" if llm_in_file else "none"
    return merged, {"source": source, "path": read_path, "from_file": sorted(taken)}
