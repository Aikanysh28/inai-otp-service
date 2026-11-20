"""Тестовый SMS-транспорт: «доставка» кода в outbox-файл в формате перехвата жюри."""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Callable

# Asia/Bishkek — UTC+6 без перехода на летнее время; фиксированное смещение не требует tzdata.
BISHKEK_TZ = timezone(timedelta(hours=6), "Asia/Bishkek")


class SmsGateway:
    """Дописывает каждую выдачу строкой JSON в outbox-файл и (по желанию) печатает в консоль.

    Формат задан жюри: {"ts": "2026-11-21T09:00:00+06:00", "msisdn": "...", "code": "012345"}.
    capture_delivery в сценариях жюри берёт последнюю строку файла для номера.
    Сервис этот файл не читает.
    """

    def __init__(self, outbox_path: str, clock: Callable[[], float] = time.time,
                 echo: bool = True):
        self.path = outbox_path
        self._clock = clock
        self._echo = echo
        self._mutex = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(outbox_path)), exist_ok=True)

    def deliver(self, msisdn: str, code: str) -> None:
        ts = datetime.fromtimestamp(self._clock(), BISHKEK_TZ).isoformat(timespec="seconds")
        line = json.dumps({"ts": ts, "msisdn": msisdn, "code": code}, ensure_ascii=False)
        with self._mutex, open(self.path, "a", encoding="utf-8") as outbox:
            outbox.write(line + "\n")
        if self._echo:
            print(f"[SMS] {ts} to=+{msisdn} code={code}", flush=True)
