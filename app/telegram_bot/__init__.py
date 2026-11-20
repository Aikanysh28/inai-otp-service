"""Уведомления о повышении уровня риска через Telegram Bot API."""
import json
import logging
import os
import time
from queue import Full, Queue
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

MAX_RETRY_AFTER = 60  # сек.: не держать очередь дольше, даже если Telegram просит больше


def _json_object(stream) -> dict:
    """Тело ответа Telegram как словарь; что угодно другое (не JSON, список, ...) — {}."""
    try:
        data = json.load(stream)
    except (ValueError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def _retry_after(details: dict, default: float) -> float:
    """Пауза из ответа 429 (parameters.retry_after), если это разумное число."""
    parameters = details.get("parameters")
    value = parameters.get("retry_after") if isinstance(parameters, dict) else None
    if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
        return min(value, MAX_RETRY_AFTER)
    return default


class TelegramAlerts:
    def __init__(self, token: str, chat_id: str):
        self._url = f"https://api.telegram.org/bot{token}/sendMessage"
        self._chat_id = chat_id
        self._messages = Queue(maxsize=256)
        Thread(target=self._deliver, name="telegram-alerts", daemon=True).start()

    @classmethod
    def from_env(cls):
        token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        chat = os.getenv("TELEGRAM_CHAT_ID", "").strip()
        if token and chat:
            return cls(token, chat)
        if token or chat:
            logger.warning("Для Telegram нужны TELEGRAM_BOT_TOKEN и TELEGRAM_CHAT_ID")
        return None

    def enqueue(self, assessment):
        text = (f"OTP · риск {assessment.level}\nIP: {assessment.ip}\n"
                f"Оценка: {assessment.score}\n"
                + "\n".join(f"• {reason.title} (+{reason.points})"
                            for reason in assessment.reasons))
        try:
            self._messages.put_nowait(text)
        except Full:
            logger.warning("Очередь Telegram заполнена, уведомление пропущено")

    def _deliver(self):
        while True:
            text = self._messages.get()
            payload = json.dumps({"chat_id": self._chat_id, "text": text}).encode()
            request = Request(self._url, data=payload,
                              headers={"Content-Type": "application/json"})
            try:
                self._send(request)
            except Exception as error:  # noqa: BLE001
                # Сбой одного сообщения не останавливает поток. В лог — только тип ошибки:
                # в тексте исключения может оказаться URL с токеном бота.
                logger.warning("Сбой отправки уведомления Telegram: %s", type(error).__name__)
            finally:
                self._messages.task_done()

    def _send(self, request):
        for attempt in range(3):
            delay = 2 ** attempt
            try:
                with urlopen(request, timeout=5) as response:
                    if not _json_object(response).get("ok"):
                        logger.warning("Telegram отклонил уведомление")
                    return
            except HTTPError as error:
                details = _json_object(error)
                logger.warning("Telegram HTTP %s: %s", error.code, details.get("description", ""))
                if error.code != 429 and error.code < 500:
                    return
                if error.code == 429:
                    delay = _retry_after(details, delay)
            except (OSError, ValueError) as error:
                logger.warning("Ошибка доставки Telegram: %s", type(error).__name__)
            if attempt < 2:
                time.sleep(delay)
