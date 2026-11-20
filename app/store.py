"""Key-value хранилища с TTL: в памяти процесса и в Redis.

Оба реализуют один интерфейс:
    get(key) / set(key, value, ttl) / delete(key) / lock(name)

lock(name) — взаимное исключение для секции «прочитать-проверить-записать».
В памяти это threading-блокировки, в Redis — распределённая блокировка
(SET NX PX + снятие через WATCH/MULTI), поэтому атомарность сохраняется
даже при нескольких экземплярах сервиса на одном Redis.
"""
from __future__ import annotations

import json
import secrets
import threading
import time
import zlib
from contextlib import contextmanager
from typing import Any, Callable, Iterator, Optional


class StoreUnavailable(Exception):
    """Хранилище недоступно или блокировку не удалось взять вовремя (-> HTTP 503)."""


class MemoryStore:
    LOCK_STRIPES = 64
    CLEANUP_EVERY = 1000  # раз в N записей удаляем просроченные ключи

    def __init__(self, clock: Callable[[], float] = time.time):
        self._clock = clock
        self._data: dict[str, tuple[Any, Optional[float]]] = {}
        self._mutex = threading.Lock()
        # «Полосатые» блокировки: фиксированный набор, номер выбирается по хешу имени.
        # Память не растёт с числом номеров, а разные номера в основном не мешают друг другу.
        self._stripes = [threading.Lock() for _ in range(self.LOCK_STRIPES)]
        self._writes = 0

    name = "memory"

    def get(self, key: str) -> Any:
        with self._mutex:
            item = self._data.get(key)
            if item is None:
                return None
            value, expires_at = item
            if expires_at is not None and self._clock() >= expires_at:
                del self._data[key]
                return None
            return value

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        with self._mutex:
            expires_at = self._clock() + ttl if ttl is not None else None
            self._data[key] = (value, expires_at)
            self._writes += 1
            if self._writes % self.CLEANUP_EVERY == 0:
                self._cleanup_locked()

    def delete(self, key: str) -> None:
        with self._mutex:
            self._data.pop(key, None)

    @contextmanager
    def lock(self, name: str) -> Iterator[None]:
        stripe = self._stripes[zlib.crc32(name.encode()) % self.LOCK_STRIPES]
        with stripe:
            yield

    def _cleanup_locked(self) -> None:
        now = self._clock()
        expired = [k for k, (_, exp) in self._data.items() if exp is not None and now >= exp]
        for key in expired:
            del self._data[key]

    def ping(self) -> bool:
        return True


class RedisStore:
    """Хранилище в Redis. Значения сериализуются в JSON, TTL — нативный (PX)."""

    name = "redis"

    def __init__(self, client, prefix: str = "otp:", lock_ttl: float = 5.0, lock_wait: float = 5.0):
        self.r = client
        self.prefix = prefix
        self.lock_ttl = lock_ttl
        self.lock_wait = lock_wait

    @classmethod
    def from_url(cls, url: str, **kwargs) -> "RedisStore":
        try:
            import redis  # импорт только если включён Redis: без него сервис работает на stdlib
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("REDIS_URL задан, но пакет redis не установлен: pip install redis") from e
        client = redis.Redis.from_url(url, socket_timeout=3, socket_connect_timeout=3)
        return cls(client, **kwargs)

    def _k(self, key: str) -> str:
        return self.prefix + key

    @contextmanager
    def _errors(self) -> Iterator[None]:
        try:
            yield
        except StoreUnavailable:
            raise
        except Exception as e:  # ConnectionError, TimeoutError и т.п. из redis-py
            if type(e).__module__.startswith("redis"):
                raise StoreUnavailable(f"redis error: {e}") from e
            raise

    def get(self, key: str) -> Any:
        with self._errors():
            raw = self.r.get(self._k(key))
        return None if raw is None else json.loads(raw)

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        px = max(1, int(ttl * 1000)) if ttl is not None else None
        with self._errors():
            self.r.set(self._k(key), json.dumps(value), px=px)

    def delete(self, key: str) -> None:
        with self._errors():
            self.r.delete(self._k(key))

    @contextmanager
    def lock(self, name: str) -> Iterator[None]:
        key = self._k("lock:" + name)
        token = secrets.token_hex(16)
        deadline = time.monotonic() + self.lock_wait
        with self._errors():
            # TTL у блокировки защищает от «вечного» замка, если процесс упал внутри секции.
            while not self.r.set(key, token, nx=True, px=int(self.lock_ttl * 1000)):
                if time.monotonic() >= deadline:
                    raise StoreUnavailable(f"lock {name!r} timeout")
                time.sleep(0.002)
        try:
            yield
        finally:
            self._release(key, token)

    def _release(self, key: str, token: str) -> None:
        # Удаляем блокировку, только если она всё ещё наша (compare-and-delete через WATCH).
        import redis

        with self._errors(), self.r.pipeline() as pipe:
            try:
                pipe.watch(key)
                current = pipe.get(key)
                if current is not None and current.decode() == token:
                    pipe.multi()
                    pipe.delete(key)
                    pipe.execute()
                else:
                    pipe.unwatch()
            except redis.WatchError:
                pass  # ключ изменился => блокировка уже не наша (истекла)

    def ping(self) -> bool:
        with self._errors():
            return bool(self.r.ping())
