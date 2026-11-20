"""Key-value хранилища с TTL: в памяти процесса и в Redis.

Оба реализуют протокол Store:
    get(key) / set(key, value, ttl) / delete(key) / lock(name) / ping()

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
from typing import Any, Callable, ContextManager, Iterator, Optional, Protocol

try:  # redis нужен только для RedisStore: без него сервис работает на stdlib
    import redis
except ImportError:  # pragma: no cover
    redis = None


class StoreUnavailable(Exception):
    """Хранилище недоступно или блокировку не удалось взять вовремя (-> HTTP 503)."""


class Store(Protocol):
    name: str

    def get(self, key: str) -> Any: ...

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None: ...

    def delete(self, key: str) -> None: ...

    def lock(self, name: str) -> ContextManager[None]: ...

    def ping(self) -> bool: ...


class MemoryStore:
    """Хранилище в памяти процесса. TTL отсчитывается по переданным часам."""

    name = "memory"
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

    def get(self, key: str) -> Any:
        with self._mutex:
            item = self._data.get(key)
            if item is None:
                return None
            value, expires_at = item
            if self._expired(expires_at, self._clock()):
                del self._data[key]
                return None
            return value

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        with self._mutex:
            expires_at = self._clock() + ttl if ttl is not None else None
            self._data[key] = (value, expires_at)
            self._writes += 1
            if self._writes % self.CLEANUP_EVERY == 0:
                self._remove_expired()

    def delete(self, key: str) -> None:
        with self._mutex:
            self._data.pop(key, None)

    @contextmanager
    def lock(self, name: str) -> Iterator[None]:
        stripe = self._stripes[zlib.crc32(name.encode()) % self.LOCK_STRIPES]
        with stripe:
            yield

    def ping(self) -> bool:
        return True

    @staticmethod
    def _expired(expires_at: Optional[float], now: float) -> bool:
        return expires_at is not None and now >= expires_at

    def _remove_expired(self) -> None:
        """Вызывается под self._mutex."""
        now = self._clock()
        for key in [k for k, (_, exp) in self._data.items() if self._expired(exp, now)]:
            del self._data[key]


class RedisStore:
    """Хранилище в Redis. Значения сериализуются в JSON, TTL — нативный (PX)."""

    name = "redis"
    LOCK_POLL_INTERVAL = 0.002

    def __init__(self, client, prefix: str = "otp:", lock_ttl: float = 5.0, lock_wait: float = 5.0):
        if redis is None:  # pragma: no cover
            raise RuntimeError("Для Redis нужен пакет redis: pip install redis")
        self.r = client
        self.prefix = prefix
        self.lock_ttl = lock_ttl
        self.lock_wait = lock_wait

    @classmethod
    def from_url(cls, url: str, **kwargs) -> "RedisStore":
        if redis is None:  # pragma: no cover
            raise RuntimeError("REDIS_URL задан, но пакет redis не установлен: pip install redis")
        client = redis.Redis.from_url(url, socket_timeout=3, socket_connect_timeout=3)
        return cls(client, **kwargs)

    def _key(self, key: str) -> str:
        return self.prefix + key

    @contextmanager
    def _translate_errors(self) -> Iterator[None]:
        """Любая ошибка Redis (соединение, таймаут, ...) превращается в StoreUnavailable."""
        try:
            yield
        except redis.RedisError as e:
            raise StoreUnavailable(f"redis error: {e}") from e

    def get(self, key: str) -> Any:
        with self._translate_errors():
            raw = self.r.get(self._key(key))
        return None if raw is None else json.loads(raw)

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        px = max(1, int(ttl * 1000)) if ttl is not None else None
        with self._translate_errors():
            self.r.set(self._key(key), json.dumps(value), px=px)

    def delete(self, key: str) -> None:
        with self._translate_errors():
            self.r.delete(self._key(key))

    @contextmanager
    def lock(self, name: str) -> Iterator[None]:
        key = self._key("lock:" + name)
        token = secrets.token_hex(16)
        self._acquire(key, token, name)
        try:
            yield
        finally:
            self._release(key, token)

    def ping(self) -> bool:
        with self._translate_errors():
            return bool(self.r.ping())

    def _acquire(self, key: str, token: str, name: str) -> None:
        deadline = time.monotonic() + self.lock_wait
        with self._translate_errors():
            # TTL у блокировки защищает от «вечного» замка, если процесс упал внутри секции.
            while not self.r.set(key, token, nx=True, px=int(self.lock_ttl * 1000)):
                if time.monotonic() >= deadline:
                    raise StoreUnavailable(f"lock {name!r} timeout")
                time.sleep(self.LOCK_POLL_INTERVAL)

    def _release(self, key: str, token: str) -> None:
        """Снять блокировку, только если она всё ещё наша (compare-and-delete через WATCH)."""
        with self._translate_errors(), self.r.pipeline() as pipe:
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
