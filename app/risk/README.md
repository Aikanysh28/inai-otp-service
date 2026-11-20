# Модуль оценки рисков (`app/risk`)

Модуль **только наблюдает**: получает события журнала безопасности, считает риск по каждому IP
и отдаёт данные для вкладки «Риски». На ответы `/otp/send` и `/otp/verify` он не влияет никак.
Уровень `high` — это тревога и подпись «в боевом режиме было бы отклонено», а не отказ.

Только стандартная библиотека. Всё состояние в памяти, под одним `threading.Lock`.
Точка входа `RiskEngine.sink(record, msisdn=None, ts=None)` никогда не бросает исключений
(ошибки считаются в `engine.errors`). Полный номер не сохраняется и не попадает в ответы:
из него сразу получаются `msisdn_id` (HMAC-SHA256, 16 hex), последние 4 цифры и маска `+996700***456`.

## Файлы

| Файл | Что внутри |
|---|---|
| `config.py` | `RiskSettings`: все пороги; `RiskSettings.from_env()` читает `RISK_<ПОЛЕ>` |
| `schema.py` | `RiskEvent`, `EVENT_MAP` (текущие имена журнала → целевые), `normalize()`, `make_msisdn_id()`, `mask_msisdn()` |
| `signals.py` | `WindowStats`, `Signal`, признаки — чистые функции |
| `engine.py` | `RiskEngine`: `sink`, `ingest`, тревоги, запросы `assess / overview / timeline / top_ips / ip_detail / scatter / alerts / meta` |
| `simulate.py` | `FakeClock`, `Traffic` (генератор событий в текущем формате журнала), `demo_story` |
| `demo.py` | консольное демо и выгрузка фикстур |
| `fixtures/` | JSON-ответы движка после демо-сюжета, для вёрстки вкладки |

## Признаки (по одному IP, окно 10 минут)

| `name` | Условие | Баллы |
|---|---|---|
| `fan_out` | больше 5 разных номеров в send / больше 15 | +20 / +40 |
| `sequential` | не меньше 5 номеров, и больше чем у 50% есть «сосед» (последние 4 цифры отличаются на 1..10) | +25 |
| `no_conversion` | `send_ok` ≥ 5 и подтверждено меньше 10% | +25 |
| `fail_rate` | попыток verify ≥ 5, доля неудачных (fail + locked) ≥ 50% | +25 |
| `new_ip` | номера, раньше подтверждённые с других IP (за 30 суток), а с этого — нет | +15 |
| `hammering_locked` | `verify_locked` ≥ 3 | +15 |
| `ip_limited` | хотя бы один `ip_rate_limited` | +15 |
| `night` | последнее событие в 01:00–05:59 по Бишкеку (UTC+6) | +10 |

Балл — сумма, но не больше 100. Уровни: `low` < 30 ≤ `medium` < 60 ≤ `high`.
Подпись действия: `low` → `allow` «обычный режим», `medium` → `stricter_delay` «задержки строже (×2)»,
`high` → `deny` «отказ (429) и тревога». Тревога создаётся, только когда уровень IP **повышается**.

У каждого признака есть объяснение с цифрами, например «коды запрошены на 37 номеров за 10 мин».

## Как читать цифры

| Поле | Что значит |
|---|---|
| `score`, `level`, `reasons` в `/api/risk/ips` и `/api/risk/ip` | оценка IP **на момент его последней активности**. Атака не исчезает из топа сразу после окончания; IP держится в списке час после последнего события |
| `current_score` там же | балл **сейчас**: события за последние 10 минут относительно текущего времени. Через 10 минут тишины он падает до 0. Если `score` = 90, а `current_score` = 0, IP был опасен, но затих |
| `assess(ip)` (метод движка) | то же, что `current_score`, с причинами |
| `last_seen` | время последнего события IP (epoch, UTC) |
| `sparkline` | событий IP по минутам за последние 10 минут, последняя минута справа |
| `overview.ips_high` / `ips_medium` | сколько IP **побывали** на этом уровне за окно запроса (`window`, по умолчанию час). IP считается один раз, по высшему уровню |
| `overview.threat_level` | `high`, если `ips_high > 0`; иначе `medium`, если `ips_medium > 0`; иначе `low` |
| `overview.sms_suspicious` | SMS, выданные IP, который в момент выдачи уже был `high`. `sms_cost_suspicious` = это число × `RISK_SMS_PRICE` |
| `overview.conversion` | `verify_ok / send_ok` за окно; `null`, если отправок не было |
| `timeline` | счётчики по шагам (`step` кратен минуте), включая пустые шаги. `low` / `medium` / `high` — сколько событий пришло от IP с этим уровнем |
| `alerts` | создаются только при **повышении** уровня IP (low→medium, medium→high). Новые сверху; `since_id` — получить только новые |
| `meta.mode` | `async` — события идут через очередь; `sync` — напрямую (тесты, сценарии). `queue_size`, `dropped` (отброшено при переполнении очереди), `errors` (исключения внутри модуля) — для контроля здоровья |

Все времена — epoch-секунды UTC. Время Бишкека (UTC+6) нужно только для признака `night` и при отображении.

## Запуск

```bash
python3 -m app.risk.demo                          # сюжет на подменённых часах, сводка и тревоги
python3 -m app.risk.demo --dump app/risk/fixtures # плюс JSON-фикстуры
python3 -m unittest tests.test_risk               # тесты модуля (только stdlib)
python3 -m unittest tests.test_risk_api           # подключение и API
python3 -m pytest -q tests/test_risk.py tests/test_risk_api.py
```

Переменные окружения: `RISK_<ИМЯ_ПОЛЯ>`, например `RISK_WINDOW=600`, `RISK_SMS_PRICE=1.0`,
`RISK_CURRENCY=сом`; `RISK_ID_SECRET` — ключ для `msisdn_id`. Если ключ не задан и не передан
в `RiskEngine(id_key=...)`, он случайный на каждый запуск.

## Подключение к сервису

```
OTPService ─► SecurityLog.event() ─► security.log, дашборд (без изменений)
                    │ add_sink: fn(dict(record), msisdn=<номер до маски>, ts=<clock()>)
                    ▼
            RiskEngine.async_sink ─► очередь ─► поток risk-worker ─► RiskEngine.sink
                                                                   ▼
                                                     GET /api/risk/*  (OTPApi, risk=engine)
```

* `app/main.py`, `build_risk()`: создаёт `RiskEngine(RiskSettings.from_env(), clock=service.clock, id_key=...)`,
  запускает обработчик (`start_worker()`) и подписывает его на журнал (`SecurityLog.add_sink`).
  Если при создании что-то упало, пишет строку в stderr, и сервис работает без модуля.
* Асинхронный синк в потоке HTTP-запроса только делает `put_nowait` в очередь (10 000 событий).
  При переполнении событие отбрасывается (`dropped`), ответ пользователю не ждёт.
* `SecurityLog.event()` вызывает подписчиков после записи в файл и историю, каждый — в `try/except`.
  Ответы `/otp/send` и `/otp/verify` от модуля не зависят: это проверяет `tests/test_risk_api.py`.
* `OTPApi(service, token, risk=None)`: без движка маршруты отвечают 503 `risk_disabled`.

## Переменные окружения

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `RISK_ENABLED` | `1` | `0` — модуль не создаётся, `/api/risk/*` → 503 `risk_disabled` |
| `RISK_ID_SECRET` | пусто | ключ для `msisdn_id`; если не задан — `HMAC-SHA256(OTP_SECRET, "risk-id")` |
| `RISK_<ПОЛЕ>` | см. `config.py` | любой порог, например `RISK_WINDOW=600`, `RISK_SMS_PRICE=1.5`, `RISK_CURRENCY=сом`. Некорректное значение — модуль не запускается, сервис работает |

## Маршруты (все `GET`, авторизация как у `/api/security/events`)

Токен `DASHBOARD_TOKEN` передаётся в `?token=` или в заголовке `X-Dashboard-Token`; без него — 401 `{"status":"unauthorized"}`.
Неверный параметр — 400 `{"status":"bad_request","error":"<параметр> must be ..."}`.
Модуль выключен — 503 `{"status":"risk_disabled"}`; исключение внутри модуля — 503 `{"status":"risk_error"}`.
Все ответы с `Cache-Control: no-store`. Полных номеров, кодов и HMAC в ответах нет.

| Маршрут | Параметры (по умолчанию; диапазон) | Ответ |
|---|---|---|
| `/api/risk/overview` | `window` (3600; 60–86400) | объект-сводка |
| `/api/risk/timeline` | `window` (3600; 60–86400), `step` (60; 60–3600) | массив шагов |
| `/api/risk/ips` | `limit` (20; 1–200), `min_level` (`low`; `low`/`medium`/`high`) | массив IP |
| `/api/risk/ip` | `ip` (обязателен; 1–64 символа) | объект; неизвестный IP — 404 `{"status":"not_found"}` |
| `/api/risk/scatter` | `window` (1800; 60–86400) | массив точек |
| `/api/risk/alerts` | `limit` (50; 1–500), `since_id` (0; ≥ 0) | массив тревог, новые сверху |
| `/api/risk/meta` | — | настройки, признаки, счётчики |

Примеры (полные — в `fixtures/`):

```jsonc
// GET /api/risk/overview
{"now": 1795163280.57, "window": 3600, "threat_level": "high", "ips_active": 41, "ips_medium": 1,
 "ips_high": 2, "alerts": 5, "sms_sent": 136, "sms_suspicious": 80, "sms_cost_suspicious": 80.0,
 "currency": "сом", "conversion": 0.324}

// GET /api/risk/timeline?window=120  — элемент на каждую минуту
[{"t": 1795163160, "low": 3, "medium": 0, "high": 0, "send_ok": 1, "send_rejected": 0,
  "verify_ok": 1, "verify_fail": 0, "verify_locked": 0, "ip_rate_limited": 0}, ...]

// GET /api/risk/ips?min_level=medium
[{"ip": "45.13.7.200", "score": 90, "level": "high", "would_action": "deny",
  "would_action_text": "отказ (429) и тревога",
  "reasons": [{"name": "fan_out", "points": 40, "detail": "коды запрошены на 40 номеров за 10 мин"}, ...],
  "numbers": 40, "sms_sent": 40, "verify_attempts": 0, "last_seen": 1795163118.412,
  "current_score": 0, "sparkline": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}]

// GET /api/risk/ip?ip=45.13.7.200 — поля из ips + first_seen, stats, sms_cost, currency, events
{"ip": "45.13.7.200", "score": 90, "level": "high", "current_score": 0, "first_seen": 1795162980.1,
 "stats": {"numbers": 40, "sms_sent": 40, "sms_rejected": 0, "verify_ok": 0, "verify_fail": 0,
           "verify_expired": 0, "verify_locked": 0, "ip_limited": 0},
 "sms_cost": 40.0, "currency": "сом",
 "events": [{"ts": 1795163118.412, "event": "send_ok", "msisdn": "+996700***239", "status": 200,
             "reason": null, "scope": null, "new_ip": false}, ...]}

// GET /api/risk/scatter
[{"t": 1795162980.1, "tail": 1200, "ip": "45.13.7.200", "level": "low", "event": "send_ok"}, ...]

// GET /api/risk/alerts
[{"id": 3, "ts": 1795162991.6, "ip": "45.13.7.200", "severity": "high", "score": 70,
  "reasons": [...], "would_action": "deny",
  "message": "IP 45.13.7.200: коды запрошены на 6 номеров за 10 мин; 100% номеров идут подряд (6 из 6); 6 SMS отправлено, подтверждено 0. В боевом режиме: отказ (429) и тревога."}]

// GET /api/risk/meta
{"now": 1795163280.57, "mode": "async", "observe_only": true, "queue_size": 0, "window": 600,
 "tz_offset_hours": 6, "levels": {"medium_at": 30, "high_at": 60, "max_score": 100},
 "actions": {...}, "signals": [{"name": "fan_out", "points": [20, 40], "description": "..."}, ...],
 "sms_price": 1.0, "currency": "сом", "ingested": 2052, "ignored": 0, "errors": 0,
 "ips_tracked": 1, "alerts_total": 2, "dropped": 0}
```
