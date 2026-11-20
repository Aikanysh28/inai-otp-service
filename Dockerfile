FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv

# Сервису из внешних пакетов нужен только клиент Redis
RUN pip install --no-cache-dir "redis>=5,<9"

COPY app ./app
COPY scenarios ./scenarios
COPY run.py attack.py run_scenarios.py ./

# Процесс работает от root внутри контейнера намеренно: outbox/ монтируется с хоста
# (жюри читает outbox/sms.jsonl в корне репозитория), а у непривилегированного UID
# контейнера на Linux-хосте не было бы прав записи в эту папку.
RUN mkdir -p /srv/logs /srv/outbox

EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"

CMD ["python", "run.py"]
