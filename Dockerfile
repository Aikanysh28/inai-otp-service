FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv

# Сервису из внешних пакетов нужен только клиент Redis
RUN pip install --no-cache-dir "redis>=5,<9"

COPY app ./app
COPY run.py attack.py ./

# Непривилегированный пользователь
RUN useradd --create-home --uid 10001 otp && mkdir -p /srv/logs && chown otp /srv/logs
USER otp

EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"

CMD ["python", "run.py"]
