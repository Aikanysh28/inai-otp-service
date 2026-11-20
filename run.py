"""Запуск сервиса одной командой:  python run.py

Внешних зависимостей нет — только стандартная библиотека Python 3.10+.
"""
from app.config import Settings
from app.main import create_server

if __name__ == "__main__":
    settings = Settings()
    server = create_server(settings)
    storage = f"Redis ({settings.redis_url})" if settings.redis_url else "memory"
    print(f"OTP service listening on http://{settings.host}:{settings.port}  storage: {storage}")
    print(f"Dashboard: http://127.0.0.1:{settings.port}/dashboard")
    print(f"Security log: {settings.log_dir}/security.log   SMS (codes): {settings.log_dir}/sms.log")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
