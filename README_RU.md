# 🛡️ AntiBot-Fingerprint-Prober

[🇬🇧 Read in English (README.md)](README.md)

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![Lua 5.4](https://img.shields.io/badge/Lua-5.4_Edge_Engine-000080.svg)](https://www.lua.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111+-009688.svg)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)

Высокопроизводительный локальный диагностический стенд и бенчмарк отпечатков для автоматизированных браузеров и скрейперов (Playwright, Puppeteer, Selenium, `curl_cffi`, `requests`, `httpx`).

---

## 🎯 Архитектура и модули

1. **L4/L5 TLS Диссектор (`network/`):** Бинарный разбор пакета Client Hello (RFC 8446/5246), фильтрация GREASE (RFC 8701), расчет отпечатков JA3 и FoxIO JA4, пассивный p0f-анализ TCP TTL.
2. **Встроенный Lua 5.4 движок (`lua_engine/` и `scoring/lua_bridge.py`):** Изолированная песочница `lupa` для высокоскоростной классификации TLS-сигнатур (`signatures.lua`) и L7-эвристик заголовков/GPU (`heuristics.lua`).
3. **L7 HTTP/2 Диссектор (`network/h2_parser.py`):** Декодирование фреймов RFC 7540, проверка порядка псевдо-заголовков Chrome, расчет Akamai H2 Hash и JA4H.
4. **JS Runtime зонды (`client_probes/`):** Перехват утечек CDP (`Runtime.enable`, `window.cdc_`, токены V8 `Error.stack`), рассинхрона WebWorker, софтверного WebGL (`SwiftShader`), шумов Canvas и рендеринга `OfflineAudioContext`.
5. **Сервер и хранение (`api/`, `storage/`):** Двухстековый HTTP/HTTPS сервер с Redis-брокером сессий и PostgreSQL (SQLAlchemy 2.0).

---

## 🚀 Быстрый старт

### Запуск сквозного бенчмарка одной командой

    pip install -r requirements.txt
    playwright install chromium
    python main.py --benchmark

### Запуск сервера и тестов раздельно

    python main.py
    python -m benchmark.runner

### Docker Compose

    docker compose up --build

* Дашборд: `https://127.0.0.1:8443` / `http://127.0.0.1:8000`
* Swagger документация: `http://127.0.0.1:8000/docs`