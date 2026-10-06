# 🛡️ AntiBot-Fingerprint-Prober

[🇬🇧 Read in English (README.md)](README.md)

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111+-009688.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)

Высокопроизводительный локальный стенд и бенчмарк для проверки качества маскировки ботов, скрейперов и автоматизированных браузеров (Playwright, Puppeteer, Selenium, `curl_cffi`, `requests`, `httpx`).

---

## 🎯 Назначение стенда

Стенд решает проблему сжигания дорогих прокси и банов аккаунтов при тестировании на боевых сайтах (Cloudflare, Akamai, DataDome). Вы запускаете бота на `localhost` и за доли секунды видите все сетевые и браузерные пробоины:
1. **L4/L5 Уровень TLS:** Бинарный разбор пакета Client Hello (RFC 8446/5246), фильтрация GREASE (RFC 8701), расчет отпечатков JA3 и JA4 (FoxIO).
2. **L7 Уровень HTTP/2:** Декодирование фреймов RFC 7540, проверка строгого порядка псевдо-заголовков Chrome (`:method`, `:authority`, `:scheme`, `:path`), расчет Akamai H2 Hash и JA4H.
3. **Пассивный OS (p0f):** Сверка начального TCP TTL (ядро Linux 64 против Windows 128) с операционной системой в User-Agent.
4. **JS Runtime зонды:** Детектирование утечек CDP (`Runtime.enable`, `window.cdc_`), изоляция WebWorker, выявление виртуального WebGL (`SwiftShader`), замер Canvas Poisoning.
5. **Движок скоринга:** Оценка маскировки от 0% до 100% с выдачей точных инструкций по устранению уязвимостей в коде.

---

## 📊 Результаты бенчмарка

```
┌──────────────────────────────┬───────────────────────┬───────────────┬──────────────────────────────────────────────────┐
│ Бот / Стек Клиента           │ Уровень               │ Stealth Score │ Вердикт                                          │
├──────────────────────────────┼───────────────────────┼───────────────┼──────────────────────────────────────────────────┤
│ Python Vanilla Client        │ Network (TLS/JA4)     │ 40%           │ BUSTED (Отсутствие GREASE / Отпечаток OpenSSL)   │
│ curl_cffi (Chrome 124)       │ Network (TLS/JA4)     │ 100%          │ UNDETECTED (Полная эмуляция TLS и JA4 Chrome)    │
│ Playwright Vanilla Headless  │ Browser (JS Runtime)  │ 0%            │ BUSTED (SwiftShader GPU + navigator.webdriver)   │
│ Playwright Stealth Patched   │ Browser (JS Runtime)  │ 100%          │ UNDETECTED (Автоматизация скрыта, GPU ANGLE)     │
└──────────────────────────────┴───────────────────────┬───────────────┬──────────────────────────────────────────────────┘
```

---

## 🚀 Быстрый старт

### Через Docker Compose (Рекомендуется)
```bash
docker compose up --build
```
* Дашборд: `http://127.0.0.1:8000`
* Порт TLS-инспектора: `https://127.0.0.1:8443`
* Swagger документация: `http://127.0.0.1:8000/docs`

### Локальный запуск
```bash
pip install -r requirements.txt
playwright install chromium
python main.py
```

Запуск бенчмарка во втором терминале:
```bash
python -m benchmark.runner
```

---

## 📄 Лицензия
MIT License