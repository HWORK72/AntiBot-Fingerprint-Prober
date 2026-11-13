# 🛡️ AntiBot-Fingerprint-Prober

[🇷🇺 Читать документацию на русском языке (README_RU.md)](README_RU.md)

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![Lua 5.4](https://img.shields.io/badge/Lua-5.4_Edge_Engine-000080.svg)](https://www.lua.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111+-009688.svg)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)

High-performance local diagnostic testbed and fingerprint telemetry benchmarker for scrapers and automated browsers (Playwright, Puppeteer, Selenium, `curl_cffi`, `requests`, `httpx`).

---

## 🎯 Architecture & Core Modules

1. **L4/L5 TLS Dissector (`network/`):** Binary RFC 8446/5246 Client Hello parser, RFC 8701 GREASE filter, JA3 and FoxIO JA4 calculation, passive TCP TTL OS checks.
2. **Embedded Lua 5.4 Edge Engine (`lua_engine/` & `scoring/lua_bridge.py`):** Sandboxed `lupa` runtime executing low-latency Lua signature classification (`signatures.lua`) and L7 Client Hints / cross-layer GPU-OS consistency heuristics (`heuristics.lua`).
3. **L7 HTTP/2 Parser (`network/h2_parser.py`):** RFC 7540 frame decoder, Chrome pseudo-headers ordering check, Akamai H2 Hash, and JA4H.
4. **JS Runtime Telemetry (`client_probes/`):** Captures CDP leaks (`Runtime.enable`, `window.cdc_`, V8 `Error.stack` tokens), WebWorker context drift, WebGL software rasterization (`SwiftShader`), Canvas geometry/poisoning, and `OfflineAudioContext` rendering.
5. **Dual-Stack Server & Persistence (`api/`, `storage/`):** Async HTTP/HTTPS TLS-relay architecture with Redis ephemeral handshake cache and PostgreSQL (SQLAlchemy 2.0) audit persistence.

---

## 🚀 Quick Start

### Single-Command Integrated Benchmark

    pip install -r requirements.txt
    playwright install chromium
    python main.py --benchmark

### Persistent Server + Separate Benchmark

    python main.py
    python -m benchmark.runner

### Docker Compose

    docker compose up --build

* Dashboard: `https://127.0.0.1:8443` / `http://127.0.0.1:8000`
* Swagger Docs: `http://127.0.0.1:8000/docs`