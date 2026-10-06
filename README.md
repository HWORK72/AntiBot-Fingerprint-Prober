# 🛡️ AntiBot-Fingerprint-Prober

[🇷🇺 Читать на русском языке (README_RU.md)](README_RU.md)

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111+-009688.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)

High-performance local diagnostic testbed and anti-detect benchmark for scrapers and automated browsers (Playwright, Puppeteer, Selenium, `curl_cffi`, `requests`, `httpx`).

---

## 🎯 What it does

Instead of testing bots on live protected websites (burning residential proxies and getting accounts banned), run them against `localhost`:
1. **L4/L5 TLS Layer:** Binary RFC 8446/5246 Client Hello dissector, RFC 8701 GREASE filter, JA3 and JA4 (FoxIO standard) hash calculation.
2. **L7 HTTP/2 Layer:** RFC 7540 frame decoder, Chrome pseudo-headers ordering validation (`:method`, `:authority`, `:scheme`, `:path`), Akamai H2 Hash, JA4H.
3. **Passive OS (p0f):** TCP initial TTL check (Linux 64 vs Windows 128) vs User-Agent.
4. **JS Runtime Probes:** Detects CDP leaks (`Runtime.enable`, `window.cdc_`), WebWorker context discrepancies, software WebGL (`SwiftShader`), Canvas Poisoning.
5. **Stealth Score Engine:** Generates an integrated 0–100% masking score with code-level remediation steps.

---

## 📊 Benchmark Summary

```
┌──────────────────────────────┬───────────────────────┬───────────────┬──────────────────────────────────────────────────┐
│ Bot / Client Stack           │ Layer                 │ Stealth Score │ Verdict                                          │
├──────────────────────────────┼───────────────────────┼───────────────┼──────────────────────────────────────────────────┤
│ Python Vanilla Client        │ Network (TLS/JA4)     │ 40%           │ BUSTED (Missing GREASE / OpenSSL fingerprint)    │
│ curl_cffi (Chrome 124)       │ Network (TLS/JA4)     │ 100%          │ UNDETECTED (Full Chrome TLS & JA4 emulation)     │
│ Playwright Vanilla Headless  │ Browser (JS Runtime)  │ 0%            │ BUSTED (SwiftShader GPU + navigator.webdriver)   │
│ Playwright Stealth Patched   │ Browser (JS Runtime)  │ 100%          │ UNDETECTED (Patched runtime, ANGLE GPU enabled)  │
└──────────────────────────────┴───────────────────────┴───────────────┴──────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Docker Compose (Recommended)
```bash
docker compose up --build
```
* Dashboard: `http://127.0.0.1:8000`
* TLS Prober Gate: `https://127.0.0.1:8443`
* Swagger Docs: `http://127.0.0.1:8000/docs`

### Local Run
```bash
pip install -r requirements.txt
playwright install chromium
python main.py
```

Run benchmark in another terminal:
```bash
python -m benchmark.runner
```

---

## 📄 License
MIT License