FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2 \
    && rm -rf /var/lib/apt/lists/*

COPY core/ /app/core/
COPY network/ /app/network/
COPY client_probes/ /app/client_probes/
COPY scoring/ /app/scoring/
COPY storage/ /app/storage/
COPY api/ /app/api/
COPY ui/ /app/ui/
COPY benchmark/ /app/benchmark/
COPY main.py /app/main.py

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
    pydantic \
    pydantic-settings \
    python-dotenv \
    rich \
    hpack \
    fastapi \
    "uvicorn[standard]" \
    jinja2 \
    cryptography \
    sqlalchemy \
    asyncpg \
    redis \
    curl_cffi \
    playwright && \
    playwright install --with-deps chromium

EXPOSE 8000 8443

CMD ["python", "main.py"]