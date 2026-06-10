FROM python:3.12-slim AS builder

LABEL maintainer="Security Research Team"
LABEL description="SSRF Auditor v2.0 - SSRF & Infrastructure Disclosure Assessment Framework"
LABEL version="2.0.0"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir aiodns cchardet brotli

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    dnsutils \
    netcat-openbsd \
    procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY . .

RUN mkdir -p /app/results /app/logs && \
    chmod +x /app/src/main.py

RUN addgroup --system ssrf && \
    adduser --system --ingroup ssrf ssrf && \
    chown -R ssrf:ssrf /app

USER ssrf

VOLUME ["/app/results", "/app/logs"]

ENTRYPOINT ["python", "-m", "src.main"]
CMD ["--help"]
