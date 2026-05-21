# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# VaultX Backend Dockerfile
# Python 3.12 + All Security Tools
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

FROM python:3.12-slim-bookworm

# Build args
ARG NUCLEI_VERSION=3.2.6
ARG AMASS_VERSION=v4.2.0
ARG SUBFINDER_VERSION=v2.6.6

LABEL maintainer="VaultX Security Platform"
LABEL version="1.0.0"

# ─── System dependencies ──────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Base tools
    curl wget git ca-certificates gnupg2 \
    # Nmap
    nmap \
    # Nikto
    nikto \
    # SQLmap
    sqlmap \
    # WhatWeb
    whatweb \
    # Build tools
    build-essential libpq-dev \
    # PDF generation
    weasyprint \
    # Network tools
    dnsutils iputils-ping netcat-openbsd \
    # Process management
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# ─── Go-based tools ───────────────────────────────
RUN wget -q https://go.dev/dl/go1.22.0.linux-amd64.tar.gz -O /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin

# Nuclei
RUN wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -O /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin/ && \
    rm /tmp/nuclei.zip && \
    nuclei -update-templates -silent || true

# Subfinder
RUN wget -q "https://github.com/projectdiscovery/subfinder/releases/download/${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" -O /tmp/subfinder.zip && \
    unzip /tmp/subfinder.zip -d /usr/local/bin/ && \
    rm /tmp/subfinder.zip

# Amass
RUN wget -q "https://github.com/owasp-amass/amass/releases/download/${AMASS_VERSION}/amass_Linux_amd64.zip" -O /tmp/amass.zip && \
    unzip /tmp/amass.zip -d /tmp/amass/ && \
    mv /tmp/amass/amass_Linux_amd64/amass /usr/local/bin/ && \
    rm -rf /tmp/amass*

# ─── Python setup ─────────────────────────────────
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# ─── Create directories ───────────────────────────
RUN mkdir -p /app/reports /app/templates /workspace

# ─── Security hardening ───────────────────────────
RUN useradd -r -s /bin/false -u 1001 vaultx && \
    chown -R vaultx:vaultx /app /workspace

# Don't run as root (except nmap which needs NET_RAW)
USER vaultx

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
