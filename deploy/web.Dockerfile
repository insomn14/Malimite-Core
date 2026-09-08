# syntax=docker/dockerfile:1.7
# Malimite-Core — Web (FastAPI) image.
# Copies a pre-built CLI fat JAR (built on the host via
#   mvn -o -DskipTests package -pl core,cli),
# installs Python deps + Ghidra + JADX, then serves the Python web service
# on the configured port (default 7070).
#
# NOTE: we intentionally do NOT run Maven inside the container — the container
# network is slow/flaky (Maven Central downloads time out). Build the JAR on the
# host against the warm ~/.m2 cache and copy it in here.

# ── stage 1: only the CLI JAR (built on host) ──────────────────────────────
FROM scratch AS cli
COPY cli/target/malimite-cli.jar /cli.jar

# ── stage 2: runtime ───────────────────────────────────────────────────────
FROM python:3.12-slim

ARG GHIDRA_VERSION=11.1.2
ARG GHIDRA_DATE=20240709
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip
ARG JADX_VERSION=1.5.1
ARG JADX_URL=https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip

# System deps + Python build deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl unzip ca-certificates default-jdk-headless && \
    rm -rf /var/lib/apt/lists/*

# Ghidra (iOS Mach-O + Android lib/arm64-v8a/*.so)
RUN curl -fL -o /tmp/ghidra.zip "$GHIDRA_URL" && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra && \
    rm /tmp/ghidra.zip
ENV GHIDRA_HOME=/opt/ghidra
ENV PATH=$GHIDRA_HOME/support:$PATH

# JADX (Android DEX/Java decompilation)
RUN curl -fL -o /tmp/jadx.zip "$JADX_URL" && \
    unzip -q /tmp/jadx.zip -d /opt/jadx && \
    rm /tmp/jadx.zip && \
    chmod +x /opt/jadx/bin/jadx /opt/jadx/bin/jadx-gui || true
ENV JADX_HOME=/opt/jadx
ENV PATH=$JADX_HOME/bin:$PATH

WORKDIR /app

# Python deps
COPY web/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Web app
COPY web/ /app/

# CLI JAR (used by the Python service to run scans as a subprocess)
COPY --from=cli /cli.jar /app/cli.jar
ENV CLI_JAR=/app/cli.jar

# Scan outputs (mount as a volume)
ENV SCAN_DIR=/var/malimite/scans
RUN mkdir -p /var/malimite/scans

# Server defaults (override via env)
ENV HOST=0.0.0.0
ENV PORT=7070

EXPOSE 7070

CMD ["sh", "-c", "python -m uvicorn app.main:app --host $HOST --port $PORT"]
