# syntax=docker/dockerfile:1.7
# Multi-stage: build all modules → runtime with Ghidra preinstalled.

# ── stage 1: build ──────────────────────────────────────────────────────────
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /src
COPY pom.xml .
COPY core/ core/
COPY cli/ cli/
COPY api/ api/
COPY worker/ worker/
COPY watcher/ watcher/
COPY bot/ bot/
RUN mvn -T 1C -DskipTests package

# ── stage 2: runtime ────────────────────────────────────────────────────────
FROM eclipse-temurin:17-jdk-jammy
ARG GHIDRA_VERSION=11.1.2
ARG GHIDRA_DATE=20240709
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl unzip ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN curl -fL -o /tmp/ghidra.zip "$GHIDRA_URL" && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra && \
    rm /tmp/ghidra.zip
ENV GHIDRA_HOME=/opt/ghidra
ENV PATH=$GHIDRA_HOME/support:$PATH

WORKDIR /app
COPY --from=build /src/cli/target/mailmite-cli.jar     /app/cli.jar
COPY --from=build /src/api/target/mailmite-api.jar     /app/api.jar
COPY --from=build /src/worker/target/mailmite-worker.jar /app/worker.jar
COPY --from=build /src/watcher/target/mailmite-watcher.jar /app/watcher.jar
COPY --from=build /src/bot/target/mailmite-bot.jar     /app/bot.jar
COPY web/ /web/

# Convenience wrapper: `mailmite <args>` from CLI image.
RUN printf '#!/bin/sh\nexec java -jar /app/cli.jar "$@"\n' > /usr/local/bin/mailmite && \
    chmod +x /usr/local/bin/mailmite

# Default = API. Override CMD to run worker/watcher/bot.
EXPOSE 8080
CMD ["java","-jar","/app/api.jar"]
