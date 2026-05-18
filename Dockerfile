# ── Stage 1: build frontend ──────────────────────────────────────────────────
FROM node:20-slim AS frontend-builder

RUN npm install -g pnpm

WORKDIR /app/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY frontend/ ./
RUN pnpm build

# ── Stage 2: Python backend ───────────────────────────────────────────────────
FROM python:3.12-slim

# DuckDB httpfs + aws CLI needs these at runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates unzip \
    && ARCH=$(uname -m) \
    && if [ "$ARCH" = "aarch64" ]; then \
         curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o /tmp/awscliv2.zip; \
       else \
         curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip; \
       fi \
    && unzip -q /tmp/awscliv2.zip -d /tmp \
    && /tmp/aws/install \
    && rm -rf /tmp/awscliv2.zip /tmp/aws \
    && apt-get remove -y unzip \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN curl -Ls https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

WORKDIR /app

# Python deps
COPY pyproject.toml uv.lock ./
RUN uv sync --no-dev --frozen

# App source
COPY backend/ ./backend/
COPY config.yaml ./

# Frontend build from Stage 1
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Persistent data directory (mount a volume here)
RUN mkdir -p /data /app/duckdb_tmp

# Config via env vars — override at runtime with --env-file .env
ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    DB_PATH=/data/soc.duckdb \
    LOCAL_SYNC_PATH=/data/logs

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
