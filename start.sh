#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

# Install Python deps
[ ! -d ".venv" ] && uv sync

# Build frontend
(cd frontend && pnpm build)

# Launch
echo "SOC Dashboard disponible en http://localhost:8000"
uv run uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
