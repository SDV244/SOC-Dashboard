#!/bin/bash
# Nightly ADR ingest: runs at 2 AM, ingests yesterday's data for current month
set -euo pipefail

LOGFILE="/data/parquet/ingest_daily.log"
PYTHON="/app/.venv/bin/python3"
SCRIPT="/app/convert_adr_day.py"
TIMEOUT=21600

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOGFILE"; }

YEAR=$(date -d "yesterday" +%Y)
MONTH=$(date -d "yesterday" +%-m)
DAY=$(date -d "yesterday" +%-d)

log "=== Nightly ADR ingest: ${YEAR}-$(printf '%02d' $MONTH)-$(printf '%02d' $DAY) ==="

docker run --rm \
  --env-file /home/opc/soc-dashboard/.env \
  -v /data/parquet:/data/parquet \
  -v /home/opc/soc-dashboard/backend:/app/backend \
  -v /home/opc/soc-dashboard/config.yaml:/app/config.yaml \
  -v /home/opc/soc-dashboard/convert_adr_day.py:/app/convert_adr_day.py \
  soc-dashboard-soc \
  timeout $TIMEOUT $PYTHON $SCRIPT $YEAR $MONTH $DAY >> "$LOGFILE" 2>&1

# Notify app via API
COOKIE=/tmp/ingest_daily_cookie.txt
curl -s -c "$COOKIE" -b "$COOKIE" -X POST http://localhost:8000/api/auth/login \
  -d 'username=admin&password=S0C-D4shboard-2025!' -o /dev/null
RESP=$(curl -s -b "$COOKIE" -X POST \
  "http://localhost:8000/api/admin/parquet/convert-month?year=${YEAR}&month=${MONTH}&indexes=adr")
log "mark API: $RESP"
log "=== DONE ==="
