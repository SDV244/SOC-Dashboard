#!/bin/bash
# ADR ingest v3 - subprocess per day, 2 parallel, timeout 90min each
# Reliable: each day is an independent process, RAM freed after each day
# Resume-safe: skips valid parquet files automatically
set -euo pipefail

LOGFILE="/data/parquet/adr_ingest_v3.log"
PYTHON="/app/.venv/bin/python3"
SCRIPT="/app/convert_adr_day.py"
PARALLEL=2          # days in parallel (2 x 3.5GB = 7GB peak, safe on 11GB VM)
TIMEOUT=5400        # 90 min per day (ADR has thousands of .gz files)

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOGFILE"; }

api_mark() {
    local month=$1
    local cookie=/tmp/adr_v3_cookie.txt
    curl -s -c "$cookie" -b "$cookie" -X POST http://localhost:8000/api/auth/login \
        -d 'username=admin&password=S0C-D4shboard-2025!' -o /dev/null
    local resp
    resp=$(curl -s -b "$cookie" -X POST \
        "http://localhost:8000/api/admin/parquet/convert-month?year=2026&month=${month}&indexes=adr")
    log "mark API month=$month: $resp"
}

ingest_month() {
    local month=$1
    local padded
    padded=$(printf '%02d' "$month")
    local dir="/data/parquet/index=adr/year=2026/month=${padded}"
    local days
    days=$(python3 -c "import calendar; print(calendar.monthrange(2026, $month)[1])")

    log "=== ADR 2026-${padded} START (${days} days, ${PARALLEL} parallel) ==="

    # Count already valid
    local valid_before
    valid_before=$(ls "$dir"/*.parquet 2>/dev/null | wc -l)
    log "Valid files on disk before: ${valid_before}/${days}"

    if [ "$valid_before" -eq "$days" ]; then
        log "ADR 2026-${padded}: already complete, registering..."
        api_mark "$month"
        return 0
    fi

    # Run days in parallel batches
    local running=0
    local pids=()
    local day_pids=()

    for day in $(seq 1 "$days"); do
        local dst="${dir}/day=$(printf '%02d' "$day").parquet"

        # Skip quickly if file exists and is non-empty (validate_parquet happens inside the script)
        if [ -f "$dst" ] && [ -s "$dst" ]; then
            log "  day=$(printf '%02d' $day): exists, will validate inside subprocess"
        fi

        # Launch subprocess with timeout
        (
            timeout "$TIMEOUT" "$PYTHON" "$SCRIPT" 2026 "$month" "$day" \
                >> "$LOGFILE" 2>&1
        ) &
        pids+=($!)
        day_pids+=("$day")
        running=$((running + 1))

        # Wait when we hit parallelism limit
        if [ "$running" -ge "$PARALLEL" ]; then
            wait "${pids[0]}" || true
            pids=("${pids[@]:1}")
            day_pids=("${day_pids[@]:1}")
            running=$((running - 1))
        fi
    done

    # Wait for remaining
    for pid in "${pids[@]}"; do
        wait "$pid" || true
    done

    # Summary
    local valid_after
    valid_after=$(ls "$dir"/*.parquet 2>/dev/null | wc -l)
    log "ADR 2026-${padded}: ${valid_after}/${days} files after conversion"

    if [ "$valid_after" -gt 0 ]; then
        log "Calling API for mark_converted + daily stats..."
        api_mark "$month"
        log "Waiting 3min for stats computation..."
        sleep 180
        log "=== ADR 2026-${padded} DONE ==="
        return 0
    else
        log "=== ADR 2026-${padded} FAILED: no files written ==="
        return 1
    fi
}

log "========================================================"
log "ADR Ingest v3: subprocess/day, ${PARALLEL} parallel, ${TIMEOUT}s timeout"
log "========================================================"

for month in 5; do
    ingest_month "$month" || log "Month $month had errors, continuing..."
done

log "========================================================"
log "ADR Ingest v3 COMPLETE"
log "========================================================"
