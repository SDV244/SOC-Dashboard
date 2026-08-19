"""
Admin endpoints for Parquet conversion management.
"""

from fastapi import APIRouter, Query

from backend.config import get_settings
from backend.services.oci_query import invalidate_cache
from backend.services.parquet_sync import (
    backfill_daily_stats,
    list_converted,
    refresh_current_months,
    start_bulk_sync,
    sync_status,
)

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.post("/parquet/convert")
def trigger_conversion(
    months_back: int = Query(default=12, ge=1, le=36, description="How many months of history to convert"),
    indexes: str = Query(default="", description="Comma-separated list of indexes, empty = all"),
):
    """
    Start background Parquet conversion for historical NDJSON.gz files in OCI.
    Already-converted months are skipped. Safe to call multiple times.
    """
    idx_list = [i.strip() for i in indexes.split(",") if i.strip()] or None
    started = start_bulk_sync(indexes=idx_list, months_back=months_back)
    return {"started": started, "message": "Already running" if not started else "Conversion started"}


@router.post("/parquet/refresh")
def refresh_parquet():
    """Re-convert current and previous month to pick up new data from OCI."""
    refresh_current_months()
    return {"started": True, "message": "Refreshing current month data"}


@router.get("/parquet/status")
def conversion_status():
    """Returns current conversion progress."""
    status = sync_status()
    converted = list_converted()
    return {
        "sync": status,
        "converted_months": converted,
        "total_converted": len(converted),
    }


@router.delete("/parquet/clear-index")
def clear_index_records(
    index: str = Query(..., description="Index name to remove from parquet_months"),
):
    """
    Remove parquet_months DB records for an index so it can be force-reconverted.
    Does NOT delete physical parquet files.
    """
    from backend.db import get_conn
    from backend.services.parquet_sync import _converted_cache
    conn = get_conn()
    rows = conn.execute("SELECT COUNT(*) FROM parquet_months WHERE index = ?", [index]).fetchone()[0]
    conn.execute("DELETE FROM parquet_months WHERE index = ?", [index])
    _converted_cache.discard
    # Clear all entries for this index from the in-memory cache
    to_remove = {e for e in _converted_cache if e[0] == index}
    for e in to_remove:
        _converted_cache.discard(e)
    return {"index": index, "deleted_records": rows}


@router.post("/cache/invalidate")
def invalidate_query_cache():
    """Clear the in-memory query result cache (5-min TTL). Forces fresh queries."""
    invalidate_cache()
    return {"message": "Cache invalidated"}


@router.post("/parquet/convert-month")
def convert_specific_month(
    year: int = Query(..., description="Year, e.g. 2026"),
    month: int = Query(..., ge=1, le=12, description="Month 1-12"),
    indexes: str = Query(default="", description="Comma-separated indexes, empty = all"),
):
    """Convert a specific year/month and compute daily stats. Runs in background."""
    import threading
    from backend.services.parquet_sync import compute_daily_stats, convert_month, mark_converted

    idx_list = [i.strip() for i in indexes.split(",") if i.strip()] or None
    settings = get_settings()
    idx = idx_list or settings.indexes

    def _run() -> None:
        import logging
        log = logging.getLogger(__name__)
        for index in idx:
            try:
                log.warning("convert-month DEBUG start %s %d-%02d", index, year, month)
                rows = convert_month(index, year, month)
                log.warning("convert-month DEBUG convert_month returned rows=%s for %s %d-%02d", rows, index, year, month)
                mark_converted(index, year, month, rows)
            except Exception:
                log.exception(
                    "convert-month convert_month failed for %s %d-%02d", index, year, month
                )
            try:
                n = compute_daily_stats(index, year, month)
                log.warning("convert-month DEBUG compute_daily_stats returned processed=%s for %s %d-%02d", n, index, year, month)
            except Exception:
                log.exception(
                    "convert-month compute_daily_stats failed for %s %d-%02d", index, year, month
                )

    threading.Thread(target=_run, daemon=True).start()
    return {"started": True, "year": year, "month": month, "indexes": idx}


@router.post("/stats/backfill")
def trigger_backfill(
    indexes: str = Query(default="", description="Comma-separated list of indexes, empty = all"),
    force: bool = Query(default=False, description="Overwrite existing rows (use to populate new columns)"),
):
    """
    Compute daily_stats for all converted months.
    force=True rewrites existing rows — use this after schema changes that add new columns.
    Runs in background.
    """
    import threading
    idx_list = [i.strip() for i in indexes.split(",") if i.strip()] or None

    def _run() -> None:
        backfill_daily_stats(idx_list, force=force)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return {"started": True, "force": force, "message": f"Backfill started in background (force={force})"}


@router.get("/stats/status")
def stats_status():
    """How many daily_stats rows exist per index."""
    from backend.db import get_conn
    conn = get_conn()
    rows = conn.execute(
        "SELECT index, count(*) as days, min(date), max(date) FROM daily_stats GROUP BY index ORDER BY index"
    ).fetchall()
    return [{"index": r[0], "days": r[1], "from": str(r[2]), "to": str(r[3])} for r in rows]


@router.get("/available-months")
def available_months() -> list[dict]:
    """Distinct (year, month) pairs that have at least one converted index."""
    from backend.db import get_conn
    conn = get_conn()
    rows = conn.execute(
        "SELECT DISTINCT year, month FROM parquet_months ORDER BY year, month"
    ).fetchall()
    return [{"year": r[0], "month": r[1]} for r in rows]


@router.get("/coverage/summary")
def coverage_summary() -> list[dict]:
    """Which indexes have Parquet data and for what date ranges."""
    from collections import defaultdict
    converted = list_converted()
    by_index: dict = defaultdict(list)
    for m in converted:
        by_index[m["index"]].append((m["year"], m["month"]))

    result = []
    for index in sorted(by_index.keys()):
        months = sorted(by_index[index])
        min_y, min_m = months[0]
        max_y, max_m = months[-1]
        # last day of max month
        import calendar
        last_day = calendar.monthrange(max_y, max_m)[1]
        result.append({
            "index": index,
            "from": f"{min_y}-{min_m:02d}-01",
            "to": f"{max_y}-{max_m:02d}-{last_day:02d}",
            "months_count": len(months),
        })
    return result


@router.get("/data-freshness")
def data_freshness() -> dict:
    """Latest data date across all indexes and next scheduled sync."""
    from datetime import UTC, datetime, timedelta
    from backend.db import get_conn
    conn = get_conn()
    row = conn.execute("SELECT MAX(date) FROM daily_stats").fetchone()
    last_date = row[0] if row and row[0] else None

    now = datetime.now(UTC)
    next_sync = now.replace(hour=3, minute=0, second=0, microsecond=0)
    if next_sync <= now:
        next_sync += timedelta(days=1)

    return {
        "last_data_date": str(last_date) if last_date else None,
        "next_sync_utc": next_sync.isoformat(),
        "sync_schedule": "Diario a las 03:00 UTC",
    }
