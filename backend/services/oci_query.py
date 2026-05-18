"""
OCI Object Storage queries via DuckDB httpfs.

Query routing:
  - Parquet (converted): fast columnar queries — used when available
  - NDJSON.gz (raw):     slow fallback for months not yet converted

Parquet path: s3://{bucket}/parquet/org={org}/index={index}/tenant={tenant}/year={y}/month={m}/part.parquet
NDJSON path:  s3://{bucket}/organization={org}/index={index}/tenant={tenant}/year={y}/month={m}/**/*.gz
"""

import json
import threading
import time
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

import duckdb

from backend.config import get_settings
from backend.db import get_conn, get_oci_conn, setup_httpfs
from backend.services.parquet_sync import is_converted, parquet_path


# ── Query result cache (5-minute TTL) ────────────────────────────────────────

_cache: dict[str, tuple] = {}
_cache_lock = threading.Lock()
_CACHE_TTL = 300  # seconds


def _get_cached(key: str) -> tuple:
    with _cache_lock:
        entry = _cache.get(key)
        if entry and time.monotonic() < entry[1]:
            return entry[0], True
        return None, False


def _set_cached(key: str, value: object) -> None:
    with _cache_lock:
        _cache[key] = (value, time.monotonic() + _CACHE_TTL)


def invalidate_cache() -> None:
    with _cache_lock:
        _cache.clear()


# ── Path helpers ──────────────────────────────────────────────────────────────

def _iter_months(start: datetime, end: datetime):
    current = start.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    while current <= end:
        yield current.year, current.month
        if current.month == 12:
            current = current.replace(year=current.year + 1, month=1)
        else:
            current = current.replace(month=current.month + 1)


def _ndjson_glob_month(index: str, year: int, month: int) -> str:
    s = get_settings()
    return (
        f"s3://{s.s3_bucket}/"
        f"organization={s.org_id}/index={index}/tenant={s.tenant_id}/"
        f"year={year:04d}/month={month:02d}/**/*.gz"
    )


def _ndjson_glob_day(index: str, year: int, month: int, day: int) -> str:
    s = get_settings()
    return (
        f"s3://{s.s3_bucket}/"
        f"organization={s.org_id}/index={index}/tenant={s.tenant_id}/"
        f"year={year:04d}/month={month:02d}/day={day:02d}/**/*.gz"
    )


def _iter_days(start: datetime, end: datetime):
    from datetime import timedelta
    current = start.replace(hour=0, minute=0, second=0, microsecond=0)
    while current <= end:
        yield current.year, current.month, current.day
        current += timedelta(days=1)


def _build_sources(index: str, start: datetime, end: datetime) -> tuple[list[str], list[str]]:
    """
    Returns local Parquet paths only — NDJSON/OCI fallback disabled (too slow for interactive use).
    Months not yet converted to Parquet simply return no data (instant empty response).
    """
    parquet_paths: list[str] = []
    day_range = (end - start).days

    if day_range < 32:
        for year, month, _day in _iter_days(start, end):
            if is_converted(index, year, month):
                p = parquet_path(index, year, month)
                if p not in parquet_paths:
                    parquet_paths.append(p)
    else:
        for year, month in _iter_months(start, end):
            if is_converted(index, year, month):
                p = parquet_path(index, year, month)
                if p not in parquet_paths:
                    parquet_paths.append(p)

    return parquet_paths, []  # ndjson_globs always empty — OCI too slow for interactive queries


def _ts_filter_parquet(start: str, end: str) -> str:
    return f"ts BETWEEN '{start}'::TIMESTAMPTZ AND '{end}'::TIMESTAMPTZ"


def _ts_filter_ndjson(start: str, end: str) -> str:
    return (
        f"to_timestamp(CAST(timestamp AS BIGINT) / 1000) "
        f"BETWEEN '{start}'::TIMESTAMPTZ AND '{end}'::TIMESTAMPTZ"
    )


def _read_parquet(paths: list[str]) -> str:
    from glob import glob as _glob
    files: list[str] = []
    for p in paths:
        files.extend(f for f in _glob(p) if not Path(f).name.startswith("tmp_"))
    if not files:
        return ""
    joined = ", ".join(f"'{f}'" for f in files)
    return f"parquet_scan([{joined}], union_by_name=true)"


def _read_ndjson(globs: list[str]) -> str:
    joined = ", ".join(f"'{g}'" for g in globs)
    return f"read_json([{joined}], format='newline_delimited', ignore_errors=true, compression='gzip')"


# ── Unified query executor ────────────────────────────────────────────────────

def _exec_union(
    conn: duckdb.DuckDBPyConnection,
    parquet_sql: str | None,
    ndjson_sql: str | None,
    aggregate_sql: str,
) -> list:
    """
    Execute aggregate_sql over Parquet + NDJSON sources and UNION the results.
    aggregate_sql must contain {source} and {ts_filter} placeholders.
    """
    parts = []
    if parquet_sql:
        parts.append(parquet_sql)
    if ndjson_sql:
        parts.append(ndjson_sql)
    if not parts:
        return []

    if len(parts) == 1:
        return conn.execute(parts[0]).fetchall()

    # Two sources: wrap both in a subquery and re-aggregate
    combined = f"({parts[0]}) UNION ALL ({parts[1]})"
    return conn.execute(f"SELECT * FROM ({combined}) ORDER BY 1").fetchall()


# ── Daily stats helpers ───────────────────────────────────────────────────────

def _daily_stats_range(index: str | None, start: str | datetime, end: str | datetime) -> list[dict]:
    """Return daily_stats rows for a date range. index=None returns all indexes."""
    conn = get_conn()
    if isinstance(start, str):
        start_date = start[:10]
    else:
        start_date = start.date().isoformat()
    if isinstance(end, str):
        end_date = end[:10]
    else:
        end_date = end.date().isoformat()

    if index is not None:
        rows = conn.execute(
            """SELECT date, total, threat_high, dga, tunneling,
                      top_apps, top_geo, top_domains, top_threats,
                      top_hosts, top_event_types, top_users, timeline_json,
                      top_processes, login_stats, avg_fidelity,
                      high_confidence_cnt, bad_ip_rep_cnt
               FROM daily_stats WHERE index=? AND date BETWEEN ? AND ?
               ORDER BY date""",
            [index, start_date, end_date],
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT date, total, threat_high, dga, tunneling,
                      top_apps, top_geo, top_domains, top_threats,
                      top_hosts, top_event_types, top_users, timeline_json,
                      top_processes, login_stats, avg_fidelity,
                      high_confidence_cnt, bad_ip_rep_cnt
               FROM daily_stats WHERE date BETWEEN ? AND ?
               ORDER BY date""",
            [start_date, end_date],
        ).fetchall()

    return [
        {
            "date": r[0], "total": r[1], "threat_high": r[2],
            "dga": r[3], "tunneling": r[4],
            "top_apps": json.loads(r[5] or "[]"),
            "top_geo": json.loads(r[6] or "[]"),
            "top_domains": json.loads(r[7] or "[]"),
            "top_threats": json.loads(r[8] or "[]"),
            "top_hosts": json.loads(r[9] or "[]"),
            "top_event_types": json.loads(r[10] or "[]"),
            "top_users": json.loads(r[11] or "[]"),
            "timeline_json": json.loads(r[12] or "[]"),
            "top_processes": json.loads(r[13] or "[]") if r[13] else [],
            "login_stats": json.loads(r[14] or "{}") if r[14] else {},
            "avg_fidelity": r[15],
            "high_confidence_cnt": r[16] or 0,
            "bad_ip_rep_cnt": r[17] or 0,
        }
        for r in rows
    ]


def _parse_host(h: str) -> str:
    """Extract hostname from JSON-encoded host strings like {"ip":"...","name":"QTGV01"}."""
    if h and h.startswith('{'):
        try:
            d = json.loads(h)
            return d.get('name') or d.get('ip') or h
        except Exception:
            pass
    return h


def _merge_top_n(rows_list: list[list[dict]], key: str, n: int = 15) -> list[dict]:
    """Merge multiple top-N lists by summing counts for matching keys."""
    totals: dict[str, int] = defaultdict(int)
    for rows in rows_list:
        for r in rows:
            k = _parse_host(r[key]) if key == 'host' else r[key]
            totals[k] += r["count"]
    return sorted(
        [{"count": v, key: k} for k, v in totals.items()],
        key=lambda x: x["count"], reverse=True,
    )[:n]


# ── KPI: overview ─────────────────────────────────────────────────────────────

def kpi_overview_oci(index: str, start: datetime, end: datetime) -> dict:
    start_s, end_s = start.isoformat(), end.isoformat()
    cache_key = f"kpi_overview:{index}:{start_s}:{end_s}"
    cached, hit = _get_cached(cache_key)
    if hit:
        return cached

    # total_events: sum ALL indexes so Jan-Apr shows data even when ADR is missing
    all_stats = _daily_stats_range(None, start, end)
    adr_stats = _daily_stats_range("adr", start, end)
    if all_stats:
        result = {
            "total_events":      sum(r["total"] for r in all_stats),
            "threat_score_high": sum(r["threat_high"] for r in adr_stats),
            "dga_detections":    sum(r["dga"] for r in adr_stats),
            "tunneling_events":  sum(r["tunneling"] for r in adr_stats),
            "_source": "daily_stats",
        }
        _set_cached(cache_key, result)
        return result

    parquet_paths, _ = _build_sources(index, start, end)
    src = _read_parquet(parquet_paths) if parquet_paths else ""
    if not src:
        result = {"total_events": 0, "threat_score_high": 0, "dga_detections": 0, "tunneling_events": 0}
        _set_cached(cache_key, result)
        return result

    conn = get_oci_conn()
    tf = _ts_filter_parquet(start_s, end_s)
    row = conn.execute(f"""
        SELECT
            count(*)                                      AS total,
            count(*) FILTER (WHERE threat_score > 50)    AS threat_high,
            count(*) FILTER (WHERE dga_flag = 'yes')     AS dga,
            count(*) FILTER (WHERE tunneling > 0)        AS tunneling
        FROM {src} WHERE {tf}
    """).fetchone()
    result = {
        "total_events":      row[0],
        "threat_score_high": row[1],
        "dga_detections":    row[2],
        "tunneling_events":  row[3],
    }
    _set_cached(cache_key, result)
    return result


# ── Alerts timeline ───────────────────────────────────────────────────────────

def alerts_timeline_oci(start: str, end: str, granularity: str = "hour") -> list[dict]:
    cache_key = f"alerts_timeline:{start}:{end}:{granularity}"
    cached, hit = _get_cached(cache_key)
    if hit:
        return cached

    start_dt = datetime.fromisoformat(start)
    end_dt = datetime.fromisoformat(end)

    stats = _daily_stats_range("adr", start_dt, end_dt)
    if stats:
        # Merge hourly timeline entries from each day's pre-aggregated JSON
        buckets: dict = defaultdict(lambda: defaultdict(int))
        for day_row in stats:
            date_str = str(day_row["date"])[:10]  # "YYYY-MM-DD"
            for entry in day_row["timeline_json"]:
                hour = int(entry["hour"])
                if granularity == "hour":
                    period = f"{date_str}T{hour:02d}:00:00"
                else:
                    period = date_str
                buckets[period][entry["msg_class"]] += entry["count"]
        result = [
            {"period": period, "msg_class": mc, "count": cnt}
            for period, mc_map in sorted(buckets.items())
            for mc, cnt in mc_map.items()
        ]
        _set_cached(cache_key, result)
        return result

    parquet_paths, ndjson_globs = _build_sources("adr", start_dt, end_dt)
    trunc = "hour" if granularity == "hour" else "day"
    conn = get_oci_conn()
    rows: list = []
    try:
        if parquet_paths:
            src = _read_parquet(parquet_paths)
            tf = _ts_filter_parquet(start, end)
            rows += conn.execute(f"""
                SELECT date_trunc('{trunc}', ts), coalesce(msg_class, 'unknown'), count(*)
                FROM {src} WHERE {tf} GROUP BY 1, 2 ORDER BY 1
            """).fetchall()
        if ndjson_globs:
            src = _read_ndjson(ndjson_globs)
            tf = _ts_filter_ndjson(start, end)
            rows += conn.execute(f"""
                SELECT date_trunc('{trunc}', to_timestamp(CAST(timestamp AS BIGINT)/1000)),
                       coalesce(msg_class,'unknown'), count(*)
                FROM {src} WHERE {tf} GROUP BY 1, 2 ORDER BY 1
            """).fetchall()
        result = [{"period": r[0], "msg_class": r[1], "count": r[2]} for r in rows]
        _set_cached(cache_key, result)
        return result
    except Exception:
        return []


# ── Top threats ───────────────────────────────────────────────────────────────

def top_threats_oci(start: str, end: str, limit: int = 10) -> list[dict]:
    cache_key = f"top_threats:{start}:{end}:{limit}"
    cached, hit = _get_cached(cache_key)
    if hit:
        return cached

    start_dt = datetime.fromisoformat(start)
    end_dt = datetime.fromisoformat(end)

    stats = _daily_stats_range("adr", start_dt, end_dt)
    if stats:
        totals: dict[str, dict] = {}
        last_date = max(str(r["date"])[:10] for r in stats) if stats else None
        for day_row in stats:
            day_str = str(day_row["date"])[:10]
            for t in day_row["top_threats"]:
                dev = t["device"]
                if dev not in totals:
                    totals[dev] = {"device": dev, "max_threat_score": t["max_score"], "count": 0, "last_seen": day_str}
                totals[dev]["count"] += t["count"]
                totals[dev]["max_threat_score"] = max(totals[dev]["max_threat_score"], t["max_score"])
                if day_str >= totals[dev]["last_seen"]:
                    totals[dev]["last_seen"] = day_str
        result = sorted(totals.values(), key=lambda x: (-x["max_threat_score"], -x["count"]))[:limit]
        _set_cached(cache_key, result)
        return result

    parquet_paths, ndjson_globs = _build_sources("adr", start_dt, end_dt)
    conn = get_oci_conn()
    rows: list = []
    try:
        if parquet_paths:
            src = _read_parquet(parquet_paths)
            tf = _ts_filter_parquet(start, end)
            rows += conn.execute(f"""
                SELECT coalesce(engid_name,'unknown'), max(threat_score), count(*), max(ts)
                FROM {src} WHERE {tf} AND threat_score > 0
                GROUP BY 1 ORDER BY 2 DESC, 3 DESC LIMIT {limit}
            """).fetchall()
        if ndjson_globs:
            src = _read_ndjson(ndjson_globs)
            tf = _ts_filter_ndjson(start, end)
            rows += conn.execute(f"""
                SELECT coalesce(engid_name,'unknown'),
                       max(TRY_CAST(threat_score AS INTEGER)),
                       count(*),
                       max(to_timestamp(CAST(timestamp AS BIGINT)/1000))
                FROM {src} WHERE {tf} AND TRY_CAST(threat_score AS INTEGER) > 0
                GROUP BY 1 ORDER BY 2 DESC, 3 DESC LIMIT {limit}
            """).fetchall()
        result = [{"device": r[0], "max_threat_score": r[1], "count": r[2], "last_seen": r[3]} for r in rows]
        _set_cached(cache_key, result)
        return result
    except Exception:
        return []


# ── Top domains ───────────────────────────────────────────────────────────────

def network_top_domains_oci(start: str, end: str, limit: int = 15) -> list[dict]:
    cache_key = f"top_domains:{start}:{end}:{limit}"
    cached, hit = _get_cached(cache_key)
    if hit:
        return cached

    start_dt = datetime.fromisoformat(start)
    end_dt = datetime.fromisoformat(end)

    stats = _daily_stats_range("adr", start_dt, end_dt)
    if stats:
        totals: dict[str, dict] = {}
        for day_row in stats:
            for d in day_row["top_domains"]:
                key = d["domain"]
                if key not in totals:
                    totals[key] = {"domain": key, "count": 0, "reputation": d["reputation"], "is_dga": d["is_dga"]}
                totals[key]["count"] += d["count"]
        result = sorted(totals.values(), key=lambda x: -x["count"])[:limit]
        _set_cached(cache_key, result)
        return result

    parquet_paths, ndjson_globs = _build_sources("adr", start_dt, end_dt)
    conn = get_oci_conn()
    rows: list = []
    try:
        if parquet_paths:
            src = _read_parquet(parquet_paths)
            tf = _ts_filter_parquet(start, end)
            rows += conn.execute(f"""
                SELECT primary_domain, count(*), coalesce(domain_reputation,'unknown'), coalesce(dga_flag,'no')
                FROM {src} WHERE {tf} AND primary_domain IS NOT NULL
                GROUP BY 1,3,4 ORDER BY 2 DESC LIMIT {limit}
            """).fetchall()
        if ndjson_globs:
            src = _read_ndjson(ndjson_globs)
            tf = _ts_filter_ndjson(start, end)
            rows += conn.execute(f"""
                SELECT domain_list[1], count(*), coalesce(domain_reputation,'unknown'), coalesce(dga_flag,'no')
                FROM {src} WHERE {tf} AND domain_list IS NOT NULL AND len(domain_list) > 0
                GROUP BY 1,3,4 ORDER BY 2 DESC LIMIT {limit}
            """).fetchall()
        result = [{"domain": r[0], "count": r[1], "reputation": r[2], "is_dga": r[3]} for r in rows]
        _set_cached(cache_key, result)
        return result
    except Exception:
        return []


# ── Network apps ──────────────────────────────────────────────────────────────

def network_apps_oci(start: str, end: str) -> list[dict]:
    cache_key = f"network_apps:{start}:{end}"
    cached, hit = _get_cached(cache_key)
    if hit:
        return cached

    start_dt = datetime.fromisoformat(start)
    end_dt = datetime.fromisoformat(end)

    stats = _daily_stats_range("adr", start_dt, end_dt)
    if stats:
        result = _merge_top_n([r["top_apps"] for r in stats], "app", n=50)
        _set_cached(cache_key, result)
        return result

    parquet_paths, ndjson_globs = _build_sources("adr", start_dt, end_dt)
    conn = get_oci_conn()
    rows: list = []
    try:
        if parquet_paths:
            src = _read_parquet(parquet_paths)
            tf = _ts_filter_parquet(start, end)
            rows += conn.execute(f"""
                SELECT coalesce(appid_name,'unknown'), count(*)
                FROM {src} WHERE {tf} GROUP BY 1 ORDER BY 2 DESC
            """).fetchall()
        if ndjson_globs:
            src = _read_ndjson(ndjson_globs)
            tf = _ts_filter_ndjson(start, end)
            rows += conn.execute(f"""
                SELECT coalesce(appid_name,'unknown'), count(*)
                FROM {src} WHERE {tf} GROUP BY 1 ORDER BY 2 DESC
            """).fetchall()
        result = [{"app": r[0], "count": r[1]} for r in rows]
        _set_cached(cache_key, result)
        return result
    except Exception:
        return []


# ── Network geo ───────────────────────────────────────────────────────────────

def network_geo_oci(start: str, end: str, limit: int = 15) -> list[dict]:
    cache_key = f"network_geo:{start}:{end}:{limit}"
    cached, hit = _get_cached(cache_key)
    if hit:
        return cached

    start_dt = datetime.fromisoformat(start)
    end_dt = datetime.fromisoformat(end)

    stats = _daily_stats_range("adr", start_dt, end_dt)
    if stats:
        result = _merge_top_n([r["top_geo"] for r in stats], "country", n=limit)
        _set_cached(cache_key, result)
        return result

    parquet_paths, ndjson_globs = _build_sources("adr", start_dt, end_dt)
    conn = get_oci_conn()
    rows: list = []
    try:
        if parquet_paths:
            src = _read_parquet(parquet_paths)
            tf = _ts_filter_parquet(start, end)
            rows += conn.execute(f"""
                SELECT coalesce(country_code,'unknown'), count(*)
                FROM {src} WHERE {tf} GROUP BY 1 ORDER BY 2 DESC LIMIT {limit}
            """).fetchall()
        if ndjson_globs:
            src = _read_ndjson(ndjson_globs)
            tf = _ts_filter_ndjson(start, end)
            rows += conn.execute(f"""
                SELECT coalesce(srcip_geo.countryCode,'unknown'), count(*)
                FROM {src} WHERE {tf} GROUP BY 1 ORDER BY 2 DESC LIMIT {limit}
            """).fetchall()
        result = [{"country": r[0], "count": r[1]} for r in rows]
        _set_cached(cache_key, result)
        return result
    except Exception:
        return []


# ── Network threats ───────────────────────────────────────────────────────────

def network_threats_oci(start: str, end: str, limit: int = 20) -> list[dict]:
    cache_key = f"network_threats:{start}:{end}:{limit}"
    cached, hit = _get_cached(cache_key)
    if hit:
        return cached

    start_dt = datetime.fromisoformat(start)
    end_dt = datetime.fromisoformat(end)
    parquet_paths, ndjson_globs = _build_sources("adr", start_dt, end_dt)
    conn = get_oci_conn()
    rows: list = []
    try:
        if parquet_paths:
            src = _read_parquet(parquet_paths)
            tf = _ts_filter_parquet(start, end)
            rows += conn.execute(f"""
                SELECT coalesce(engid_name,'unknown'), threat_score,
                       coalesce(appid_name,'unknown'), coalesce(dga_flag,'no'), ts
                FROM {src} WHERE {tf} AND threat_score > 0
                ORDER BY threat_score DESC, ts DESC LIMIT {limit}
            """).fetchall()
        if ndjson_globs:
            src = _read_ndjson(ndjson_globs)
            tf = _ts_filter_ndjson(start, end)
            rows += conn.execute(f"""
                SELECT coalesce(engid_name,'unknown'),
                       TRY_CAST(threat_score AS INTEGER),
                       coalesce(appid_name,'unknown'),
                       coalesce(dga_flag,'no'),
                       to_timestamp(CAST(timestamp AS BIGINT)/1000)
                FROM {src} WHERE {tf} AND TRY_CAST(threat_score AS INTEGER) > 0
                ORDER BY 2 DESC, 5 DESC LIMIT {limit}
            """).fetchall()
        result = [{"device": r[0], "threat_score": r[1], "app": r[2], "is_dga": r[3], "ts": r[4]} for r in rows]
        _set_cached(cache_key, result)
        return result
    except Exception:
        return []


# ── Syslog volume ─────────────────────────────────────────────────────────────

def syslog_volume_oci(start: str, end: str, limit: int = 10) -> dict:
    cache_key = f"syslog_volume:{start}:{end}:{limit}"
    cached, hit = _get_cached(cache_key)
    if hit:
        return cached

    start_dt = datetime.fromisoformat(start)
    end_dt = datetime.fromisoformat(end)

    all_hosts_lists, all_events_lists, timeline_rows = [], [], []
    any_stats = False
    for index in ("syslog", "wineventlog"):
        stats = _daily_stats_range(index, start_dt, end_dt)
        if stats:
            any_stats = True
            all_hosts_lists.extend(r["top_hosts"] for r in stats)
            all_events_lists.extend(r["top_event_types"] for r in stats)
            for day_row in stats:
                date_str = str(day_row["date"])[:10]
                for entry in day_row["timeline_json"]:
                    timeline_rows.append({
                        "period": f"{date_str}T{int(entry['hour'] or 0):02d}:00:00",
                        "index": index,
                        "count": entry["count"],
                    })
    if any_stats:
        result: dict = {
            "by_host": _merge_top_n(all_hosts_lists, "host", n=limit) if all_hosts_lists else [],
            "by_event_type": _merge_top_n(all_events_lists, "event_type", n=limit) if all_events_lists else [],
            "timeline": sorted(timeline_rows, key=lambda x: x["period"]),
        }
        _set_cached(cache_key, result)
        return result

    result = {"by_host": [], "by_event_type": [], "timeline": []}
    for index in ("syslog", "wineventlog"):
        parquet_paths, ndjson_globs = _build_sources(index, start_dt, end_dt)
        conn = get_oci_conn()
        try:
            for src, tf, ts_expr in [
                (_read_parquet(parquet_paths) if parquet_paths else None,
                 _ts_filter_parquet(start, end), "ts"),
                (_read_ndjson(ndjson_globs) if ndjson_globs else None,
                 _ts_filter_ndjson(start, end), "to_timestamp(CAST(timestamp AS BIGINT)/1000)"),
            ]:
                if not src:
                    continue
                hosts = conn.execute(f"""
                    SELECT coalesce(
                        CASE WHEN host LIKE '{{%' THEN json_extract_string(host, '$.name') END,
                        CASE WHEN host LIKE '{{%' THEN json_extract_string(host, '$.ip') END,
                        host, 'unknown'
                    ), count(*)
                    FROM {src} WHERE {tf} GROUP BY 1 ORDER BY 2 DESC LIMIT {limit}
                """).fetchall()
                events = conn.execute(f"""
                    SELECT coalesce(event_type,'unknown'), count(*)
                    FROM {src} WHERE {tf} GROUP BY 1 ORDER BY 2 DESC LIMIT {limit}
                """).fetchall()
                tl = conn.execute(f"""
                    SELECT date_trunc('hour', {ts_expr}), '{index}', count(*)
                    FROM {src} WHERE {tf} GROUP BY 1,2 ORDER BY 1
                """).fetchall()
                result["by_host"].extend({"host": _parse_host(r[0]), "count": r[1]} for r in hosts)
                result["by_event_type"].extend({"event_type": r[0], "count": r[1]} for r in events)
                result["timeline"].extend({"period": r[0], "index": r[1], "count": r[2]} for r in tl)
        except Exception:
            pass
    _set_cached(cache_key, result)
    return result


# ── Users activity ────────────────────────────────────────────────────────────

def users_activity_oci(start: str, end: str, limit: int = 10) -> dict:
    cache_key = f"users_activity:{start}:{end}:{limit}"
    cached, hit = _get_cached(cache_key)
    if hit:
        return cached

    start_dt = datetime.fromisoformat(start)
    end_dt = datetime.fromisoformat(end)

    stats = _daily_stats_range("users", start_dt, end_dt)
    if stats:
        merged = _merge_top_n([r["top_users"] for r in stats], "user", n=limit)
        result = {
            "top_users": [{"user": u["user"], "count": u["count"], "last_seen": None} for u in merged],
            "user_events": [],
        }
        _set_cached(cache_key, result)
        return result

    parquet_paths, ndjson_globs = _build_sources("users", start_dt, end_dt)
    conn = get_oci_conn()
    try:
        top_users, user_events = [], []
        if parquet_paths:
            src = _read_parquet(parquet_paths)
            tf = _ts_filter_parquet(start, end)
            top_users += conn.execute(f"""
                SELECT user_name, count(*), max(ts)
                FROM {src} WHERE {tf} AND user_name IS NOT NULL
                GROUP BY 1 ORDER BY 2 DESC LIMIT {limit}
            """).fetchall()
            user_events += conn.execute(f"""
                SELECT coalesce(user_name,'unknown'), coalesce(event_type,'unknown'), count(*)
                FROM {src} WHERE {tf} GROUP BY 1,2 ORDER BY 3 DESC LIMIT {limit}
            """).fetchall()
        if ndjson_globs:
            src = _read_ndjson(ndjson_globs)
            tf = _ts_filter_ndjson(start, end)
            top_users += conn.execute(f"""
                SELECT user_name, count(*), max(to_timestamp(CAST(timestamp AS BIGINT)/1000))
                FROM {src} WHERE {tf} AND user_name IS NOT NULL
                GROUP BY 1 ORDER BY 2 DESC LIMIT {limit}
            """).fetchall()
            user_events += conn.execute(f"""
                SELECT coalesce(user_name,'unknown'), coalesce(event_type,'unknown'), count(*)
                FROM {src} WHERE {tf} GROUP BY 1,2 ORDER BY 3 DESC LIMIT {limit}
            """).fetchall()
        result = {
            "top_users": [{"user": r[0], "count": r[1], "last_seen": r[2]} for r in top_users],
            "user_events": [{"user": r[0], "event_type": r[1], "count": r[2]} for r in user_events],
        }
        _set_cached(cache_key, result)
        return result
    except Exception:
        return {"top_users": [], "user_events": []}


# ── Assets activity ───────────────────────────────────────────────────────────

def assets_activity_oci(start: str, end: str, limit: int = 10) -> dict:
    cache_key = f"assets_activity:{start}:{end}:{limit}"
    cached, hit = _get_cached(cache_key)
    if hit:
        return cached

    start_dt = datetime.fromisoformat(start)
    end_dt = datetime.fromisoformat(end)

    stats = _daily_stats_range("assets", start_dt, end_dt)
    if stats:
        merged = _merge_top_n([r["top_hosts"] for r in stats], "host", n=limit)
        result = {"top_assets": [{"asset": h["host"], "count": h["count"], "last_seen": None} for h in merged]}
        _set_cached(cache_key, result)
        return result

    parquet_paths, ndjson_globs = _build_sources("assets", start_dt, end_dt)
    conn = get_oci_conn()
    rows: list = []
    try:
        if parquet_paths:
            src = _read_parquet(parquet_paths)
            tf = _ts_filter_parquet(start, end)
            rows += conn.execute(f"""
                SELECT coalesce(host, src_ip, 'unknown'), count(*), max(ts)
                FROM {src} WHERE {tf} GROUP BY 1 ORDER BY 2 DESC LIMIT {limit}
            """).fetchall()
        if ndjson_globs:
            src = _read_ndjson(ndjson_globs)
            tf = _ts_filter_ndjson(start, end)
            rows += conn.execute(f"""
                SELECT coalesce(host, srcip, 'unknown'), count(*),
                       max(to_timestamp(CAST(timestamp AS BIGINT)/1000))
                FROM {src} WHERE {tf} GROUP BY 1 ORDER BY 2 DESC LIMIT {limit}
            """).fetchall()
        result = {"top_assets": [{"asset": r[0], "count": r[1], "last_seen": r[2]} for r in rows]}
        _set_cached(cache_key, result)
        return result
    except Exception:
        return {"top_assets": []}


# ── ML Confidence ─────────────────────────────────────────────────────────────

def ml_confidence_oci(start: str, end: str) -> dict:
    cache_key = f"ml_confidence:{start}:{end}"
    cached, hit = _get_cached(cache_key)
    if hit:
        return cached

    rows = _daily_stats_range(None, start, end)
    if rows:
        total = sum(r["total"] for r in rows)
        high_conf = sum(r.get("high_confidence_cnt") or 0 for r in rows)
        bad_ip = sum(r.get("bad_ip_rep_cnt") or 0 for r in rows)
        fidelity_vals = [r["avg_fidelity"] for r in rows if r.get("avg_fidelity") is not None]
        avg_fid = round(sum(fidelity_vals) / len(fidelity_vals), 1) if fidelity_vals else None
        result = {
            "avg_fidelity": avg_fid,
            "high_confidence_count": high_conf,
            "bad_ip_reputation_count": bad_ip,
            "high_confidence_pct": round(high_conf / total * 100, 1) if total else 0,
        }
        _set_cached(cache_key, result)
        return result

    return {"avg_fidelity": None, "high_confidence_count": 0, "bad_ip_reputation_count": 0, "high_confidence_pct": 0}


# ── Login Stats ────────────────────────────────────────────────────────────────

def login_stats_oci(start: str, end: str) -> dict:
    cache_key = f"login_stats:{start}:{end}"
    cached, hit = _get_cached(cache_key)
    if hit:
        return cached

    rows = _daily_stats_range(None, start, end)
    if rows:
        total_failed = 0
        total_success = 0
        total_logins = 0
        type_counts: dict = defaultdict(int)
        for r in rows:
            ls = r.get("login_stats")
            if not ls:
                continue
            try:
                d = json.loads(ls) if isinstance(ls, str) else ls
                total_failed += d.get("failed", 0)
                total_success += d.get("successful", 0)
                total_logins += d.get("total_logins", 0)
                for t in d.get("top_types", []):
                    type_counts[t["type"]] += t["count"]
            except Exception:
                pass
        top_types = sorted([{"type": k, "count": v} for k, v in type_counts.items()], key=lambda x: -x["count"])[:10]
        total_attempts = total_failed + total_success
        result = {
            "total_failed": total_failed,
            "total_successful": total_success,
            "total_logins": total_logins,
            "fail_ratio": round(total_failed / total_attempts * 100, 1) if total_attempts else 0,
            "top_login_types": top_types,
        }
        _set_cached(cache_key, result)
        return result

    return {"total_failed": 0, "total_successful": 0, "total_logins": 0, "fail_ratio": 0, "top_login_types": []}


# ── Top Processes ──────────────────────────────────────────────────────────────

def top_processes_oci(start: str, end: str, limit: int = 20) -> list:
    cache_key = f"top_processes:{start}:{end}:{limit}"
    cached, hit = _get_cached(cache_key)
    if hit:
        return cached

    rows = _daily_stats_range(None, start, end)
    if rows:
        proc_counts: dict = defaultdict(int)
        for r in rows:
            tp = r.get("top_processes")
            if not tp:
                continue
            try:
                for p in (json.loads(tp) if isinstance(tp, str) else tp):
                    proc_counts[p["process"]] += p["count"]
            except Exception:
                pass
        result = sorted([{"process": k, "count": v} for k, v in proc_counts.items()], key=lambda x: -x["count"])[:limit]
        _set_cached(cache_key, result)
        return result

    return []


# ── Log Browser ──────────────────────────────────────────────────────────────

def browse_logs_oci(
    index: str | None,
    start: str,
    end: str,
    host: str | None = None,
    user_name: str | None = None,
    search: str | None = None,
    threat_score_min: int = 0,
    is_dga: str | None = None,
    is_tunneling: bool | None = None,
    app_name: str | None = None,
    src_country: str | None = None,
    domain: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> dict:
    start_dt = datetime.fromisoformat(start)
    end_dt = datetime.fromisoformat(end)
    settings = get_settings()
    indexes = [index] if index else settings.indexes

    def _build_conditions(tf: str) -> list[str]:
        conds = [tf]
        if host:
            conds.append(f"host ILIKE '%{host.replace(chr(39), '')}%'")
        if user_name:
            conds.append(f"user_name ILIKE '%{user_name.replace(chr(39), '')}%'")
        if threat_score_min > 0:
            conds.append(f"threat_score >= {int(threat_score_min)}")
        if is_dga:
            conds.append(f"dga_flag = '{is_dga}'")
        if is_tunneling:
            conds.append("tunneling > 0")
        if app_name:
            conds.append(f"appid_name ILIKE '%{app_name.replace(chr(39), '')}%'")
        if src_country:
            conds.append(f"country_code = '{src_country.replace(chr(39), '')}'")
        if domain:
            conds.append(f"primary_domain ILIKE '%{domain.replace(chr(39), '')}%'")
        if search:
            s = search.replace("'", "")
            if s.isdigit():
                # Integer equality lets DuckDB use parquet row-group min/max stats
                conds.append(
                    f"(host ILIKE '%{s}%' OR user_name ILIKE '%{s}%' OR "
                    f"engid_name ILIKE '%{s}%' OR appid_name ILIKE '%{s}%' OR "
                    f"primary_domain ILIKE '%{s}%' OR src_ip ILIKE '%{s}%' OR "
                    f"event_id = {int(s)})"
                )
            else:
                conds.append(
                    f"(host ILIKE '%{s}%' OR user_name ILIKE '%{s}%' OR "
                    f"engid_name ILIKE '%{s}%' OR appid_name ILIKE '%{s}%' OR "
                    f"primary_domain ILIKE '%{s}%' OR src_ip ILIKE '%{s}%')"
                )
        return conds

    def _query_index(idx: str) -> tuple[int, list]:
        paths, _ = _build_sources(idx, start_dt, end_dt)
        if not paths:
            return 0, []
        src = _read_parquet(paths)
        if not src:
            return 0, []
        conn = get_oci_conn()
        tf = _ts_filter_parquet(start, end)
        where = " AND ".join(_build_conditions(tf))
        # fmt: off
        _COLS = [
            "ts", "src_ip", "host", "user_name", "engid_name", "appid_name",   # 0-5
            "threat_score", "dga_flag", "tunneling", "country_code",            # 6-9
            "primary_domain", "domain_reputation", "msg_class", "event_type",   # 10-13
            "fidelity", "dst_ip", "severity",                                   # 14-16
            "hostname", "login_type", "login_result", "process_name", "event_id",  # 17-21
            "kill_chain_stage", "tactic", "technique",                          # 22-24
            "srcip_reputation", "dstip_reputation",                             # 25-26
        ]
        # fmt: on
        try:
            # Describe available columns to avoid Binder Error on absent columns
            avail = {r[0] for r in conn.execute(f"DESCRIBE SELECT * FROM {src} LIMIT 0").fetchall()}
            sel = ", ".join(f"{c}" if c in avail else f"NULL AS {c}" for c in _COLS)
            # Single scan: window COUNT(*) OVER () + data in one pass
            raw = conn.execute(
                f"SELECT count(*) OVER () AS _total, {sel} "
                f"FROM {src} WHERE {where} ORDER BY ts DESC LIMIT 5000"
            ).fetchall()
            cnt = raw[0][0] if raw else 0
            rows = [r[1:] for r in raw]  # strip _total prefix
            return cnt, [(idx, r) for r in rows]
        except Exception as _exc:
            import logging as _log
            _log.getLogger("uvicorn").warning("browse _query_index [%s] error: %s", idx, _exc)
            return 0, []

    # Query each index separately so one corrupted file doesn't break others
    total_count = 0
    all_rows: list[tuple[str, tuple]] = []
    for idx in indexes:
        cnt, rows = _query_index(idx)
        total_count += cnt
        all_rows.extend(rows)

    if not all_rows:
        return {"total": 0, "page": page, "page_size": page_size, "pages": 0, "items": []}

    # Sort combined results by ts desc and paginate
    all_rows.sort(key=lambda x: x[1][0] or "", reverse=True)
    offset = (page - 1) * page_size
    page_rows = all_rows[offset: offset + page_size]

    items = [
        {
            "id": None,
            "index": idx_name,
            "ts": r[0],
            "severity": r[16],
            # host fallback chain: host JSON → hostname column → engid_name → src_ip
            "host": _parse_host(r[2]) or r[17] or r[4] or r[1],
            "user_name": r[3],
            "event_type": r[13] or r[12],  # event_type → msg_class fallback
            "src_ip": r[1],
            "dst_ip": r[15],
            "raw": {
                "engid_name": r[4], "appid_name": r[5],
                "threat_score": r[6], "is_dga": r[7],
                "is_tunneling": r[8] if r[8] else 0, "country_code": r[9],
                "primary_domain": r[10], "domain_reputation": r[11],
                "msg_class": r[12], "fidelity": r[14],
                "hostname": r[17], "login_type": r[18], "login_result": r[19],
                "process_name": r[20], "event_id": r[21],
                "kill_chain_stage": r[22], "tactic": r[23], "technique": r[24],
                "srcip_reputation": r[25], "dstip_reputation": r[26],
            },
        }
        for idx_name, r in page_rows
    ]
    return {
        "total": total_count,
        "page": page,
        "page_size": page_size,
        "pages": (total_count + page_size - 1) // page_size,
        "items": items,
        "source": "oci_parquet",
    }


# ── PCI Coverage (always NDJSON — needs exact counts over all time) ────────────

def coverage_by_month(index: str, months: int = 3) -> list[dict]:
    end = datetime.now(UTC)
    start = end - timedelta(days=months * 30)
    conn = get_conn()
    rows = conn.execute(
        "SELECT date::VARCHAR, total FROM daily_stats WHERE index=? AND date >= ? ORDER BY date",
        [index, start.date().isoformat()],
    ).fetchall()
    return [{"day": r[0], "count": r[1]} for r in rows]
