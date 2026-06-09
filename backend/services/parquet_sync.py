"""
Parquet conversion service.

Converts NDJSON.gz files in OCI Object Storage to columnar Parquet,
enabling 10-50x faster queries via column pruning and predicate pushdown.

Source:  s3://{bucket}/organization={org}/index={index}/tenant={tenant}/year={y}/month={m}/**/*.gz
Parquet: s3://{bucket}/parquet/org={org}/index={index}/tenant={tenant}/year={y}/month={m}/part.parquet
"""

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, wait as _futures_wait
from datetime import UTC, datetime
from pathlib import Path

import duckdb

from backend.config import get_settings
from backend.db import get_conn, setup_httpfs

# VM tiene 12GB RAM. 4 workers × 2GB = 8GB peak + ~2GB overhead = ~10GB total.
_DAY_WORKERS = 4
_MEM_PER_WORKER = "2000MB"
_DAY_TIMEOUT_S = 1800  # 30 min per day; prevents ADR-style infinite hangs

_sync_lock = threading.Lock()
_sync_state: dict = {"running": False, "progress": [], "error": None}


# ── Path helpers ──────────────────────────────────────────────────────────────

def parquet_dir(index: str, year: int, month: int) -> str:
    """Returns the directory containing daily Parquet files for a month."""
    s = get_settings()
    base = Path(s.parquet_base) if s.parquet_base else Path(s.db_path).parent / "parquet"
    return str(base / f"index={index}" / f"year={year:04d}" / f"month={month:02d}")


def parquet_path(index: str, year: int, month: int) -> str:
    """Returns glob pattern to scan all daily Parquet files for a month."""
    return parquet_dir(index, year, month) + "/day=*.parquet"


def src_glob(index: str, year: int, month: int) -> str:
    s = get_settings()
    return (
        f"s3://{s.s3_bucket}/"
        f"organization={s.org_id}/index={index}/tenant={s.tenant_id}/"
        f"year={year:04d}/month={month:02d}/**/*.gz"
    )


# ── Local status table ────────────────────────────────────────────────────────

def ensure_parquet_table() -> None:
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS parquet_months (
            index       VARCHAR,
            year        INTEGER,
            month       INTEGER,
            row_count   BIGINT,
            converted_at TIMESTAMPTZ DEFAULT now(),
            PRIMARY KEY (index, year, month)
        )
    """)
    try:
        col_type = conn.execute(
            "SELECT data_type FROM information_schema.columns "
            "WHERE table_name='parquet_months' AND column_name='row_count'"
        ).fetchone()
        if col_type and col_type[0].upper() != "BIGINT":
            conn.execute("ALTER TABLE parquet_months ALTER COLUMN row_count TYPE BIGINT")
            conn.execute("CHECKPOINT")
    except Exception:
        pass


def mark_converted(index: str, year: int, month: int, row_count: int) -> None:
    ensure_parquet_table()
    conn = get_conn()
    conn.execute(
        "INSERT OR REPLACE INTO parquet_months (index, year, month, row_count) VALUES (?, ?, ?, ?)",
        [index, year, month, row_count],
    )
    _converted_cache.add((index, year, month))


_converted_cache: set[tuple[str, int, int]] = set()
_converted_cache_loaded = False


def _load_converted_cache() -> None:
    global _converted_cache_loaded
    ensure_parquet_table()
    conn = get_conn()
    rows = conn.execute("SELECT index, year, month FROM parquet_months").fetchall()
    _converted_cache.update((r[0], r[1], r[2]) for r in rows)
    _converted_cache_loaded = True


def is_converted(index: str, year: int, month: int) -> bool:
    if not _converted_cache_loaded:
        _load_converted_cache()
    return (index, year, month) in _converted_cache


def list_converted() -> list[dict]:
    ensure_parquet_table()
    conn = get_conn()
    rows = conn.execute(
        "SELECT index, year, month, row_count, converted_at FROM parquet_months ORDER BY index, year, month"
    ).fetchall()
    return [
        {"index": r[0], "year": r[1], "month": r[2], "row_count": r[3], "converted_at": str(r[4])}
        for r in rows
    ]


# ── Conversion ────────────────────────────────────────────────────────────────

_SELECT_COLS = """
    to_timestamp(CAST(timestamp AS BIGINT) / 1000)::TIMESTAMPTZ AS ts,
    COALESCE(threat_score, TRY_CAST(risk_score AS INTEGER))       AS threat_score,
    severity,
    confidence,
    is_dga                                                        AS dga_flag,
    is_tunneling                                                  AS tunneling,
    srcip                                                         AS src_ip,
    srcip_type,
    srcip_geo.countryCode                                         AS country_code,
    dstip                                                         AS dst_ip,
    srcport                                                       AS src_port,
    dstport                                                       AS dst_port,
    proto,
    engid_name,
    appid_name,
    CASE WHEN domain_list IS NOT NULL AND len(domain_list) > 0
         THEN domain_list[1] ELSE NULL END                        AS primary_domain,
    domain_list                                                   AS all_domains,
    domain_reputation,
    kill_chain_stage,
    tactic,
    technique,
    msg_class,
    COALESCE(
        NULLIF(event_type, ''),
        NULLIF(task, ''),
        NULLIF(event.type, ''),
        CASE WHEN data_sources IS NOT NULL AND len(data_sources) > 0
             THEN data_sources[1] END
    )                                                             AS event_type,
    host,
    COALESCE(
        NULLIF(user_name, ''),
        NULLIF(username, ''),
        NULLIF(login_user, ''),
        NULLIF(exec_user, ''),
        NULLIF(event_data['SubjectUserName'], ''),
        NULLIF(event_data['TargetUserName'], ''),
        NULLIF(srcip_username, ''),
        NULLIF(hostip_username, ''),
        NULLIF(process_user, ''),
        NULLIF(user.name, ''),
        CASE WHEN name IS NOT NULL AND len(name) > 0 THEN name[1] END
    ) AS user_name,
    COALESCE(
        NULLIF(hostname, ''),
        NULLIF(computer_name, ''),
        NULLIF(hostip_host, '')
    )                                                             AS hostname,
    login_type,
    login_result,
    fidelity,
    actual,
    typical,
    COALESCE(
        NULLIF(process_name, ''),
        NULLIF(process.name, ''),
        NULLIF(file_path, '')
    )                                                             AS process_name,
    COALESCE(
        NULLIF(parent_proc_name, ''),
        NULLIF(process.parent.name, '')
    )                                                             AS parent_proc_name,
    hostip                                                         AS host_ip,
    event_id,
    srcip_reputation,
    dstip_reputation,
    weighted_anomaly_score,
    result
"""

_READ_COLS = """{
    'timestamp':        'BIGINT',
    'threat_score':     'INTEGER',
    'severity':         'VARCHAR',
    'confidence':       'INTEGER',
    'is_dga':           'VARCHAR',
    'is_tunneling':     'INTEGER',
    'srcip':            'VARCHAR',
    'srcip_type':       'VARCHAR',
    'srcip_geo':        'STRUCT(countryCode VARCHAR)',
    'dstip':            'VARCHAR',
    'srcport':          'INTEGER',
    'dstport':          'INTEGER',
    'proto':            'VARCHAR',
    'engid_name':       'VARCHAR',
    'appid_name':       'VARCHAR',
    'domain_list':      'VARCHAR[]',
    'domain_reputation':'VARCHAR',
    'kill_chain_stage': 'VARCHAR',
    'tactic':           'VARCHAR',
    'technique':        'VARCHAR',
    'msg_class':        'VARCHAR',
    'event_type':       'VARCHAR',
    'host':             'VARCHAR',
    'user_name':        'VARCHAR',
    'username':         'VARCHAR',
    'login_user':       'VARCHAR',
    'exec_user':        'VARCHAR',
    'event_data':       'MAP(VARCHAR, VARCHAR)',
    'srcip_username':   'VARCHAR',
    'srcip_usersid':    'VARCHAR',
    'hostip_username':  'VARCHAR',
    'hostip_usersid':   'VARCHAR',
    'process_user':     'VARCHAR',
    'hostname':         'VARCHAR',
    'computer_name':    'VARCHAR',
    'login_type':       'VARCHAR',
    'login_result':     'VARCHAR',
    'fidelity':               'INTEGER',
    'actual':                 'DOUBLE',
    'typical':                'DOUBLE',
    'process_name':           'VARCHAR',
    'parent_proc_name':       'VARCHAR',
    'hostip':                 'VARCHAR',
    'event_id':               'INTEGER',
    'srcip_reputation':       'VARCHAR',
    'dstip_reputation':       'VARCHAR',
    'weighted_anomaly_score': 'DOUBLE',
    'result':                 'VARCHAR',
    'name':                   'VARCHAR[]',
    'risk_score':             'DOUBLE',
    'data_sources':           'VARCHAR[]',
    'user':                   'STRUCT(name VARCHAR)',
    'process':                'STRUCT(name VARCHAR, parent STRUCT(name VARCHAR))',
    'event':                  'STRUCT(type VARCHAR)',
    'hostip_host':            'VARCHAR',
    'file_path':              'VARCHAR',
    'task':                   'VARCHAR'
}"""


def _day_glob(index: str, year: int, month: int, day: int) -> str:
    s = get_settings()
    return (
        f"s3://{s.s3_bucket}/"
        f"organization={s.org_id}/index={index}/tenant={s.tenant_id}/"
        f"year={year:04d}/month={month:02d}/day={day:02d}/**/*.gz"
    )


def _month_glob(index: str, year: int, month: int) -> str:
    s = get_settings()
    return (
        f"s3://{s.s3_bucket}/"
        f"organization={s.org_id}/index={index}/tenant={s.tenant_id}/"
        f"year={year:04d}/month={month:02d}/**/*.gz"
    )


def _oci_month_has_data(index: str, year: int, month: int) -> bool:
    """Single S3 LIST call to check if any files exist for this month. Fast — no download."""
    from backend.db import get_oci_conn
    glob = _month_glob(index, year, month)
    try:
        conn = get_oci_conn()
        row = conn.execute(f"SELECT count(*) FROM glob('{glob}')").fetchone()
        return bool(row and row[0] > 0)
    except Exception:
        return False


def _convert_day_task(args: tuple) -> tuple[int, int, str | None]:
    """Convert one day to Parquet. Returns (day, row_count, error_msg|None)."""
    index, year, month, day, dst_dir = args
    src = _day_glob(index, year, month, day)
    dst = str(Path(dst_dir) / f"day={day:02d}.parquet")
    conn = duckdb.connect(":memory:")
    setup_httpfs(conn)
    conn.execute(f"SET memory_limit='{_MEM_PER_WORKER}'")
    conn.execute("SET temp_directory='/data/duckdb_tmp'")
    try:
        conn.execute(f"""
            COPY (SELECT {_SELECT_COLS}
                  FROM read_json('{src}', format='newline_delimited',
                      compression='gzip', ignore_errors=true, columns={_READ_COLS}))
            TO '{dst}' (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 100000)
        """)
        rows = conn.execute(f"SELECT count(*) FROM parquet_scan('{dst}')").fetchone()[0]
        return day, rows, None
    except Exception as e:
        return day, 0, str(e)[:200]
    finally:
        conn.close()


def convert_month(index: str, year: int, month: int) -> int:
    """
    Convert one month using _DAY_WORKERS parallel workers, one Parquet per day.
    Skips immediately if OCI has no data for the month (fast S3 LIST check).
    Peak RAM = _DAY_WORKERS × _MEM_PER_WORKER. Safe for 12GB VM.
    Returns total rows written. Raises if no data found for the month.
    """
    import calendar
    if not _oci_month_has_data(index, year, month):
        return 0
    dst_dir = parquet_dir(index, year, month)
    Path(dst_dir).mkdir(parents=True, exist_ok=True)
    Path("/data/duckdb_tmp").mkdir(exist_ok=True)

    days = calendar.monthrange(year, month)[1]
    from datetime import date as _date
    _today = _date.today()
    tasks = []
    for day in range(1, days + 1):
        # Never ingest the current calendar day — OCI data is incomplete until midnight
        if year == _today.year and month == _today.month and day == _today.day:
            continue
        dst_file = Path(dst_dir) / f"day={day:02d}.parquet"
        if not (dst_file.exists() and dst_file.stat().st_size > 0):
            tasks.append((index, year, month, day, dst_dir))
    if not tasks:
        return 0

    total_rows = 0
    timeout_budget = _DAY_TIMEOUT_S * max(len(tasks), 1)
    with ThreadPoolExecutor(max_workers=_DAY_WORKERS) as pool:
        futs = [pool.submit(_convert_day_task, t) for t in tasks]
        done, not_done = _futures_wait(futs, timeout=timeout_budget)
        for f in not_done:
            f.cancel()
        if not_done:
            import logging as _log2; _log2.getLogger(__name__).warning(
                "convert_month %s %d-%02d: %d day(s) timed out after %ds",
                index, year, month, len(not_done), timeout_budget)
        for f in done:
            try:
                _day, rows, _err = f.result()
                total_rows += rows
            except Exception:
                pass

    if total_rows == 0:
        raise FileNotFoundError(f"No data found for {index} {year}-{month:02d}")
    return total_rows


# ── Background bulk conversion ────────────────────────────────────────────────

def _iter_months(start: datetime, end: datetime):
    current = start.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    while current <= end:
        yield current.year, current.month
        if current.month == 12:
            current = current.replace(year=current.year + 1, month=1)
        else:
            current = current.replace(month=current.month + 1)


def _run_bulk_sync(indexes: list[str], months_back: int) -> None:
    global _sync_state
    end = datetime.now(UTC)
    # Exact calendar months: months_back=5 in May 2026 → start = Jan 2026
    start_month = end.month - (months_back - 1)
    start_year = end.year
    while start_month <= 0:
        start_month += 12
        start_year -= 1
    start = end.replace(year=start_year, month=start_month, day=1,
                        hour=0, minute=0, second=0, microsecond=0)

    all_months = list(reversed(list(_iter_months(start, end))))  # newest first
    total = len(all_months) * len(indexes)
    done = 0
    errors = []

    for index in indexes:
        for year, month in all_months:
            label = f"{index} {year}-{month:02d}"
            if is_converted(index, year, month):
                _sync_state["progress"].append({"month": label, "status": "skipped (already done)"})
                done += 1
                _sync_state["pct"] = round(done / total * 100, 1)
                continue
            _sync_state["progress"].append({"month": label, "status": "converting..."})
            _sync_state["current"] = label
            try:
                rows = convert_month(index, year, month)
                mark_converted(index, year, month, rows)
                compute_daily_stats(index, year, month)
                _sync_state["progress"][-1] = {"month": label, "status": f"ok ({rows:,} rows)"}
            except Exception as exc:
                msg = str(exc)[:200]
                errors.append(f"{label}: {msg}")
                _sync_state["progress"][-1] = {"month": label, "status": f"error: {msg}"}
            done += 1
            _sync_state["pct"] = round(done / total * 100, 1)

    _sync_state["running"] = False
    _sync_state["error"] = errors if errors else None
    _sync_state["finished_at"] = datetime.now(UTC).isoformat()


def refresh_current_months(indexes: list[str] | None = None) -> bool:
    """
    Download only missing days of the current month for all configured indexes.
    Uses delta sync: days that already have a local parquet file are skipped.
    Non-blocking — runs in background thread.
    """
    now = datetime.now(UTC)
    year, month = now.year, now.month

    settings = get_settings()
    idx = indexes or settings.indexes

    def _run() -> None:
        for index in idx:
            try:
                rows = convert_month(index, year, month)
                if rows > 0:
                    mark_converted(index, year, month, rows)
                compute_daily_stats(index, year, month)
            except Exception:
                pass

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return True


def start_bulk_sync(indexes: list[str] | None = None, months_back: int = 12) -> bool:
    """Launch bulk conversion in a background thread. Returns False if already running."""
    global _sync_state
    with _sync_lock:
        if _sync_state["running"]:
            return False
        settings = get_settings()
        _sync_state = {
            "running": True,
            "progress": [],
            "pct": 0,
            "error": None,
            "started_at": datetime.now(UTC).isoformat(),
        }
    idx = indexes or settings.indexes
    t = threading.Thread(target=_run_bulk_sync, args=(idx, months_back), daemon=True)
    t.start()
    return True


def sync_status() -> dict:
    return dict(_sync_state)


# ── Daily stats pre-aggregation ──────────────────────────────────────────────

def compute_daily_stats(index: str, year: int, month: int, force: bool = False) -> int:
    """
    Compute per-day aggregates from local Parquet files and store in daily_stats.
    Called after convert_month so KPI queries read 7 rows instead of 580M.
    Returns number of days processed.
    force=True overwrites existing rows (use to backfill new columns).
    """
    import json
    from glob import glob as _glob

    dst_dir = parquet_dir(index, year, month)
    day_files = sorted(_glob(str(Path(dst_dir) / "day=*.parquet")))
    if not day_files:
        return 0

    conn = get_conn()
    processed = 0

    for day_file in day_files:
        day_num = int(Path(day_file).stem.split("=")[1])
        date_str = f"{year:04d}-{month:02d}-{day_num:02d}"

        if not force:
            existing = conn.execute(
                "SELECT 1 FROM daily_stats WHERE index=? AND date=?", [index, date_str]
            ).fetchone()
            if existing:
                processed += 1
                continue

        try:
            f = day_file.replace("\\", "/")
            overview = conn.execute(f"""
                SELECT
                    count(*)                                   AS total,
                    count(*) FILTER (WHERE threat_score > 50) AS threat_high,
                    count(*) FILTER (WHERE dga_flag = 'yes')  AS dga,
                    count(*) FILTER (WHERE tunneling > 0)     AS tunneling
                FROM parquet_scan('{f}')
            """).fetchone()

            apps = conn.execute(f"""
                SELECT coalesce(appid_name,'unknown'), count(*)
                FROM parquet_scan('{f}') GROUP BY 1 ORDER BY 2 DESC LIMIT 20
            """).fetchall()

            geo = conn.execute(f"""
                SELECT coalesce(country_code,'unknown'), count(*)
                FROM parquet_scan('{f}') GROUP BY 1 ORDER BY 2 DESC LIMIT 20
            """).fetchall()

            domains = conn.execute(f"""
                SELECT primary_domain, count(*),
                       coalesce(domain_reputation,'unknown'), coalesce(dga_flag,'no')
                FROM parquet_scan('{f}')
                WHERE primary_domain IS NOT NULL
                GROUP BY 1,3,4 ORDER BY 2 DESC LIMIT 20
            """).fetchall()

            threats = conn.execute(f"""
                SELECT coalesce(engid_name,'unknown'), max(threat_score), count(*)
                FROM parquet_scan('{f}')
                WHERE threat_score > 0
                GROUP BY 1 ORDER BY 2 DESC, 3 DESC LIMIT 20
            """).fetchall()

            hosts = conn.execute(f"""
                SELECT coalesce(
                    hostname,
                    CASE WHEN host LIKE '{{%' THEN json_extract_string(host, '$.name') END,
                    CASE WHEN host LIKE '{{%' THEN json_extract_string(host, '$.ip') END,
                    host, 'unknown'
                ), count(*)
                FROM parquet_scan('{f}', union_by_name=true)
                GROUP BY 1 ORDER BY 2 DESC LIMIT 20
            """).fetchall()

            event_types = conn.execute(f"""
                SELECT coalesce(event_type,'unknown'), count(*)
                FROM parquet_scan('{f}') GROUP BY 1 ORDER BY 2 DESC LIMIT 20
            """).fetchall()

            top_users = conn.execute(f"""
                SELECT coalesce(user_name,'unknown'), count(*)
                FROM parquet_scan('{f}', union_by_name=true)
                WHERE user_name IS NOT NULL
                GROUP BY 1 ORDER BY 2 DESC LIMIT 20
            """).fetchall()

            timeline = conn.execute(f"""
                SELECT date_part('hour', ts), coalesce(msg_class,'unknown'), count(*)
                FROM parquet_scan('{f}') GROUP BY 1, 2 ORDER BY 1
            """).fetchall()

            top_processes = conn.execute(f"""
                SELECT coalesce(process_name,'unknown'), count(*)
                FROM parquet_scan('{f}', union_by_name=true)
                WHERE process_name IS NOT NULL
                GROUP BY 1 ORDER BY 2 DESC LIMIT 20
            """).fetchall()

            login_stats = conn.execute(f"""
                SELECT
                    count(*) FILTER (WHERE lower(login_result) IN ('failure','failed','0')) AS failed,
                    count(*) FILTER (WHERE lower(login_result) IN ('success','succeeded','1')) AS successful,
                    count(*) FILTER (WHERE login_type IS NOT NULL) AS total_logins
                FROM parquet_scan('{f}', union_by_name=true)
            """).fetchone()

            top_login_types = conn.execute(f"""
                SELECT login_type, count(*)
                FROM parquet_scan('{f}', union_by_name=true)
                WHERE login_type IS NOT NULL
                GROUP BY 1 ORDER BY 2 DESC LIMIT 10
            """).fetchall()

            fidelity_stats = conn.execute(f"""
                SELECT
                    avg(fidelity) FILTER (WHERE fidelity IS NOT NULL),
                    count(*) FILTER (WHERE threat_score > 50 AND fidelity > 70)
                FROM parquet_scan('{f}', union_by_name=true)
            """).fetchone()

            bad_ip = conn.execute(f"""
                SELECT count(*) FROM parquet_scan('{f}', union_by_name=true)
                WHERE srcip_reputation IN ('Bad','Malicious','suspicious')
                   OR dstip_reputation IN ('Bad','Malicious','suspicious')
            """).fetchone()

            conn.execute("""
                INSERT OR REPLACE INTO daily_stats
                (index, date, total, threat_high, dga, tunneling,
                 top_apps, top_geo, top_domains, top_threats,
                 top_hosts, top_event_types, top_users, timeline_json,
                 top_processes, login_stats, avg_fidelity,
                 high_confidence_cnt, bad_ip_rep_cnt)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                index, date_str,
                overview[0], overview[1], overview[2], overview[3],
                json.dumps([{"app": r[0], "count": r[1]} for r in apps]),
                json.dumps([{"country": r[0], "count": r[1]} for r in geo]),
                json.dumps([{"domain": r[0], "count": r[1], "reputation": r[2], "is_dga": r[3]} for r in domains]),
                json.dumps([{"device": r[0], "max_score": r[1], "count": r[2]} for r in threats]),
                json.dumps([{"host": r[0], "count": r[1]} for r in hosts]),
                json.dumps([{"event_type": r[0], "count": r[1]} for r in event_types]),
                json.dumps([{"user": r[0], "count": r[1]} for r in top_users]),
                json.dumps([{"hour": r[0], "msg_class": r[1], "count": r[2]} for r in timeline]),
                json.dumps([{"process": r[0], "count": r[1]} for r in top_processes]),
                json.dumps({
                    "failed": login_stats[0] or 0,
                    "successful": login_stats[1] or 0,
                    "total_logins": login_stats[2] or 0,
                    "top_types": [{"type": r[0], "count": r[1]} for r in top_login_types],
                }),
                fidelity_stats[0],
                fidelity_stats[1] or 0,
                bad_ip[0] or 0,
            ])
            processed += 1
        except Exception:
            pass

    return processed


def backfill_daily_stats(indexes: list[str] | None = None, force: bool = False) -> int:
    """
    Compute daily_stats for all converted months.
    force=True rewrites existing rows (use after adding new columns).
    Returns total days processed.
    """
    conn = get_conn()
    rows = conn.execute(
        "SELECT index, year, month FROM parquet_months ORDER BY index, year, month"
    ).fetchall()

    settings = get_settings()
    idx_filter = set(indexes or settings.indexes)

    total = 0
    for index, year, month in rows:
        if index not in idx_filter:
            continue
        try:
            total += compute_daily_stats(index, year, month, force=force)
        except Exception:
            pass
    return total


# ── Auto-recovery on startup ──────────────────────────────────────────────────

def recover_from_disk() -> int:
    """
    Scan parquet directory and register any months not in parquet_months.
    Called on app startup so the registry survives container rebuilds.
    Returns number of months newly registered.
    """
    import re
    s = get_settings()
    base = Path(s.parquet_base) if s.parquet_base else Path(s.db_path).parent / "parquet"
    if not base.exists():
        return 0

    ensure_parquet_table()
    conn = get_conn()
    already = {
        (r[0], r[1], r[2])
        for r in conn.execute("SELECT index, year, month FROM parquet_months").fetchall()
    }

    pattern = re.compile(r"index=(\w+)/year=(\d{4})/month=(\d{2})/day=\d+\.parquet$")
    months: dict[tuple, list[Path]] = {}
    for f in sorted(base.rglob("day=*.parquet")):
        rel = f.relative_to(base).as_posix()
        m = pattern.search(rel)
        if not m:
            continue
        key = (m.group(1), int(m.group(2)), int(m.group(3)))
        months.setdefault(key, []).append(f)

    registered = 0
    for (index, year, month), files in sorted(months.items()):
        if (index, year, month) in already:
            continue
        rows = 0
        for f in files:
            try:
                rows += conn.execute(f"SELECT count(*) FROM parquet_scan('{f}')").fetchone()[0]
            except Exception:
                f.unlink(missing_ok=True)
        if rows == 0:
            continue
        conn.execute(
            "INSERT OR REPLACE INTO parquet_months (index, year, month, row_count) VALUES (?, ?, ?, ?)",
            [index, year, month, rows],
        )
        _converted_cache.add((index, year, month))
        registered += 1

    return registered
