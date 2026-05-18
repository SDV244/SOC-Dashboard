import threading
from pathlib import Path

import duckdb

from backend.config import get_settings

_local    = threading.local()   # thread-local para conexión local (DuckDB file)
_oci_local = threading.local()  # thread-local para conexión OCI (httpfs, reutilizable)
_db_path: str | None = None


def setup_httpfs(conn: duckdb.DuckDBPyConnection) -> None:
    settings = get_settings()
    endpoint = settings.s3_endpoint.removeprefix("https://").removeprefix("http://")
    tmp_dir = Path(settings.db_path).parent / "duckdb_tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    conn.execute(f"SET temp_directory='{tmp_dir.as_posix()}';")
    conn.execute("INSTALL httpfs; LOAD httpfs;")
    conn.execute(f"SET s3_endpoint='{endpoint}';")
    conn.execute(f"SET s3_access_key_id='{settings.aws_access_key_id}';")
    conn.execute(f"SET s3_secret_access_key='{settings.aws_secret_access_key}';")
    conn.execute(f"SET s3_region='{settings.s3_region}';")
    conn.execute("SET s3_url_style='path';")
    conn.execute("SET s3_use_ssl=true;")


def get_oci_conn() -> duckdb.DuckDBPyConnection:
    """Conexión reutilizable por thread para queries Parquet/httpfs."""
    conn = getattr(_oci_local, "conn", None)
    if conn is not None:
        try:
            conn.execute("SELECT 1")
            return conn
        except Exception:
            _oci_local.conn = None
    conn = duckdb.connect(":memory:")
    conn.execute("SET threads=4; SET memory_limit='4GB';")
    setup_httpfs(conn)
    _oci_local.conn = conn
    return conn


def has_local_data(index: str | None, start: str, end: str) -> bool:
    conn = get_conn()
    if index:
        row = conn.execute(
            "SELECT 1 FROM logs WHERE index=? AND ts BETWEEN ? AND ? LIMIT 1",
            [index, start, end],
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT 1 FROM logs WHERE ts BETWEEN ? AND ? LIMIT 1",
            [start, end],
        ).fetchone()
    return row is not None


def get_conn() -> duckdb.DuckDBPyConnection:
    global _db_path
    if not hasattr(_local, "conn") or _local.conn is None:
        settings = get_settings()
        if _db_path is None:
            _db_path = str(Path(settings.db_path))
            Path(_db_path).parent.mkdir(parents=True, exist_ok=True)
        _local.conn = duckdb.connect(_db_path)
        _init_schema(_local.conn)
    return _local.conn


def _init_schema(conn: duckdb.DuckDBPyConnection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id          VARCHAR,
            index       VARCHAR,
            tenant      VARCHAR,
            ts          TIMESTAMPTZ,
            severity    VARCHAR,
            host        VARCHAR,
            user_name   VARCHAR,
            event_type  VARCHAR,
            src_ip      VARCHAR,
            dst_ip      VARCHAR,
            raw         JSON
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ts    ON logs(ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_index ON logs(index)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS ingested_files (
            path        VARCHAR PRIMARY KEY,
            ingested_at TIMESTAMPTZ DEFAULT now(),
            row_count   INTEGER
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS sync_status (
            id          INTEGER PRIMARY KEY DEFAULT 1,
            last_sync   TIMESTAMPTZ,
            last_status VARCHAR,
            details     VARCHAR
        )
    """)
    conn.execute("""
        INSERT OR IGNORE INTO sync_status (id, last_sync, last_status, details)
        VALUES (1, NULL, 'never', '')
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS parquet_months (
            index       VARCHAR,
            year        INTEGER,
            month       INTEGER,
            row_count   INTEGER,
            converted_at TIMESTAMPTZ DEFAULT now(),
            PRIMARY KEY (index, year, month)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS daily_stats (
            index                VARCHAR,
            date                 DATE,
            total                BIGINT,
            threat_high          BIGINT,
            dga                  BIGINT,
            tunneling            BIGINT,
            top_apps             JSON,
            top_geo              JSON,
            top_domains          JSON,
            top_threats          JSON,
            top_hosts            JSON,
            top_event_types      JSON,
            top_users            JSON,
            timeline_json        JSON,
            top_processes        JSON,
            login_stats          JSON,
            avg_fidelity         DOUBLE,
            high_confidence_cnt  BIGINT,
            bad_ip_rep_cnt       BIGINT,
            PRIMARY KEY (index, date)
        )
    """)
    # Migrate existing tables that predate new columns
    for col, typedef in [
        ("top_processes",       "JSON"),
        ("login_stats",         "JSON"),
        ("avg_fidelity",        "DOUBLE"),
        ("high_confidence_cnt", "BIGINT"),
        ("bad_ip_rep_cnt",      "BIGINT"),
    ]:
        try:
            conn.execute(f"ALTER TABLE daily_stats ADD COLUMN {col} {typedef}")
        except Exception:
            pass
