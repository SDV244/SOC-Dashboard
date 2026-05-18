"""
Direct OCI log search — queries NDJSON.gz files in OCI for date ranges not yet converted to Parquet.

Performance trick: simple SELECT with LIMIT (no GROUP BY) — DuckDB stops reading once limit is hit.
Max 3 days enforced to keep response time under ~10s.
"""

from datetime import datetime

from fastapi import APIRouter, HTTPException, Query

from backend.config import get_settings
from backend.db import get_oci_conn

router = APIRouter(prefix="/api/oci", tags=["oci-search"])

_COLUMNS = """{
    'timestamp':        'BIGINT',
    'threat_score':     'INTEGER',
    'severity':         'VARCHAR',
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
    'user_name':        'VARCHAR'
}"""


def _day_glob(index: str, year: int, month: int, day: int) -> str:
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


@router.get("/search")
def oci_search(
    index: str = Query(..., description="Index to search (e.g. adr, syslog, wineventlog)"),
    start: str = Query(..., description="ISO datetime start"),
    end: str = Query(..., description="ISO datetime end — max 3 days from start"),
    host: str | None = Query(default=None),
    user_name: str | None = Query(default=None),
    threat_score_min: int = Query(default=0, ge=0, le=100),
    src_ip: str | None = Query(default=None),
    search: str | None = Query(default=None, description="Free text search across key fields"),
    limit: int = Query(default=200, ge=1, le=500),
) -> dict:
    """
    Search OCI logs directly. Returns up to `limit` rows from NDJSON.gz files.
    Fast because: day-level globs + simple SELECT with LIMIT (DuckDB stops reading early).
    """
    try:
        start_dt = datetime.fromisoformat(start)
        end_dt = datetime.fromisoformat(end)
    except ValueError as e:
        raise HTTPException(400, f"Invalid datetime: {e}")

    day_diff = (end_dt - start_dt).days
    if day_diff > 3:
        raise HTTPException(400, "Max range is 3 days for OCI search. Use a narrower date range.")
    if day_diff < 0:
        raise HTTPException(400, "start must be before end")

    globs = [_day_glob(index, y, m, d) for y, m, d in _iter_days(start_dt, end_dt)]
    joined = ", ".join(f"'{g}'" for g in globs)
    src = (
        f"read_json([{joined}], format='newline_delimited', "
        f"ignore_errors=true, compression='gzip', columns={_COLUMNS})"
    )

    ts_filter = (
        f"to_timestamp(CAST(timestamp AS BIGINT) / 1000) "
        f"BETWEEN '{start}'::TIMESTAMPTZ AND '{end}'::TIMESTAMPTZ"
    )
    conditions = [ts_filter]

    def _safe(s: str) -> str:
        return s.replace("'", "")

    if host:
        conditions.append(f"host ILIKE '%{_safe(host)}%'")
    if user_name:
        conditions.append(f"user_name ILIKE '%{_safe(user_name)}%'")
    if src_ip:
        conditions.append(f"srcip ILIKE '%{_safe(src_ip)}%'")
    if threat_score_min > 0:
        conditions.append(f"threat_score >= {int(threat_score_min)}")
    if search:
        s = _safe(search)
        conditions.append(
            f"(host ILIKE '%{s}%' OR user_name ILIKE '%{s}%' OR "
            f"engid_name ILIKE '%{s}%' OR appid_name ILIKE '%{s}%' OR srcip ILIKE '%{s}%')"
        )

    where = " AND ".join(conditions)
    conn = get_oci_conn()

    try:
        rows = conn.execute(f"""
            SELECT
                to_timestamp(CAST(timestamp AS BIGINT) / 1000) AS ts,
                host,
                user_name,
                srcip                                           AS src_ip,
                dstip                                           AS dst_ip,
                threat_score,
                is_dga,
                is_tunneling,
                srcip_geo.countryCode                           AS country_code,
                engid_name,
                appid_name,
                CASE WHEN domain_list IS NOT NULL AND len(domain_list) > 0
                     THEN domain_list[1] ELSE NULL END          AS primary_domain,
                domain_reputation,
                kill_chain_stage,
                tactic,
                technique,
                msg_class,
                event_type
            FROM {src}
            WHERE {where}
            ORDER BY ts DESC
            LIMIT {int(limit)}
        """).fetchall()

        items = [
            {
                "ts": str(r[0]),
                "host": r[1],
                "user_name": r[2],
                "src_ip": r[3],
                "dst_ip": r[4],
                "threat_score": r[5],
                "is_dga": r[6],
                "is_tunneling": r[7],
                "country_code": r[8],
                "engid_name": r[9],
                "appid_name": r[10],
                "primary_domain": r[11],
                "domain_reputation": r[12],
                "kill_chain_stage": r[13],
                "tactic": r[14],
                "technique": r[15],
                "msg_class": r[16],
                "event_type": r[17],
            }
            for r in rows
        ]
        return {
            "items": items,
            "count": len(items),
            "days_searched": len(globs),
            "index": index,
        }
    except Exception as exc:
        raise HTTPException(500, f"OCI query failed: {str(exc)[:300]}")
