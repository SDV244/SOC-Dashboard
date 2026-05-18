import csv
import io
import json
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from backend.db import get_conn
from backend.services.oci_query import browse_logs_oci

router = APIRouter(prefix="/api/logs", tags=["logs"])


class NLQueryRequest(BaseModel):
    query: str


@router.post("/nl-query")
async def nl_query_endpoint(body: NLQueryRequest) -> dict:
    """Convert natural language to search filters. No log data is sent to the LLM."""
    from backend.services.nl_service import nl_to_filters
    from backend.config import get_settings
    if len(body.query) > 500:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Query demasiado larga")
    if not get_settings().openrouter_api_key:
        return {"filters": {}, "query": body.query, "error": "openrouter_api_key no configurada"}
    try:
        filters = await nl_to_filters(body.query)
        return {"filters": filters, "query": body.query}
    except Exception as exc:
        return {"filters": {}, "query": body.query, "error": str(exc)[:200]}


def _build_adr_conditions(
    conditions: list,
    params: list,
    threat_score_min: int | None,
    is_dga: str | None,
    is_tunneling: bool | None,
    app_name: str | None,
    src_country: str | None,
    domain: str | None,
) -> None:
    if threat_score_min is not None and threat_score_min > 0:
        conditions.append("TRY_CAST(json_extract_string(raw, '$.threat_score') AS INTEGER) >= ?")
        params.append(threat_score_min)
    if is_dga is not None:
        conditions.append("json_extract_string(raw, '$.is_dga') = ?")
        params.append(is_dga)
    if is_tunneling is True:
        conditions.append("TRY_CAST(json_extract_string(raw, '$.is_tunneling') AS INTEGER) > 0")
    if app_name:
        conditions.append("json_extract_string(raw, '$.appid_name') ILIKE ?")
        params.append(f"%{app_name}%")
    if src_country:
        conditions.append("json_extract_string(raw, '$.srcip_geo.countryCode') = ?")
        params.append(src_country)
    if domain:
        conditions.append("json_extract_string(raw, '$.domain_list[0]') ILIKE ?")
        params.append(f"%{domain}%")


@router.get("/browse")
async def browse_logs(
    index: str = Query(default=None),
    start: str = Query(default=None),
    end: str = Query(default=None),
    host: str = Query(default=None),
    user_name: str = Query(default=None),
    severity: str = Query(default=None),
    search: str = Query(default=None),
    threat_score_min: int = Query(default=0, ge=0, le=100),
    is_dga: str = Query(default=None, pattern="^(yes|no)$"),
    is_tunneling: bool = Query(default=None),
    app_name: str = Query(default=None),
    src_country: str = Query(default=None),
    domain: str = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
):
    import asyncio
    default_start = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    default_end = datetime.now(UTC).isoformat()
    start = start or default_start
    end = end or default_end

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        lambda: browse_logs_oci(
            index=index, start=start, end=end,
            host=host, user_name=user_name, search=search,
            threat_score_min=threat_score_min, is_dga=is_dga,
            is_tunneling=is_tunneling, app_name=app_name,
            src_country=src_country, domain=domain,
            page=page, page_size=page_size,
        )
    )


@router.get("/export")
def export_csv(
    index: str = Query(default=None),
    start: str = Query(default=None),
    end: str = Query(default=None),
    host: str = Query(default=None),
    user_name: str = Query(default=None),
    severity: str = Query(default=None),
    search: str = Query(default=None),
    threat_score_min: int = Query(default=0, ge=0, le=100),
    is_dga: str = Query(default=None),
    is_tunneling: bool = Query(default=None),
    app_name: str = Query(default=None),
    src_country: str = Query(default=None),
    domain: str = Query(default=None),
    limit: int = Query(default=10000, le=100000),
):
    conn = get_conn()
    default_start = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    default_end = datetime.now(UTC).isoformat()
    start = start or default_start
    end = end or default_end

    conditions = ["ts BETWEEN ? AND ?"]
    params: list = [start, end]

    if index:
        conditions.append("index = ?")
        params.append(index)
    if host:
        conditions.append("host ILIKE ?")
        params.append(f"%{host}%")
    if user_name:
        conditions.append("user_name ILIKE ?")
        params.append(f"%{user_name}%")
    if severity:
        conditions.append("lower(severity) = lower(?)")
        params.append(severity)
    if search:
        conditions.append(
            "(raw ILIKE ? OR host ILIKE ? OR user_name ILIKE ? OR event_type ILIKE ?)"
        )
        params.extend([f"%{search}%"] * 4)

    _build_adr_conditions(conditions, params, threat_score_min, is_dga, is_tunneling, app_name, src_country, domain)

    where = " AND ".join(conditions)
    rows = conn.execute(
        f"""
        SELECT id, index, ts, severity, host, user_name, event_type, src_ip, dst_ip
        FROM logs WHERE {where} ORDER BY ts DESC LIMIT ?
        """,
        params + [limit],
    ).fetchall()

    def _generate():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            ["id", "index", "ts", "severity", "host", "user_name", "event_type", "src_ip", "dst_ip"]
        )
        for r in rows:
            writer.writerow(r)
            buf.seek(0)
            yield buf.read()
            buf.seek(0)
            buf.truncate()

    return StreamingResponse(
        _generate(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=soc_logs.csv"},
    )


@router.get("/indexes")
def list_indexes():
    conn = get_conn()
    rows = conn.execute("SELECT DISTINCT index FROM parquet_months ORDER BY index").fetchall()
    if rows:
        return [r[0] for r in rows]
    # Fallback: configured indexes
    from backend.config import get_settings
    return get_settings().indexes


_VALID_INDEXES = {"adr","ade","syslog","wineventlog","users","assets","maltrace","scan","ser","audit","cloudtrail"}

@router.get("/users")
def list_users(index: str = Query(default=None)):
    conn = get_conn()
    users: set[str] = set()

    if index and index in _VALID_INDEXES:
        # Query parquet files directly for the specific index
        import glob as _glob
        from pathlib import Path
        parquet_base = Path("/data/parquet")
        files = _glob.glob(str(parquet_base / f"index={index}" / "**" / "*.parquet"), recursive=True)
        if files:
            # Prefer most-recent files (reconverted ones have more fields)
            sampled = sorted(files, reverse=True)[:20]
            file_list = ", ".join(f"'{f}'" for f in sampled)
            try:
                rows = conn.execute(f"""
                    SELECT DISTINCT user_name
                    FROM read_parquet([{file_list}])
                    WHERE user_name IS NOT NULL AND user_name != ''
                    LIMIT 300
                """).fetchall()
                for (u,) in rows:
                    if u and u not in ("unknown", "-", "N/A", ""):
                        users.add(u)
            except Exception:
                pass
    else:
        # Pull from daily_stats.top_users (covers all converted months)
        rows = conn.execute(
            "SELECT top_users FROM daily_stats WHERE top_users IS NOT NULL"
        ).fetchall()
        for (top_json,) in rows:
            try:
                for entry in json.loads(top_json):
                    u = entry.get("user", "")
                    if u and u not in ("unknown", "-", "N/A", ""):
                        users.add(u)
            except Exception:
                pass

        for (u,) in conn.execute(
            "SELECT DISTINCT user_name FROM logs WHERE user_name IS NOT NULL LIMIT 200"
        ).fetchall():
            if u and u not in ("unknown", "-", ""):
                users.add(u)

    return sorted(users)[:500]
