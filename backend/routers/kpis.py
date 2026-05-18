from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Query

from backend.db import get_conn, has_local_data
from backend.services.oci_query import _parse_host
from backend.services.oci_query import (
    alerts_timeline_oci,
    assets_activity_oci,
    coverage_by_month,
    kpi_overview_oci,
    login_stats_oci,
    ml_confidence_oci,
    network_apps_oci,
    network_geo_oci,
    network_threats_oci,
    network_top_domains_oci,
    syslog_volume_oci,
    top_processes_oci,
    top_threats_oci,
    users_activity_oci,
)

router = APIRouter(prefix="/api/kpis", tags=["kpis"])


def _default_start() -> str:
    return (datetime.now(UTC) - timedelta(days=7)).isoformat()


def _default_end() -> str:
    return datetime.now(UTC).isoformat()


@router.get("/overview")
def overview(
    start: str = Query(default=None),
    end: str = Query(default=None),
):
    start = start or _default_start()
    end = end or _default_end()

    if has_local_data("adr", start, end):
        conn = get_conn()
        total = conn.execute(
            "SELECT count(*) FROM logs WHERE ts BETWEEN ? AND ?", [start, end]
        ).fetchone()[0]
        by_index = conn.execute(
            "SELECT index, count(*) FROM logs WHERE ts BETWEEN ? AND ? GROUP BY index ORDER BY count(*) DESC",
            [start, end],
        ).fetchall()
        time_range = conn.execute("SELECT min(ts), max(ts) FROM logs").fetchone()
        threat_high = conn.execute(
            "SELECT count(*) FROM logs WHERE index='adr' AND TRY_CAST(json_extract_string(raw, '$.threat_score') AS INTEGER) > 50 AND ts BETWEEN ? AND ?",
            [start, end],
        ).fetchone()[0]
        dga = conn.execute(
            "SELECT count(*) FROM logs WHERE index='adr' AND json_extract_string(raw, '$.is_dga') = 'yes' AND ts BETWEEN ? AND ?",
            [start, end],
        ).fetchone()[0]
        tunneling = conn.execute(
            "SELECT count(*) FROM logs WHERE index='adr' AND TRY_CAST(json_extract_string(raw, '$.is_tunneling') AS INTEGER) > 0 AND ts BETWEEN ? AND ?",
            [start, end],
        ).fetchone()[0]
        unique_ext_ips = conn.execute(
            "SELECT count(*) FROM (SELECT DISTINCT src_ip FROM logs WHERE index='adr' AND src_ip IS NOT NULL AND ts BETWEEN ? AND ? AND json_extract_string(raw, '$.srcip_type') = 'public')",
            [start, end],
        ).fetchone()[0]
        return {
            "total_events": total,
            "threat_score_high": threat_high,
            "dga_detections": dga,
            "tunneling_events": tunneling,
            "unique_external_ips": unique_ext_ips,
            "by_index": {row[0]: row[1] for row in by_index},
            "time_range": {"min": time_range[0], "max": time_range[1]},
            "source": "local",
        }

    oci = kpi_overview_oci("adr", datetime.fromisoformat(start), datetime.fromisoformat(end))
    oci["source"] = "oci"
    oci["by_index"] = {}
    oci["time_range"] = {"min": start, "max": end}
    return oci


@router.get("/alerts/timeline")
def alerts_timeline(
    start: str = Query(default=None),
    end: str = Query(default=None),
    granularity: str = Query(default="hour"),
):
    start = start or _default_start()
    end = end or _default_end()

    if has_local_data("adr", start, end):
        conn = get_conn()
        trunc = "hour" if granularity == "hour" else "day"
        rows = conn.execute(
            f"""
            SELECT date_trunc('{trunc}', ts) AS period,
                   coalesce(event_type, 'unknown') AS msg_class,
                   count(*)
            FROM logs
            WHERE index='adr' AND ts BETWEEN ? AND ?
            GROUP BY 1, 2 ORDER BY 1
            """,
            [start, end],
        ).fetchall()
        return [{"period": r[0], "msg_class": r[1], "count": r[2]} for r in rows]

    return alerts_timeline_oci(start, end, granularity)


@router.get("/alerts/top-threats")
def top_threats(
    start: str = Query(default=None),
    end: str = Query(default=None),
    limit: int = Query(default=10),
):
    start = start or _default_start()
    end = end or _default_end()

    if has_local_data("adr", start, end):
        conn = get_conn()
        rows = conn.execute(
            """
            SELECT coalesce(json_extract_string(raw, '$.engid_name'), 'unknown') AS device,
                   max(TRY_CAST(json_extract_string(raw, '$.threat_score') AS INTEGER)) AS max_threat,
                   count(*) AS event_count,
                   max(ts) AS last_seen
            FROM logs
            WHERE index='adr'
              AND TRY_CAST(json_extract_string(raw, '$.threat_score') AS INTEGER) > 0
              AND ts BETWEEN ? AND ?
            GROUP BY 1 ORDER BY 2 DESC, 3 DESC LIMIT ?
            """,
            [start, end, limit],
        ).fetchall()
        return [{"device": r[0], "max_threat_score": r[1], "count": r[2], "last_seen": r[3]} for r in rows]

    return top_threats_oci(start, end, limit)


@router.get("/network/top-domains")
def network_top_domains(
    start: str = Query(default=None),
    end: str = Query(default=None),
    limit: int = Query(default=15),
):
    start = start or _default_start()
    end = end or _default_end()

    if has_local_data("adr", start, end):
        conn = get_conn()
        rows = conn.execute(
            """
            SELECT json_extract_string(raw, '$.domain_list[0]') AS domain,
                   count(*) AS query_count,
                   coalesce(json_extract_string(raw, '$.domain_reputation'), 'unknown') AS reputation,
                   coalesce(json_extract_string(raw, '$.is_dga'), 'no') AS is_dga
            FROM logs
            WHERE index='adr'
              AND json_extract_string(raw, '$.domain_list[0]') IS NOT NULL
              AND json_extract_string(raw, '$.domain_list[0]') != ''
              AND ts BETWEEN ? AND ?
            GROUP BY domain, reputation, is_dga ORDER BY query_count DESC LIMIT ?
            """,
            [start, end, limit],
        ).fetchall()
        return [{"domain": r[0], "count": r[1], "reputation": r[2], "is_dga": r[3]} for r in rows]

    return network_top_domains_oci(start, end, limit)


@router.get("/network/apps")
def network_apps(
    start: str = Query(default=None),
    end: str = Query(default=None),
):
    start = start or _default_start()
    end = end or _default_end()

    if has_local_data("adr", start, end):
        conn = get_conn()
        rows = conn.execute(
            "SELECT coalesce(json_extract_string(raw, '$.appid_name'), 'unknown') AS app, count(*) AS event_count FROM logs WHERE index='adr' AND ts BETWEEN ? AND ? GROUP BY app ORDER BY event_count DESC",
            [start, end],
        ).fetchall()
        return [{"app": r[0], "count": r[1]} for r in rows]

    return network_apps_oci(start, end)


@router.get("/network/geo")
def network_geo(
    start: str = Query(default=None),
    end: str = Query(default=None),
    limit: int = Query(default=15),
):
    start = start or _default_start()
    end = end or _default_end()

    if has_local_data("adr", start, end):
        conn = get_conn()
        rows = conn.execute(
            "SELECT coalesce(json_extract_string(raw, '$.srcip_geo.countryCode'), 'unknown') AS country, count(*) AS event_count FROM logs WHERE index='adr' AND ts BETWEEN ? AND ? GROUP BY country ORDER BY event_count DESC LIMIT ?",
            [start, end, limit],
        ).fetchall()
        return [{"country": r[0], "count": r[1]} for r in rows]

    return network_geo_oci(start, end, limit)


@router.get("/network/threats")
def network_threats(
    start: str = Query(default=None),
    end: str = Query(default=None),
    limit: int = Query(default=20),
):
    start = start or _default_start()
    end = end or _default_end()

    if has_local_data("adr", start, end):
        conn = get_conn()
        rows = conn.execute(
            """
            SELECT coalesce(json_extract_string(raw, '$.engid_name'), 'unknown') AS device,
                   TRY_CAST(json_extract_string(raw, '$.threat_score') AS INTEGER) AS threat_score,
                   coalesce(json_extract_string(raw, '$.appid_name'), 'unknown') AS app,
                   coalesce(json_extract_string(raw, '$.is_dga'), 'no') AS is_dga, ts
            FROM logs WHERE index='adr'
              AND TRY_CAST(json_extract_string(raw, '$.threat_score') AS INTEGER) > 0
              AND ts BETWEEN ? AND ?
            ORDER BY threat_score DESC, ts DESC LIMIT ?
            """,
            [start, end, limit],
        ).fetchall()
        return [{"device": r[0], "threat_score": r[1], "app": r[2], "is_dga": r[3], "ts": r[4]} for r in rows]

    return network_threats_oci(start, end, limit)


@router.get("/syslog/volume")
def syslog_volume(
    start: str = Query(default=None),
    end: str = Query(default=None),
    limit: int = Query(default=10),
):
    start = start or _default_start()
    end = end or _default_end()

    if has_local_data(None, start, end):
        conn = get_conn()
        by_host = conn.execute(
            """SELECT coalesce(
                   CASE WHEN host LIKE '{%' THEN json_extract_string(host, '$.name') END,
                   CASE WHEN host LIKE '{%' THEN json_extract_string(host, '$.ip') END,
                   host, 'unknown'
               ), count(*)
               FROM logs WHERE index IN ('syslog', 'wineventlog') AND ts BETWEEN ? AND ?
               GROUP BY 1 ORDER BY 2 DESC LIMIT ?""",
            [start, end, limit],
        ).fetchall()
        by_event = conn.execute(
            "SELECT coalesce(event_type, 'unknown'), count(*) FROM logs WHERE index IN ('syslog', 'wineventlog') AND ts BETWEEN ? AND ? GROUP BY 1 ORDER BY 2 DESC LIMIT ?",
            [start, end, limit],
        ).fetchall()
        timeline = conn.execute(
            "SELECT date_trunc('hour', ts) AS period, index, count(*) FROM logs WHERE index IN ('syslog', 'wineventlog') AND ts BETWEEN ? AND ? GROUP BY 1, 2 ORDER BY 1",
            [start, end],
        ).fetchall()
        return {
            "by_host": [{"host": _parse_host(r[0]), "count": r[1]} for r in by_host],
            "by_event_type": [{"event_type": r[0], "count": r[1]} for r in by_event],
            "timeline": [{"period": r[0], "index": r[1], "count": r[2]} for r in timeline],
        }

    return syslog_volume_oci(start, end, limit)


@router.get("/users/activity")
def users_activity(
    start: str = Query(default=None),
    end: str = Query(default=None),
    limit: int = Query(default=10),
):
    start = start or _default_start()
    end = end or _default_end()

    if has_local_data("users", start, end):
        conn = get_conn()
        top_users = conn.execute(
            "SELECT user_name, count(*), max(ts) FROM logs WHERE user_name IS NOT NULL AND ts BETWEEN ? AND ? GROUP BY 1 ORDER BY 2 DESC LIMIT ?",
            [start, end, limit],
        ).fetchall()
        user_events = conn.execute(
            "SELECT coalesce(user_name, 'unknown'), coalesce(event_type, 'unknown'), count(*) FROM logs WHERE index='users' AND ts BETWEEN ? AND ? GROUP BY 1, 2 ORDER BY 3 DESC LIMIT ?",
            [start, end, limit],
        ).fetchall()
        return {
            "top_users": [{"user": r[0], "count": r[1], "last_seen": r[2]} for r in top_users],
            "user_events": [{"user": r[0], "event_type": r[1], "count": r[2]} for r in user_events],
        }

    return users_activity_oci(start, end, limit)


@router.get("/assets/activity")
def assets_activity(
    start: str = Query(default=None),
    end: str = Query(default=None),
    limit: int = Query(default=10),
):
    start = start or _default_start()
    end = end or _default_end()

    if has_local_data(None, start, end):
        conn = get_conn()
        rows = conn.execute(
            "SELECT coalesce(host, src_ip, 'unknown'), count(*), max(ts) FROM logs WHERE ts BETWEEN ? AND ? GROUP BY 1 ORDER BY 2 DESC LIMIT ?",
            [start, end, limit],
        ).fetchall()
        return {"top_assets": [{"asset": r[0], "count": r[1], "last_seen": r[2]} for r in rows]}

    return assets_activity_oci(start, end, limit)


@router.get("/ml/confidence")
def ml_confidence(
    start: str = Query(default=None),
    end: str = Query(default=None),
):
    start = start or _default_start()
    end = end or _default_end()
    return ml_confidence_oci(start, end)


@router.get("/logins/stats")
def login_stats(
    start: str = Query(default=None),
    end: str = Query(default=None),
):
    start = start or _default_start()
    end = end or _default_end()
    return login_stats_oci(start, end)


@router.get("/processes/top")
def top_processes(
    start: str = Query(default=None),
    end: str = Query(default=None),
    limit: int = Query(default=20),
):
    start = start or _default_start()
    end = end or _default_end()
    return top_processes_oci(start, end, limit)


@router.get("/coverage")
def log_coverage(
    index: str = Query(default="adr"),
    months: int = Query(default=3, ge=1, le=12),
):
    try:
        days = coverage_by_month(index, months)
    except Exception as exc:
        return {"error": str(exc), "days": []}

    total_days_with_data = len([d for d in days if d["count"] > 0])
    required_days = months * 30
    pct = round(total_days_with_data / required_days * 100, 1)

    return {
        "index": index,
        "months_requested": months,
        "required_days": required_days,
        "days_with_data": total_days_with_data,
        "coverage_pct": pct,
        "compliant": total_days_with_data >= required_days * 0.95,
        "days": days,
    }
