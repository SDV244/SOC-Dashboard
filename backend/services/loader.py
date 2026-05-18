import gzip
import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

from backend.config import get_settings
from backend.db import get_conn

# Regex to extract index from path: .../index=adr/...
_INDEX_RE = re.compile(r"index=([^/\\]+)")
_TENANT_RE = re.compile(r"tenant=([^/\\]+)")

# Field name candidates — StellarCyber fields listed first
# NOTE: stellar_da_input is processing latency (ms), NOT a timestamp — exclude it
_TS_KEYS = ["timestamp", "@timestamp", "write_time", "receive_time",
            "time", "event_time", "ts", "startTime", "event_created", "EventTime"]
_SEVERITY_KEYS = ["severity", "risk_score_str", "alert_severity", "xdr_risk_level",
                  "threat_score", "level", "log_level"]
_HOST_KEYS = ["hostip", "hostname", "device_hostname", "src_host", "source_host",
              "agent_host", "engid_device_desc"]
_USER_KEYS = ["username", "user", "user_name", "account_name", "subject_user_name",
              "SubjectUserName"]
_EVENT_TYPE_KEYS = ["msg_class", "process_name", "appid_family", "event_type", "event_name",
                    "EventID", "event_id", "type", "log_type", "category", "xdr_event_name"]
_SRC_IP_KEYS = ["srcip", "src_ip", "source_ip", "src", "client_ip", "ipaddr"]
_DST_IP_KEYS = ["dstip", "dst_ip", "dest_ip", "dst", "server_ip", "destip", "hostip"]


def _pick(doc: dict, keys: list[str]) -> str | None:
    for k in keys:
        v = doc.get(k)
        if v is None:
            continue
        # Handle nested dicts like host:{ip:...} — extract first string value
        if isinstance(v, dict):
            v = next((str(x) for x in v.values() if x is not None), None)
        if v is not None:
            return str(v)[:512]
    return None


def _parse_ts(raw_ts: str | None) -> datetime | None:
    if not raw_ts:
        return None
    try:
        # Numeric: int/float or string that looks like one
        numeric: float | None = None
        if isinstance(raw_ts, (int, float)):
            numeric = float(raw_ts)
        else:
            try:
                numeric = float(str(raw_ts))
                # Only treat as epoch if it looks like one (no dashes)
                if "-" in str(raw_ts):
                    numeric = None
            except (ValueError, TypeError):
                numeric = None

        if numeric is not None:
            if numeric > 1e12:
                numeric /= 1000
            return datetime.fromtimestamp(numeric, tz=UTC)

        return datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
    except Exception:
        return None


def _extract_index_from_path(path: Path) -> str:
    m = _INDEX_RE.search(str(path))
    return m.group(1) if m else "unknown"


def _extract_tenant_from_path(path: Path) -> str:
    m = _TENANT_RE.search(str(path))
    return m.group(1) if m else ""


def load_file(gz_path: Path) -> int:
    conn = get_conn()
    path_str = str(gz_path)

    already = conn.execute("SELECT 1 FROM ingested_files WHERE path=?", [path_str]).fetchone()
    if already:
        return 0

    index = _extract_index_from_path(gz_path)
    tenant = _extract_tenant_from_path(gz_path)
    rows = []

    try:
        with gzip.open(gz_path, "rt", encoding="utf-8", errors="replace") as f:
            content = f.read()

        decoder = json.JSONDecoder()
        pos = 0
        content = content.strip()
        while pos < len(content):
            # Skip whitespace between objects
            while pos < len(content) and content[pos] in " \t\r\n":
                pos += 1
            if pos >= len(content):
                break
            try:
                doc, end = decoder.raw_decode(content, pos)
                pos = end
            except json.JSONDecodeError:
                # Skip one char and retry (handles malformed data)
                pos += 1
                continue

            if not isinstance(doc, dict):
                continue

            ts = _parse_ts(_pick(doc, _TS_KEYS))
            rows.append({
                "id": doc.get("stellar_uuid") or doc.get("_id") or doc.get("id") or str(uuid.uuid4()),
                "index": index,
                "tenant": tenant,
                "ts": ts,
                "severity": _pick(doc, _SEVERITY_KEYS),
                "host": _pick(doc, _HOST_KEYS),
                "user_name": _pick(doc, _USER_KEYS),
                "event_type": _pick(doc, _EVENT_TYPE_KEYS),
                "src_ip": _pick(doc, _SRC_IP_KEYS),
                "dst_ip": _pick(doc, _DST_IP_KEYS),
                "raw": json.dumps(doc),
            })
    except Exception as e:
        print(f"[loader] Error reading {gz_path}: {e}")
        return 0

    if rows:
        conn.executemany(
            """INSERT INTO logs (id, index, tenant, ts, severity, host, user_name,
               event_type, src_ip, dst_ip, raw)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    r["id"],
                    r["index"],
                    r["tenant"],
                    r["ts"],
                    r["severity"],
                    r["host"],
                    r["user_name"],
                    r["event_type"],
                    r["src_ip"],
                    r["dst_ip"],
                    r["raw"],
                )
                for r in rows
            ],
        )

    conn.execute(
        "INSERT OR REPLACE INTO ingested_files (path, ingested_at, row_count) VALUES (?, now(), ?)",
        [path_str, len(rows)],
    )
    return len(rows)


def load_all_new() -> dict:
    settings = get_settings()
    local_path = Path(settings.local_sync_path)
    if not local_path.exists():
        return {"files_processed": 0, "rows_inserted": 0}

    gz_files = list(local_path.rglob("*.gz"))
    total_rows = 0
    files_processed = 0

    for gz_path in gz_files:
        rows = load_file(gz_path)
        if rows > 0:
            files_processed += 1
            total_rows += rows
            print(f"[loader] {gz_path.name}: {rows} rows")

    return {"files_processed": files_processed, "rows_inserted": total_rows}
