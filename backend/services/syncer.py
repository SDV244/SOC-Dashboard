import os
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from backend.config import get_settings
from backend.db import get_conn


@dataclass
class SyncResult:
    success: bool
    files_downloaded: int
    bytes_transferred: int
    message: str


def build_s3_prefix(
    settings,
    index: str | None = None,
    year: int | None = None,
    month: int | None = None,
    day: int | None = None,
) -> str:
    prefix = f"organization={settings.org_id}"
    if index:
        prefix += f"/index={index}/tenant={settings.tenant_id}"
        if year:
            prefix += f"/year={year:04d}"
            if month:
                prefix += f"/month={month:02d}"
                if day:
                    prefix += f"/day={day:02d}"
    return prefix


def sync_from_s3(
    index: str | None = None,
    year: int | None = None,
    month: int | None = None,
    day: int | None = None,
) -> SyncResult:
    settings = get_settings()
    local_path = Path(settings.local_sync_path)
    local_path.mkdir(parents=True, exist_ok=True)

    prefix = build_s3_prefix(settings, index, year, month, day)
    s3_uri = f"s3://{settings.s3_bucket}/{prefix}/"

    env = os.environ.copy()
    if settings.aws_access_key_id:
        env["AWS_ACCESS_KEY_ID"] = settings.aws_access_key_id
    if settings.aws_secret_access_key:
        env["AWS_SECRET_ACCESS_KEY"] = settings.aws_secret_access_key
    env["AWS_DEFAULT_REGION"] = settings.s3_region

    cmd = [
        "aws",
        "s3",
        "sync",
        s3_uri,
        str(local_path / prefix) + "/",
        "--endpoint-url",
        settings.s3_endpoint,
        "--region",
        settings.s3_region,
        "--no-progress",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=3600)
        output = result.stdout + result.stderr

        files_downloaded = output.count("download:")
        bytes_transferred = 0
        for line in output.splitlines():
            if "download:" in line and "to" in line:
                bytes_transferred += 1

        success = result.returncode == 0
        message = output[-2000:] if len(output) > 2000 else output

        _update_sync_status(success, message)
        return SyncResult(
            success=success,
            files_downloaded=files_downloaded,
            bytes_transferred=bytes_transferred,
            message=message,
        )
    except FileNotFoundError:
        msg = "aws CLI not found. Install it and ensure it is in PATH."
        _update_sync_status(False, msg)
        return SyncResult(success=False, files_downloaded=0, bytes_transferred=0, message=msg)
    except subprocess.TimeoutExpired:
        msg = "aws s3 sync timed out after 1 hour."
        _update_sync_status(False, msg)
        return SyncResult(success=False, files_downloaded=0, bytes_transferred=0, message=msg)


def _update_sync_status(success: bool, details: str) -> None:
    conn = get_conn()
    status = "ok" if success else "error"
    conn.execute(
        "UPDATE sync_status SET last_sync=?, last_status=?, details=? WHERE id=1",
        [datetime.now(UTC), status, details[:4000]],
    )


def get_sync_status() -> dict:
    conn = get_conn()
    row = conn.execute(
        "SELECT last_sync, last_status, details FROM sync_status WHERE id=1"
    ).fetchone()
    if row:
        return {"last_sync": row[0], "status": row[1], "details": row[2]}
    return {"last_sync": None, "status": "never", "details": ""}
