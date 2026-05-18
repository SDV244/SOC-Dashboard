from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel

from backend.services.loader import load_all_new
from backend.services.syncer import SyncResult, get_sync_status, sync_from_s3

router = APIRouter(prefix="/api/ingest", tags=["ingest"])

_running = False
_last_result: dict = {}


class SyncRequest(BaseModel):
    index: str | None = None
    year: int | None = None
    month: int | None = None
    day: int | None = None


def _sync_and_load(req: SyncRequest) -> None:
    global _running, _last_result
    _running = True
    try:
        result: SyncResult = sync_from_s3(
            index=req.index,
            year=req.year,
            month=req.month,
            day=req.day,
        )
        load_result = load_all_new()
        _last_result = {
            "sync": {
                "success": result.success,
                "files_downloaded": result.files_downloaded,
                "message": result.message[-500:],
            },
            "load": load_result,
        }
    finally:
        _running = False


@router.post("/sync")
async def trigger_sync(req: SyncRequest, background_tasks: BackgroundTasks):
    if _running:
        return {"status": "already_running"}
    background_tasks.add_task(_sync_and_load, req)
    return {"status": "started"}


@router.post("/load")
async def trigger_load(background_tasks: BackgroundTasks):
    """Load any new .gz files already on disk into DuckDB (no S3 sync)."""
    if _running:
        return {"status": "already_running"}

    def _run():
        global _running, _last_result
        _running = True
        try:
            _last_result = {"load": load_all_new()}
        finally:
            _running = False

    background_tasks.add_task(_run)
    return {"status": "started"}


@router.get("/status")
async def ingest_status():
    sync_st = get_sync_status()
    return {
        "running": _running,
        "last_result": _last_result,
        "sync_status": sync_st,
    }
