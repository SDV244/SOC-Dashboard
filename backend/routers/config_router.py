from fastapi import APIRouter
from pydantic import BaseModel

from backend.config import get_settings, save_settings

router = APIRouter(prefix="/api/config", tags=["config"])


class ConfigUpdate(BaseModel):
    s3_endpoint: str | None = None
    s3_bucket: str | None = None
    s3_region: str | None = None
    org_id: str | None = None
    tenant_id: str | None = None
    local_sync_path: str | None = None
    db_path: str | None = None
    indexes: list[str] | None = None


@router.get("")
def read_config():
    s = get_settings()
    return {
        "s3_endpoint": s.s3_endpoint,
        "s3_bucket": s.s3_bucket,
        "s3_region": s.s3_region,
        "org_id": s.org_id,
        "tenant_id": s.tenant_id,
        "local_sync_path": s.local_sync_path,
        "db_path": s.db_path,
        "indexes": s.indexes,
    }


@router.put("")
def update_config(body: ConfigUpdate):
    data = {k: v for k, v in body.model_dump().items() if v is not None}
    save_settings(data)
    return {"status": "saved", "updated": list(data.keys())}
