import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.auth import AuthMiddleware, handle_login, handle_logout, login_page
from backend.db import get_conn
from backend.routers import ingest, kpis, logs
from backend.routers.admin import router as admin_router
from backend.routers.config_router import router as config_router
from backend.routers.search import router as search_router


async def _nightly_refresh() -> None:
    """
    Every night at 03:00 UTC: download missing days of the current month (delta sync)
    and compute daily_stats for any new days.
    """
    from datetime import timedelta
    from backend.services.parquet_sync import compute_daily_stats, refresh_current_months
    from backend.config import get_settings
    while True:
        now = datetime.now(UTC)
        next_run = now.replace(hour=3, minute=0, second=0, microsecond=0)
        if next_run <= now:
            next_run += timedelta(days=1)
        await asyncio.sleep((next_run - now).total_seconds())
        import logging as _log_nr
        _nr_log = _log_nr.getLogger(__name__)
        try:
            refresh_current_months()
        except Exception:
            _nr_log.exception('_nightly_refresh: refresh_current_months failed')
        # Compute stats for any new days that arrived (skips already-computed dates)
        now2 = datetime.now(UTC)
        for index in get_settings().indexes:
            try:
                compute_daily_stats(index, now2.year, now2.month)
            except Exception:
                _nr_log.exception('_nightly_refresh: compute_daily_stats failed for %s', index)


@asynccontextmanager
async def lifespan(app: FastAPI):
    import logging
    logger = logging.getLogger("uvicorn")
    get_conn()
    from backend.auth import bootstrap_admin
    bootstrap_admin()
    from backend.services.parquet_sync import recover_from_disk
    recovered = await asyncio.get_event_loop().run_in_executor(None, recover_from_disk)
    if recovered:
        logger.info(f"Auto-recovered {recovered} Parquet month(s) from disk")
    # backfill_daily_stats disabled — runs via API only (too expensive on startup)
    asyncio.create_task(_nightly_refresh())
    yield


app = FastAPI(title="SOC Dashboard", version="1.0.0", lifespan=lifespan)

app.add_middleware(AuthMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth routes
@app.get("/login", include_in_schema=False, response_model=None)
async def _login_page():
    return login_page()

@app.post("/api/auth/login", include_in_schema=False, response_model=None)
async def _login(request: Request):
    return await handle_login(request)

@app.get("/api/auth/logout", include_in_schema=False, response_model=None)
async def _logout(request: Request):
    return await handle_logout(request)

@app.get("/api/auth/me", include_in_schema=False)
async def _me(request: Request):
    from backend.auth import _COOKIE, _verify_token
    raw_cookie = request.headers.get("cookie", "")
    token = None
    for part in raw_cookie.split(";"):
        part = part.strip()
        if part.startswith(f"{_COOKIE}="):
            token = part[len(f"{_COOKIE}="):]
            break
    user = _verify_token(token) if token else None
    if not user:
        from fastapi import HTTPException
        raise HTTPException(status_code=401)
    return user

from backend.routers.users import router as users_router
app.include_router(users_router)
app.include_router(ingest.router)
app.include_router(kpis.router)
app.include_router(logs.router)
app.include_router(config_router)
app.include_router(admin_router)
app.include_router(search_router)

STATIC_DIR = Path(__file__).parent.parent / "frontend" / "dist"
if STATIC_DIR.exists():
    from fastapi.responses import FileResponse

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_fallback(full_path: str):
        if full_path.startswith("api/"):
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="Not found")
        file = STATIC_DIR / full_path
        if file.exists() and file.is_file():
            return FileResponse(str(file))
        return FileResponse(str(STATIC_DIR / "index.html"))

    app.mount("/assets", StaticFiles(directory=str(STATIC_DIR / "assets")), name="assets")
