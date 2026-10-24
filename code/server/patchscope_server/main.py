"""PatchScope 분석 서버. nginx(TLS 종료) 뒤 127.0.0.1:8000 에서 실행."""
import asyncio
import contextlib
import logging

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from . import auth, db, ingest, tasks, web

log = logging.getLogger("patchscope")


async def retention_loop():
    while True:
        try:
            log.info("retention: %s", await asyncio.to_thread(db.apply_retention))
        except Exception:  # noqa: BLE001 - 다음 주기에 재시도
            log.exception("retention failed")
        await asyncio.sleep(3600)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_schema()
    task = asyncio.create_task(retention_loop())
    yield
    task.cancel()


app = FastAPI(title="PatchScope", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(ingest.router)
app.include_router(tasks.router)
app.include_router(web.router)
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")


@app.exception_handler(auth.LoginRequired)
async def login_redirect(request: Request, exc: auth.LoginRequired):
    return RedirectResponse("/login", status_code=303)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    return resp
