from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.config import FRONTEND_DIST_DIR, settings
from app.database import init_db
from app.routes import audit, certificates, dashboard, devices, health, operations


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Never triggers any sanitization -- only ensures tables/dirs exist.
    init_db()
    yield


app = FastAPI(title=settings.app_name, version=settings.app_version, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(devices.router)
app.include_router(operations.router)
app.include_router(certificates.router)
app.include_router(audit.router)
app.include_router(dashboard.router)

# Serve the built frontend (if present) from the same process/port, so a
# packaged build needs only one process and one port. API routes above take
# precedence over this catch-all mount since Starlette matches routes in
# registration order.
if FRONTEND_DIST_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST_DIR), html=True), name="frontend")
