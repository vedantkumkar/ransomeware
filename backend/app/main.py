"""RansomGuard IR — FastAPI application entry point.

Run from the backend/ directory:
    uvicorn app.main:app --host 0.0.0.0 --port 8000
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import config, db
from .routes import endpoints as endpoints_routes
from .routes import evidence, events, incidents, system


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()  # create schema + seed demo endpoint registry
    yield


app = FastAPI(
    title="RansomGuard IR API",
    description="Automated Ransomware Containment & Incident Response Orchestrator",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(system.router)
app.include_router(incidents.router)
app.include_router(endpoints_routes.router)
app.include_router(evidence.router)
app.include_router(events.router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host=config.host(), port=config.port())
