import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routers import scan, imports
from database import create_tables

_log_level = getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
logging.basicConfig(
    level=_log_level,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Q-Ready API starting up")
    create_tables()
    yield
    logger.info("Q-Ready API shutting down")


app = FastAPI(
    title="Q-Ready API",
    description="Post-quantum cryptography migration assistant — backend API",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router, prefix="/scans", tags=["scans"])
app.include_router(imports.router, prefix="/import", tags=["imports"])


@app.get("/ping", tags=["health"])
async def ping() -> dict:
    return {"status": "ok"}
