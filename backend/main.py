"""
VaultX - AI-Powered VAPT Platform
FastAPI Backend - Main Entry Point
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import uvicorn
import asyncio
import logging
from contextlib import asynccontextmanager

from backend.routers import scans, findings, reports, agents, health
from backend.database import init_db
from backend.config import settings
from backend.queue_manager import init_queues

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("vaultx")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    logger.info("🔐 VaultX Platform starting up...")
    await init_db()
    await init_queues()
    logger.info("✅ All services initialized")
    yield
    logger.info("🛑 VaultX Platform shutting down...")


app = FastAPI(
    title="VaultX VAPT Platform API",
    description="AI-Powered Vulnerability Assessment & Penetration Testing Platform",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(health.router, prefix="/api/health", tags=["Health"])
app.include_router(scans.router, prefix="/api/scans", tags=["Scans"])
app.include_router(findings.router, prefix="/api/findings", tags=["Findings"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(agents.router, prefix="/api/agents", tags=["AI Agents"])


@app.get("/")
async def root():
    return {"service": "VaultX VAPT Platform", "version": "1.0.0", "status": "operational"}


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        workers=settings.WORKERS
    )
