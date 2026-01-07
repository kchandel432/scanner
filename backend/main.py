"""
Cyber Risk Intelligence Platform - Main Entry Point
"""
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
import uvicorn
from pathlib import Path
from backend.app.middleware import SecurityMiddleware


from backend.core.settings import settings
from backend.core.logger import setup_logging
from backend.app.lifespan import lifespan
from backend.app.middleware import SecurityMiddleware
from backend.api.router import api_router
from backend.frontend.routes.web import web_router
from backend.frontend.routes.websocket_routes import router as ws_router
from backend.frontend.routes.htmx_routes import htmx_router
from backend.frontend.templates_engine import templates

# Setup logging
logger = setup_logging()

@asynccontextmanager
async def app_lifespan(app: FastAPI):
    """Application lifespan management"""
    logger.info("Starting Cyber Risk Intelligence Platform")
    
    # Startup tasks
    await lifespan.startup()
    
    yield
    
    # Shutdown tasks
    await lifespan.shutdown()
    logger.info("Platform shutting down")

# Create FastAPI app
app = FastAPI(
    title="Cyber Risk Intelligence Platform",
    description="AI-Powered Cyber Risk Assessment for Investors",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=app_lifespan
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(SecurityMiddleware)

# Mount static files
import os
BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "backend" / "frontend" / "static"

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Include routers
app.include_router(api_router)
app.include_router(web_router)
app.include_router(htmx_router)
app.include_router(ws_router)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "cyber-risk-intel",
        "version": "1.0.0"
    }

if __name__ == "__main__":
    uvicorn.run(
        "backend.app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info"
    )