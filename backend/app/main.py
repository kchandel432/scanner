# backend/app/main.py

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles

from backend.core.settings import settings
from backend.core.logger import setup_logging
from backend.app.lifespan import lifespan
from backend.app.middleware import SecurityMiddleware  # Updated import
from backend.api.router import api_router
from backend.frontend.routes.web import web_router
from backend.frontend.routes.websocket_routes import router as ws_router
from backend.frontend.routes.htmx_routes import htmx_router

# ------------------------
# Logging setup
# ------------------------
logger = setup_logging()

# ------------------------
# Lifespan management
# ------------------------
@asynccontextmanager
async def app_lifespan(app: FastAPI):
    """Application startup/shutdown lifecycle"""
    logger.info("Starting Cyber Risk Intelligence Platform")
    await lifespan.startup()
    yield
    await lifespan.shutdown()
    logger.info("Platform shutting down")


# ------------------------
# Create FastAPI app
# ------------------------
app = FastAPI(
    title="Cyber Risk Intelligence Platform",
    description="AI-Powered Cyber Risk Assessment for Investors",
    version=settings.APP_VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=app_lifespan,
)

# ------------------------
# Middleware
# ------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(SecurityMiddleware)  # Our custom security middleware

# ------------------------
# Static files
# ------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "frontend" / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ------------------------
# Routers
# ------------------------
app.include_router(api_router)
app.include_router(web_router)
app.include_router(htmx_router)
app.include_router(ws_router)

# ------------------------
# Health check
# ------------------------
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "cyber-risk-intel",
        "version": settings.APP_VERSION,
    }

# ------------------------
# Run Uvicorn
# ------------------------
if __name__ == "__main__":
    uvicorn.run(
        "backend.app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info",
    )
