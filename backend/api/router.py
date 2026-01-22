"""
Main API router
"""
from fastapi import APIRouter
from backend.api.v1.router import router as v1_router

# Create router
api_router = APIRouter(prefix="/api", tags=["api"])

# Include v1 routes
api_router.include_router(v1_router, prefix="/v1")
