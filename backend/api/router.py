"""
Main API router
"""
from fastapi import APIRouter
from backend.api.v1.router import router as v1_router

# Create router
api_router = APIRouter(prefix="/api", tags=["api"])

# Health check
@api_router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "cyber-risk-intel",
        "version": "1.0.0"
    }

# Include v1 routes
api_router.include_router(v1_router, prefix="/v1")
