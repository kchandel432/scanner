"""
API v1 router - aggregates all v1 endpoints
"""
from fastapi import APIRouter

# Import all endpoint routers
from backend.api.v1.endpoints.scan import router as scan_router
from backend.api.v1.endpoints.website import router as website_router
from backend.api.v1.endpoints.analysis import router as analysis_router
from backend.api.v1.endpoints.auth import router as auth_router
from backend.api.v1.endpoints.report import router as report_router
from backend.api.v1.endpoints.reports import router as reports_router

# Create v1 router (no prefix - already handled by api_router)
router = APIRouter()

# Include all endpoint routers
router.include_router(scan_router)
router.include_router(website_router)
router.include_router(analysis_router)
router.include_router(auth_router)
router.include_router(report_router)
router.include_router(reports_router)
