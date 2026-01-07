from fastapi import APIRouter
from backend.api.v1.endpoints import scan, website, analysis, reports

router = APIRouter()
router.include_router(scan.router, prefix="/scan", tags=["scan"])
router.include_router(website.router, prefix="/website", tags=["website"])
router.include_router(analysis.router, prefix="/analysis", tags=["analysis"])
router.include_router(reports.router, prefix="/reports", tags=["reports"])
