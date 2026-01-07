"""
Web routes for server-rendered pages
"""
from fastapi import APIRouter, Request, Depends
from fastapi.templating import Jinja2Templates
from typing import Dict, Any
import datetime

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")

# Mock data for demo
def get_mock_dashboard_data() -> Dict[str, Any]:
    """Get mock dashboard data"""
    return {
        "stats": {
            "total_scans": 1247,
            "active_threats": 23,
            "risk_score": 68,
            "uptime": "99.9%"
        },
        "recent_scans": [
            {
                "id": "scan_001",
                "target": "example.com",
                "type": "website",
                "status": "completed",
                "risk_level": "medium",
                "timestamp": datetime.datetime.now() - datetime.timedelta(hours=1)
            },
            {
                "id": "scan_002",
                "target": "malware.exe",
                "type": "file",
                "status": "completed",
                "risk_level": "high",
                "timestamp": datetime.datetime.now() - datetime.timedelta(hours=2)
            }
        ],
        "alerts": [
            {
                "id": "alert_001",
                "title": "Suspicious Network Activity",
                "severity": "high",
                "source": "192.168.1.100",
                "timestamp": datetime.datetime.now() - datetime.timedelta(minutes=30)
            },
            {
                "id": "alert_002",
                "title": "Malware Detected",
                "severity": "critical",
                "source": "uploaded_file.exe",
                "timestamp": datetime.datetime.now() - datetime.timedelta(minutes=45)
            }
        ]
    }

@router.get("/")
async def dashboard(request: Request):
    """Main dashboard page"""
    data = get_mock_dashboard_data()
    return templates.TemplateResponse(
        "pages/dashboard.html",
        {
            "request": request,
            "page_title": "Dashboard",
            "page_subtitle": "AI-Powered Cyber Risk Assessment",
            **data
        }
    )

@router.get("/scan")
async def scan_page(request: Request):
    """Scan page"""
    return templates.TemplateResponse(
        "pages/scan.html",
        {
            "request": request,
            "page_title": "Scanner",
            "page_subtitle": "Scan files and websites for threats"
        }
    )

@router.get("/reports")
async def reports_page(request: Request):
    """Reports page"""
    return templates.TemplateResponse(
        "pages/reports.html",
        {
            "request": request,
            "page_title": "Reports",
            "page_subtitle": "View detailed scan reports and analytics"
        }
    )

@router.get("/settings")
async def settings_page(request: Request):
    """Settings page"""
    return templates.TemplateResponse(
        "pages/settings.html",
        {
            "request": request,
            "page_title": "Settings",
            "page_subtitle": "Configure platform settings"
        }
    )
# Export router
web_router = router