import asyncio
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from backend.application.services.malware_scanner import AdvancedMalwareScanner
from backend.domain.models.scan import ScanRequest, ScanResponse
from backend.infrastructure.repositories.scan_repo import ScanRepository
from backend.infrastructure.database.session import get_session

router = APIRouter(prefix="/scan", tags=["Scan Operations"])
scanner = AdvancedMalwareScanner()
scan_repo = ScanRepository()


# Pydantic models for request validation
class URLScanRequest(BaseModel):
    url: str


def _calculate_threat_score(results: dict) -> float:
    """Calculate threat score from website scan results"""
    score = 0.0
    if results.get("malware_detected"):
        score += 0.4
    score += results.get("phishing_risk", 0.0) * 0.3
    if results.get("ssl_info", {}).get("has_expired"):
        score += 0.2
    vulnerabilities = results.get("vulnerabilities", [])
    score += min(len(vulnerabilities) * 0.1, 0.3)
    return min(score, 1.0)


class BatchScanRequest(BaseModel):
    file_paths: List[str] = []


@router.get("/health", summary="Health Check")
async def health_check():
    """Check if scan service is healthy"""
    return {
        "status": "healthy",
        "service": "malware-scanner-api",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.post("/file", response_model=ScanResponse, summary="Scan Single File")
async def scan_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="File to scan for malware"),
):
    """Scan uploaded file for malware and threats"""

    # Validate file
    if not file.filename or file.filename.strip() == "":
        raise HTTPException(status_code=400, detail="No file provided")

    # Check file size (limit to 100MB)
    max_size = 100 * 1024 * 1024  # 100MB
    file.file.seek(0, 2)  # Seek to end
    file_size = file.file.tell()
    file.file.seek(0)  # Reset to beginning

    if file_size > max_size:
        raise HTTPException(
            status_code=413, detail=f"File too large. Max size: {max_size/1024/1024}MB"
        )

    # Generate unique filename for temp storage
    file_extension = Path(file.filename).suffix
    temp_filename = f"{uuid.uuid4()}{file_extension}"

    # Save file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=file_extension) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        # Scan file using malware scanner
        print(f"🔍 Scanning file: {file.filename} ({file_size} bytes)")
        results = scanner.scan_file(tmp_path)

        # Save to database in background
        def save_result():
            try:
                with get_session() as db:
                    scan_data = {
                        "filename": file.filename,
                        "is_malware": results.get("threat_level") in ["critical", "high"],
                        "threat_score": results.get("ai_score", 0.0),
                        "scan_type": "file_scan",
                        "target": file.filename,
                        "result_data": results
                    }
                    scan_repo.save_scan_result(db, scan_data)
            except Exception as e:
                print(f"⚠️ Failed to save scan result: {e}")
        
        background_tasks.add_task(save_result)

        # Generate scan response
        scan_response = ScanResponse(
            filename=file.filename,
            scan_id=str(uuid.uuid4()),
            results=results,
            timestamp=datetime.utcnow(),
            file_size=file_size,
            scan_type="file_scan",
        )

        return scan_response

    except Exception as e:
        print(f"❌ Error scanning file: {e}")
        raise HTTPException(status_code=500, detail=f"Error scanning file: {str(e)}")

    finally:
        # Clean up temp file
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


@router.post("/url", summary="Scan URL/Website")
async def scan_url(request: URLScanRequest):
    """Scan URL/website for threats and security issues"""

    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    # Validate URL format
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    try:
        print(f"🔍 Scanning URL: {url}")

        # Scan website
        from backend.application.services.website_scanner import AdvancedWebsiteScanner

        website_scanner = AdvancedWebsiteScanner()

        results = await website_scanner.scan_website(url)

        # Save to database
        try:
            with get_session() as db:
                scan_data = {
                    "filename": url,
                    "is_malware": results.get("malware_detected", False),
                    "threat_score": _calculate_threat_score(results),
                    "scan_type": "website_scan",
                    "target": url,
                    "result_data": results
                }
                scan_repo.save_scan_result(db, scan_data)
        except Exception as e:
            print(f"⚠️ Failed to save scan result to database: {e}")

        return {
            "url": url,
            "scan_id": str(uuid.uuid4()),
            "results": results,
            "timestamp": datetime.utcnow().isoformat(),
            "scan_type": "website_scan",
        }

    except ImportError as e:
        print(f"❌ Website scanner import error: {e}")
        raise HTTPException(
            status_code=501, detail=f"Website scanner module not available. Required packages may be missing: whois, dnspython, aiohttp. Error: {str(e)}"
        )
    except Exception as e:
        print(f"❌ Error scanning URL: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error scanning URL: {str(e)}")


@router.post("/batch", summary="Scan Multiple Files")
async def scan_batch(
    files: List[UploadFile] = File(..., description="Multiple files to scan")
):
    """Scan multiple files simultaneously"""

    if len(files) > 10:
        raise HTTPException(status_code=400, detail="Maximum 10 files per batch")

    if len(files) == 0:
        raise HTTPException(status_code=400, detail="No files provided")

    results = []
    temp_files = []  # Track temp files for cleanup

    for file in files:
        try:
            # Validate file
            if not file.filename:
                results.append(
                    {
                        "filename": "unknown",
                        "error": "No filename provided",
                        "success": False,
                    }
                )
                continue

            # Save file temporarily
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=Path(file.filename).suffix
            ) as tmp:
                content = await file.read()
                tmp.write(content)
                tmp_path = Path(tmp.name)
                temp_files.append(tmp_path)

            print(f"🔍 Scanning batch file: {file.filename}")

            # Scan each file
            scan_result = scanner.scan_file(tmp_path)

            results.append(
                {
                    "filename": file.filename,
                    "results": scan_result,
                    "success": True,
                    "scan_id": str(uuid.uuid4()),
                }
            )

        except Exception as e:
            results.append(
                {
                    "filename": file.filename if file.filename else "unknown",
                    "error": str(e),
                    "success": False,
                }
            )

    # Clean up all temp files
    for tmp_path in temp_files:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)

    return {
        "scans": results,
        "total_files": len(files),
        "successful_scans": len([r for r in results if r.get("success")]),
        "failed_scans": len([r for r in results if not r.get("success")]),
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/status/{scan_id}", summary="Get Scan Status")
async def get_scan_status(scan_id: str):
    """Get status of a specific scan"""
    try:
        # Try to get scan from database
        scan_data = scan_repo.get_scan_by_id(scan_id)

        if scan_data:
            return {
                "scan_id": scan_id,
                "status": "completed",
                "data": scan_data,
                "timestamp": datetime.utcnow().isoformat(),
            }
        else:
            return {
                "scan_id": scan_id,
                "status": "not_found",
                "message": "Scan ID not found in database",
                "timestamp": datetime.utcnow().isoformat(),
            }

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error retrieving scan status: {str(e)}"
        )


@router.get("/recent", summary="Get Recent Scans")
async def get_recent_scans(limit: int = 10):
    """Get recent scan results"""
    try:
        recent_scans = scan_repo.get_recent_scans(limit)

        return {
            "scans": recent_scans,
            "total": len(recent_scans),
            "limit": limit,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error retrieving recent scans: {str(e)}"
        )


@router.get("/engines", summary="Get Available Scan Engines")
async def get_scan_engines():
    """Get list of available scan engines and their status"""
    try:
        engines = []

        # Check YARA engine
        try:
            import yara

            engines.append(
                {
                    "name": "YARA",
                    "status": "available",
                    "description": "Pattern matching for malware detection",
                }
            )
        except ImportError:
            engines.append(
                {
                    "name": "YARA",
                    "status": "unavailable",
                    "description": "YARA library not installed",
                    "error": "Install yara-python and libyara.dll",
                }
            )

        # Check PE file analyzer
        try:
            import pefile

            engines.append(
                {
                    "name": "PE Analyzer",
                    "status": "available",
                    "description": "Windows PE file analysis",
                }
            )
        except ImportError:
            engines.append(
                {
                    "name": "PE Analyzer",
                    "status": "unavailable",
                    "description": "PE file analysis not available",
                    "error": "Install pefile module",
                }
            )

        # Check magic file type detection
        try:
            import magic

            engines.append(
                {
                    "name": "File Type Detection",
                    "status": "available",
                    "description": "File type and MIME detection",
                }
            )
        except ImportError:
            engines.append(
                {
                    "name": "File Type Detection",
                    "status": "unavailable",
                    "description": "File type detection not available",
                    "error": "Install python-magic-bin module",
                }
            )

        # Website scanner check
        try:
            from backend.application.services.website_scanner import (
                AdvancedWebsiteScanner,
            )

            engines.append(
                {
                    "name": "Website Scanner",
                    "status": "available",
                    "description": "Website security and threat analysis",
                }
            )
        except ImportError:
            engines.append(
                {
                    "name": "Website Scanner",
                    "status": "unavailable",
                    "description": "Website scanner not configured",
                }
            )

        return {
            "engines": engines,
            "total_engines": len(engines),
            "available_engines": len(
                [e for e in engines if e["status"] == "available"]
            ),
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error retrieving engine status: {str(e)}"
        )
