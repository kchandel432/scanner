from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from typing import List
import tempfile
import uuid
from pathlib import Path
from datetime import datetime
from backend.application.services.malware_scanner import AdvancedMalwareScanner
from backend.domain.models.scan import ScanRequest, ScanResponse
from backend.infrastructure.repositories.scan_repo import ScanRepository
import asyncio

router = APIRouter()
scanner = AdvancedMalwareScanner()
scan_repo = ScanRepository()

@router.post("/scan/file", response_model=ScanResponse)
async def scan_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    """Scan uploaded file for malware"""
    
    # Validate file
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    # Check file size (limit to 100MB)
    max_size = 100 * 1024 * 1024
    file.file.seek(0, 2)  # Seek to end
    file_size = file.file.tell()
    file.file.seek(0)  # Reset to beginning
    
    if file_size > max_size:
        raise HTTPException(
            status_code=413, 
            detail=f"File too large. Max size: {max_size/1024/1024}MB"
        )
    
    # Save file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=Path(file.filename).suffix) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = Path(tmp.name)
    
    try:
        # Scan file
        results = scanner.scan_file(tmp_path)
        
        # Save to database in background
        background_tasks.add_task(
            scan_repo.save_scan_result,
            file.filename,
            results,
            "file_scan"
        )
        
        return ScanResponse(
            filename=file.filename,
            scan_id=str(uuid.uuid4()),
            results=results,
            timestamp=datetime.utcnow()
        )
        
    finally:
        # Clean up temp file
        tmp_path.unlink(missing_ok=True)

@router.post("/scan/url")
async def scan_url(request: dict):
    """Scan URL/website for threats"""
    url = request.get("url")
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    
    # Validate URL format
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    
    # Scan website
    from backend.application.services.website_scanner import AdvancedWebsiteScanner
    website_scanner = AdvancedWebsiteScanner()
    
    results = await website_scanner.scan_website(url)
    
    # Save to database
    scan_repo.save_scan_result(url, results, "website_scan")
    
    return {
        "url": url,
        "scan_id": str(uuid.uuid4()),
        "results": results,
        "timestamp": datetime.utcnow().isoformat()
    }

@router.post("/scan/batch")
async def scan_batch(files: List[UploadFile] = File(...)):
    """Scan multiple files"""
    if len(files) > 10:
        raise HTTPException(status_code=400, detail="Maximum 10 files per batch")
    
    results = []
    for file in files:
        try:
            # Create temporary file
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                content = await file.read()
                tmp.write(content)
                tmp_path = Path(tmp.name)
            
            # Scan each file
            scan_result = scanner.scan_file(tmp_path)
            results.append({
                "filename": file.filename,
                "results": scan_result
            })
            
            # Clean up
            tmp_path.unlink()
            
        except Exception as e:
            results.append({
                "filename": file.filename,
                "error": str(e)
            })
    
    return {"scans": results}
