import json
from backend.infrastructure.database.models import ScanRecord
from datetime import datetime
from typing import Dict, Any

class ScanRepository:
    def create(self, db, filename: str, malicious: bool, score: float):
        rec = ScanRecord(filename=filename, malicious=malicious, score=score)
        db.add(rec)
        db.commit()
        db.refresh(rec)
        return rec
    
    def save_scan_result(self, db, scan_data: Dict[str, Any]) -> ScanRecord:
        """Save a complete scan result to the database"""
        rec = ScanRecord(
            filename=scan_data.get("filename", "unknown"),
            malicious=scan_data.get("is_malware", False),
            score=scan_data.get("threat_score", 0.0),
            scan_type=scan_data.get("scan_type", "file"),
            target=scan_data.get("target", ""),
            result_data=json.dumps(scan_data.get("result_data", {})),
            created_at=datetime.utcnow()
        )
        db.add(rec)
        db.commit()
        db.refresh(rec)
        return rec
