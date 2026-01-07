from backend.infrastructure.database.models import ScanRecord

class ScanRepository:
    def create(self, db, filename: str, malicious: bool, score: float):
        rec = ScanRecord(filename=filename, malicious=malicious, score=score)
        db.add(rec)
        db.commit()
        db.refresh(rec)
        return rec
