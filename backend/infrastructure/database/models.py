from sqlalchemy import Column, Integer, String, Boolean, Float, DateTime, Text
from backend.domain.schemas.database import Base
from datetime import datetime

class ScanRecord(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True)
    filename = Column(String, nullable=False)
    malicious = Column(Boolean, default=False)
    score = Column(Float, default=0.0)
    scan_type = Column(String, default="file")
    target = Column(String, default="")
    result_data = Column(Text, default="{}")
    created_at = Column(DateTime, default=datetime.utcnow)
