from sqlalchemy import Column, Integer, String, Boolean, Float
from backend.domain.schemas.database import Base

class ScanRecord(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True)
    filename = Column(String, nullable=False)
    malicious = Column(Boolean, default=False)
    score = Column(Float, default=0.0)
