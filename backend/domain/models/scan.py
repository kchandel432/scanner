"""
Scan domain models
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field


class ScanType(str, Enum):
    """Types of scans"""
    FILE = "file"
    WEBSITE = "website"
    API = "api"
    NETWORK = "network"


class ScanStatus(str, Enum):
    """Scan status"""
    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"
    QUEUED = "queued"


class RiskLevel(str, Enum):
    """Risk levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    CLEAN = "clean"


class MalwareType(str, Enum):
    """Malware types"""
    TROJAN = "trojan"
    RANSOMWARE = "ransomware"
    SPYWARE = "spyware"
    ADWARE = "adware"
    ROOTKIT = "rootkit"
    WORN = "worm"
    VIRUS = "virus"
    BACKDOOR = "backdoor"
    MINER = "miner"
    PHISHING = "phishing"
    UNKNOWN = "unknown"


class ScanRequest(BaseModel):
    """Scan request model"""
    scan_type: ScanType
    target: str
    options: Dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(default=1, ge=1, le=10)


class ScanResult(BaseModel):
    """Scan result model"""
    scan_id: str
    status: ScanStatus
    risk_level: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    threats: List[Dict[str, Any]] = Field(default_factory=list)
    indicators: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration: Optional[float] = None

    @property
    def is_completed(self) -> bool:
        """Check if scan is completed"""
        return self.status == ScanStatus.COMPLETED

    @property
    def is_failed(self) -> bool:
        """Check if scan failed"""
        return self.status == ScanStatus.FAILED


class ThreatFinding(BaseModel):
    """Individual threat finding"""
    id: str
    type: str
    severity: RiskLevel
    title: str
    description: str
    evidence: List[str] = Field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)


class RiskScore(BaseModel):
    """Risk score model"""
    overall: float = Field(ge=0.0, le=100.0)
    breakdown: Dict[str, float] = Field(default_factory=dict)
    factors: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    last_updated: datetime = Field(default_factory=datetime.utcnow)

    def get_level(self) -> RiskLevel:
        """Get risk level from score"""
        if self.overall >= 80:
            return RiskLevel.CRITICAL
        elif self.overall >= 60:
            return RiskLevel.HIGH
        elif self.overall >= 40:
            return RiskLevel.MEDIUM
        elif self.overall >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.CLEAN
