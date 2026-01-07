from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean, JSON, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from backend.persistence.db.session import Base

class SecurityReport(Base):
    """Security report model"""
    __tablename__ = "security_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(String(64), unique=True, index=True, nullable=False)
    scan_id = Column(String(64), ForeignKey("scan_results.scan_id"), nullable=False)
    report_type = Column(String(32), nullable=False)  # executive, technical, forensic, compliance
    format = Column(String(16), nullable=False)  # pdf, json, html, zip
    generated_by = Column(String(128), nullable=False)
    generated_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Report content
    report_data = Column(JSON, nullable=True)  # JSON structure of report data
    report_file = Column(Text, nullable=False)  # Base64 encoded report file
    file_size = Column(Integer, nullable=False)
    
    # Security features
    hash_sha256 = Column(String(64), nullable=False)
    digital_signature = Column(Text, nullable=True)
    watermarked = Column(Boolean, default=False)
    
    # Verification
    verification_url = Column(String(256), nullable=True)
    verification_code = Column(String(32), nullable=True)
    
    # Access control
    access_token = Column(String(64), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    max_downloads = Column(Integer, default=1)
    download_count = Column(Integer, default=0)
    
    # Relationships
    scan = relationship("ScanResult", back_populates="reports")
    downloads = relationship("ReportDownload", back_populates="report")
    
    def __repr__(self):
        return f"<SecurityReport {self.report_id} ({self.report_type}.{self.format})>"

class ReportDownload(Base):
    """Track report downloads"""
    __tablename__ = "report_downloads"
    
    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(String(64), ForeignKey("security_reports.report_id"), nullable=False)
    downloaded_by = Column(String(128), nullable=False)
    downloaded_at = Column(DateTime(timezone=True), server_default=func.now())
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(512), nullable=True)
    download_method = Column(String(32), nullable=False)  # direct, share, api
    
    # Relationships
    report = relationship("SecurityReport", back_populates="downloads")

class ReportShare(Base):
    """Shareable report links"""
    __tablename__ = "report_shares"
    
    id = Column(Integer, primary_key=True, index=True)
    share_token = Column(String(64), unique=True, index=True, nullable=False)
    report_id = Column(String(64), ForeignKey("security_reports.report_id"), nullable=False)
    created_by = Column(String(128), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    password_hash = Column(String(256), nullable=True)
    max_downloads = Column(Integer, default=1)
    downloads_used = Column(Integer, default=0)
    enabled = Column(Boolean, default=True)
    
    # Access tracking
    last_accessed = Column(DateTime(timezone=True), nullable=True)
    access_count = Column(Integer, default=0)

class ComplianceEvidence(Base):
    """Compliance evidence tracking"""
    __tablename__ = "compliance_evidence"
    
    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(String(64), ForeignKey("security_reports.report_id"), nullable=False)
    standard = Column(String(32), nullable=False)  # iso27001, soc2, gdpr, hipaa, pci_dss
    requirement = Column(String(128), nullable=False)
    status = Column(String(32), nullable=False)  # compliant, non_compliant, partial, not_applicable
    evidence = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    verified_by = Column(String(128), nullable=True)
    verified_at = Column(DateTime(timezone=True), nullable=True)
