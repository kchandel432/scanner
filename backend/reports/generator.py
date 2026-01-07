import json
import hashlib
import zipfile
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, BinaryIO
from dataclasses import dataclass
import pandas as pd
from jinja2 import Environment, FileSystemLoader
import weasyprint
import pdfkit
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

@dataclass
class ReportMetadata:
    """Report metadata for tracking and verification"""
    report_id: str
    scan_id: str
    client_id: str
    report_type: str  # executive, technical, forensic, compliance
    generated_at: datetime
    generated_by: str
    version: str = "2.0"
    format: str = "pdf"
    language: str = "en"

class EnterpriseReportGenerator:
    """Enterprise-grade report generator with compliance features"""
    
    def __init__(self, templates_dir: str = "backend/reports/templates"):
        self.templates_dir = Path(templates_dir)
        self.jinja_env = Environment(
            loader=FileSystemLoader(self.templates_dir),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True
        )
        self.evidence_collector = EvidenceCollector()
        self.signer = ReportSigner()
        self.watermarker = ReportWatermarker()
        
    def generate_report(self, scan_id: str, report_type: str, 
                       client_info: Dict, format: str = "pdf") -> Dict[str, Any]:
        """Generate comprehensive security report"""
        
        # 1. Collect evidence and analysis data
        evidence = self.evidence_collector.collect_for_scan(scan_id)
        
        # 2. Calculate risk scores
        risk_assessment = self._calculate_risk_assessment(evidence)
        
        # 3. Prepare report data
        report_data = {
            "metadata": ReportMetadata(
                report_id=f"BL-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                scan_id=scan_id,
                client_id=client_info.get("client_id", "anonymous"),
                report_type=report_type,
                generated_at=datetime.now(timezone.utc),
                generated_by="BlackLotus AI Security Platform",
                format=format
            ),
            "client": client_info,
            "executive_summary": self._generate_executive_summary(evidence, risk_assessment),
            "detailed_findings": self._generate_detailed_findings(evidence),
            "threat_intelligence": self._gather_threat_intelligence(evidence),
            "risk_assessment": risk_assessment,
            "recommendations": self._generate_recommendations(risk_assessment),
            "compliance_checklist": self._generate_compliance_checklist(evidence),
            "forensic_evidence": evidence.get("forensics", {}),
            "appendices": self._generate_appendices(evidence)
        }
        
        # 4. Generate report based on type and format
        if report_type == "executive":
            report_file = self._generate_executive_report(report_data, format)
        elif report_type == "technical":
            report_file = self._generate_technical_report(report_data, format)
        elif report_type == "forensic":
            report_file = self._generate_forensic_report(report_data, format)
        elif report_type == "compliance":
            report_file = self._generate_compliance_report(report_data, format)
        else:
            raise ValueError(f"Unknown report type: {report_type}")
        
        # 5. Add security features
        report_file = self.watermarker.add_watermark(report_file, client_info)
        report_file = self.signer.sign_report(report_file, report_data["metadata"])
        
        # 6. Generate verification data
        verification = self._generate_verification_data(report_file, report_data)
        
        return {
            "report_file": report_file,
            "report_data": report_data,
            "verification": verification,
            "download_url": self._generate_download_url(report_data["metadata"])
        }
    
    def _generate_executive_report(self, data: Dict, format: str) -> bytes:
        """Generate executive summary report for management"""
        template = self.jinja_env.get_template("executive.html.j2")
        html_content = template.render(**data)
        
        if format == "pdf":
            return self._html_to_pdf(html_content, "executive")
        elif format == "html":
            return html_content.encode('utf-8')
        elif format == "json":
            return json.dumps({
                "executive_summary": data["executive_summary"],
                "risk_assessment": data["risk_assessment"],
                "recommendations": data["recommendations"]
            }, indent=2).encode('utf-8')
    
    def _generate_technical_report(self, data: Dict, format: str) -> bytes:
        """Generate technical report for IT/Security teams"""
        template = self.jinja_env.get_template("technical.html.j2")
        html_content = template.render(**data)
        
        if format == "pdf":
            return self._html_to_pdf(html_content, "technical")
        elif format == "html":
            return html_content.encode('utf-8')
        elif format == "json":
            # Return all technical details
            return json.dumps(data, indent=2).encode('utf-8')
    
    def _generate_forensic_report(self, data: Dict, format: str) -> bytes:
        """Generate forensic evidence bundle"""
        if format == "zip":
            return self._create_forensic_zip(data)
        else:
            return self._generate_technical_report(data, format)
    
    def _create_forensic_zip(self, data: Dict) -> bytes:
        """Create forensic evidence bundle as ZIP"""
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp:
            with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Add JSON evidence
                evidence_json = json.dumps(data["forensic_evidence"], indent=2)
                zipf.writestr("evidence.json", evidence_json)
                
                # Add timeline CSV
                timeline_csv = self._export_timeline_csv(data)
                zipf.writestr("timeline.csv", timeline_csv)
                
                # Add IOC list
                ioc_csv = self._export_ioc_csv(data)
                zipf.writestr("iocs.csv", ioc_csv)
                
                # Add memory dump if available
                if "memory_dump" in data["forensic_evidence"]:
                    zipf.writestr("memory_analysis.txt", 
                                str(data["forensic_evidence"]["memory_dump"]))
                
                # Add network capture if available
                if "network_capture" in data["forensic_evidence"]:
                    zipf.writestr("network_traffic.pcap", 
                                data["forensic_evidence"]["network_capture"])
                
                # Add report summary
                summary = self._generate_executive_report(data, "json")
                zipf.writestr("report_summary.json", summary)
                
                # Add chain of custody
                chain_of_custody = self._generate_chain_of_custody(data)
                zipf.writestr("chain_of_custody.txt", chain_of_custody)
            
            # Read ZIP content
            tmp.flush()
            with open(tmp.name, 'rb') as f:
                zip_content = f.read()
        
        Path(tmp.name).unlink()
        return zip_content
    
    def _calculate_risk_assessment(self, evidence: Dict) -> Dict:
        """Calculate comprehensive risk assessment"""
        threats = evidence.get("threats", [])
        vulnerabilities = evidence.get("vulnerabilities", [])
        
        # Calculate risk scores
        risk_scores = {
            "overall_risk": 0,
            "threat_risk": 0,
            "vulnerability_risk": 0,
            "compliance_risk": 0,
            "business_impact": 0
        }
        
        # Threat-based scoring
        threat_severities = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 1
        }
        
        for threat in threats:
            severity = threat.get("severity", "medium")
            risk_scores["threat_risk"] += threat_severities.get(severity, 4)
        
        # Vulnerability scoring (CVSS-based)
        for vuln in vulnerabilities:
            cvss_score = float(vuln.get("cvss_score", 0))
            risk_scores["vulnerability_risk"] += cvss_score
        
        # Overall risk calculation
        risk_scores["overall_risk"] = (
            risk_scores["threat_risk"] * 0.5 +
            risk_scores["vulnerability_risk"] * 0.3 +
            risk_scores["compliance_risk"] * 0.2
        )
        
        # Determine risk level
        if risk_scores["overall_risk"] >= 80:
            risk_level = "CRITICAL"
        elif risk_scores["overall_risk"] >= 60:
            risk_level = "HIGH"
        elif risk_scores["overall_risk"] >= 40:
            risk_level = "MEDIUM"
        elif risk_scores["overall_risk"] >= 20:
            risk_level = "LOW"
        else:
            risk_level = "INFORMATIONAL"
        
        return {
            **risk_scores,
            "risk_level": risk_level,
            "risk_matrix": self._generate_risk_matrix(threats, vulnerabilities),
            "risk_trend": self._calculate_risk_trend(evidence.get("history", []))
        }
    
    def _generate_executive_summary(self, evidence: Dict, risk: Dict) -> Dict:
        """Generate executive summary"""
        return {
            "overview": f"Security assessment completed on {datetime.now().strftime('%B %d, %Y')}",
            "key_findings": [
                f"Found {len(evidence.get('threats', []))} security threats",
                f"Identified {len(evidence.get('vulnerabilities', []))} vulnerabilities",
                f"Overall risk level: {risk.get('risk_level', 'UNKNOWN')}",
                f"Risk score: {risk.get('overall_risk', 0):.1f}/100"
            ],
            "business_impact": self._calculate_business_impact(evidence),
            "immediate_actions": self._get_immediate_actions(risk),
            "summary_chart": self._generate_summary_chart_data(evidence)
        }
    
    def _generate_detailed_findings(self, evidence: Dict) -> List[Dict]:
        """Generate detailed security findings"""
        findings = []
        
        # Process threats
        for threat in evidence.get("threats", []):
            findings.append({
                "type": "THREAT",
                "severity": threat.get("severity", "medium"),
                "title": threat.get("name", "Unknown Threat"),
                "description": threat.get("description", ""),
                "affected_assets": threat.get("affected_assets", []),
                "detection_method": threat.get("detection_method", ""),
                "confidence": threat.get("confidence", 0),
                "timeline": threat.get("timeline", []),
                "mitigation": threat.get("mitigation", []),
                "evidence": threat.get("evidence", [])
            })
        
        # Process vulnerabilities
        for vuln in evidence.get("vulnerabilities", []):
            findings.append({
                "type": "VULNERABILITY",
                "severity": self._cvss_to_severity(vuln.get("cvss_score", 0)),
                "title": vuln.get("name", "Unknown Vulnerability"),
                "description": vuln.get("description", ""),
                "cvss_score": vuln.get("cvss_score", 0),
                "cvss_vector": vuln.get("cvss_vector", ""),
                "affected_components": vuln.get("affected_components", []),
                "exploitation_likelihood": vuln.get("exploitation_likelihood", "MEDIUM"),
                "exploitation_impact": vuln.get("exploitation_impact", "MEDIUM"),
                "remediation": vuln.get("remediation", ""),
                "references": vuln.get("references", [])
            })
        
        return findings
    
    def _gather_threat_intelligence(self, evidence: Dict) -> Dict:
        """Gather threat intelligence context"""
        return {
            "iocs": {
                "hashes": evidence.get("file_hashes", []),
                "ips": evidence.get("suspicious_ips", []),
                "domains": evidence.get("suspicious_domains", []),
                "urls": evidence.get("suspicious_urls", []),
                "registry_keys": evidence.get("suspicious_registry", []),
                "mutexes": evidence.get("suspicious_mutexes", [])
            },
            "threat_actors": evidence.get("threat_actors", []),
            "campaigns": evidence.get("campaigns", []),
            "malware_families": evidence.get("malware_families", []),
            "timeline": evidence.get("attack_timeline", []),
            "tactics_techniques": evidence.get("mitre_att&ck", [])
        }
    
    def _generate_recommendations(self, risk: Dict) -> List[Dict]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if risk["risk_level"] in ["CRITICAL", "HIGH"]:
            recommendations.append({
                "priority": "IMMEDIATE",
                "category": "CONTAINMENT",
                "action": "Isolate affected systems from network",
                "owner": "Security Team",
                "eta": "Within 1 hour",
                "resources": ["Network team", "System administrators"]
            })
        
        recommendations.extend([
            {
                "priority": "HIGH",
                "category": "REMEDIATION",
                "action": "Apply security patches for identified vulnerabilities",
                "owner": "IT Operations",
                "eta": "Within 24 hours",
                "resources": ["Patch management system", "Vulnerability scanner"]
            },
            {
                "priority": "MEDIUM",
                "category": "DETECTION",
                "action": "Implement additional monitoring for identified attack patterns",
                "owner": "SOC Team",
                "eta": "Within 48 hours",
                "resources": ["SIEM", "EDR solution", "Network monitoring"]
            },
            {
                "priority": "LOW",
                "category": "PREVENTION",
                "action": "Review and update security policies and procedures",
                "owner": "Security Management",
                "eta": "Within 1 week",
                "resources": ["Security policy documents", "Compliance framework"]
            }
        ])
        
        return recommendations
    
    def _generate_compliance_checklist(self, evidence: Dict) -> Dict:
        """Generate compliance checklist"""
        return {
            "iso_27001": self._check_iso27001_compliance(evidence),
            "soc_2": self._check_soc2_compliance(evidence),
            "gdpr": self._check_gdpr_compliance(evidence),
            "hipaa": self._check_hipaa_compliance(evidence),
            "pci_dss": self._check_pci_dss_compliance(evidence)
        }
    
    def _generate_appendices(self, evidence: Dict) -> Dict:
        """Generate report appendices"""
        return {
            "glossary": self._generate_glossary(),
            "acronyms": self._generate_acronyms(),
            "references": self._generate_references(),
            "contact_information": self._generate_contact_info(),
            "disclaimer": self._generate_disclaimer(),
            "methodology": self._generate_methodology(),
            "tools_used": evidence.get("tools_used", [])
        }
    
    def _html_to_pdf(self, html_content: str, report_type: str) -> bytes:
        """Convert HTML to PDF with professional styling"""
        try:
            # Using WeasyPrint for better CSS support
            pdf_bytes = weasyprint.HTML(string=html_content).write_pdf()
            return pdf_bytes
        except Exception as e:
            # Fallback to pdfkit
            options = {
                'page-size': 'A4',
                'margin-top': '0.75in',
                'margin-right': '0.75in',
                'margin-bottom': '0.75in',
                'margin-left': '0.75in',
                'encoding': "UTF-8",
                'no-outline': None,
                'quiet': ''
            }
            
            css = """
            <style>
                @page {
                    margin: 0.75in;
                    @bottom-center {
                        content: "Page " counter(page) " of " counter(pages);
                        font-family: Arial, sans-serif;
                        font-size: 10pt;
                    }
                }
                body {
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                }
                .header {
                    border-bottom: 2px solid #2c3e50;
                    padding-bottom: 10px;
                    margin-bottom: 20px;
                }
                .footer {
                    border-top: 1px solid #ddd;
                    padding-top: 10px;
                    margin-top: 20px;
                    font-size: 9pt;
                    color: #666;
                }
                .risk-critical { color: #e74c3c; font-weight: bold; }
                .risk-high { color: #e67e22; font-weight: bold; }
                .risk-medium { color: #f1c40f; font-weight: bold; }
                .risk-low { color: #2ecc71; font-weight: bold; }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                }
                th, td {
                    border: 1px solid #ddd;
                    padding: 8px;
                    text-align: left;
                }
                th {
                    background-color: #f2f2f2;
                }
            </style>
            """
            
            html_with_css = f"<html><head>{css}</head><body>{html_content}</body></html>"
            
            return pdfkit.from_string(html_with_css, False, options=options)
    
    def _generate_verification_data(self, report_file: bytes, metadata: Dict) -> Dict:
        """Generate verification data for report integrity"""
        # Generate hash
        sha256_hash = hashlib.sha256(report_file).hexdigest()
        
        # Generate digital signature (simplified)
        signature = self._generate_digital_signature(report_file)
        
        return {
            "hash_sha256": sha256_hash,
            "signature": signature,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "report_id": metadata.report_id,
            "verification_url": f"https://verify.blacklotus.ai/{metadata.report_id}"
        }
    
    def _generate_digital_signature(self, data: bytes) -> str:
        """Generate digital signature for report"""
        # In production, use proper digital signature with private key
        return hashlib.sha256(data).hexdigest()
    
    def _generate_download_url(self, metadata: ReportMetadata) -> str:
        """Generate secure download URL"""
        token = hashlib.sha256(
            f"{metadata.report_id}:{metadata.generated_at}:{metadata.client_id}".encode()
        ).hexdigest()[:16]
        
        return f"/api/v1/reports/download/{metadata.report_id}?token={token}"
