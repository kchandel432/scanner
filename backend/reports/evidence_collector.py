from typing import Dict, List, Any
from datetime import datetime, timedelta
import sqlalchemy as sa
from sqlalchemy.orm import Session
from backend.persistence.db.session import get_db
from backend.persistence.models import ScanResult, ThreatFinding, Vulnerability

class EvidenceCollector:
    """Collect evidence from various sources for report generation"""
    
    def __init__(self):
        self.db_session = get_db()
    
    def collect_for_scan(self, scan_id: str) -> Dict[str, Any]:
        """Collect all evidence for a specific scan"""
        evidence = {}
        
        # Get scan results from database
        scan_result = self.db_session.query(ScanResult).filter(
            ScanResult.scan_id == scan_id
        ).first()
        
        if not scan_result:
            raise ValueError(f"Scan ID {scan_id} not found")
        
        # Basic scan information
        evidence["scan_info"] = {
            "scan_id": scan_result.scan_id,
            "scan_type": scan_result.scan_type,
            "start_time": scan_result.start_time,
            "end_time": scan_result.end_time,
            "status": scan_result.status,
            "target": scan_result.target,
            "initiated_by": scan_result.initiated_by
        }
        
        # Get threat findings
        threats = self.db_session.query(ThreatFinding).filter(
            ThreatFinding.scan_id == scan_id
        ).all()
        
        evidence["threats"] = [
            self._process_threat(threat) for threat in threats
        ]
        
        # Get vulnerabilities
        vulnerabilities = self.db_session.query(Vulnerability).filter(
            Vulnerability.scan_id == scan_id
        ).all()
        
        evidence["vulnerabilities"] = [
            self._process_vulnerability(vuln) for vuln in vulnerabilities
        ]
        
        # Get forensic data
        evidence["forensics"] = self._collect_forensic_data(scan_id)
        
        # Get AI analysis results
        evidence["ai_analysis"] = self._collect_ai_analysis(scan_id)
        
        # Get behavioral data
        evidence["behavioral"] = self._collect_behavioral_data(scan_id)
        
        # Get network data
        evidence["network"] = self._collect_network_data(scan_id)
        
        # Get threat intelligence correlations
        evidence["threat_intel"] = self._collect_threat_intel(evidence)
        
        # Calculate statistics
        evidence["statistics"] = self._calculate_statistics(evidence)
        
        # Generate timeline
        evidence["timeline"] = self._generate_timeline(scan_id)
        
        return evidence
    
    def _process_threat(self, threat: ThreatFinding) -> Dict:
        """Process threat finding into report format"""
        return {
            "id": threat.id,
            "name": threat.name,
            "type": threat.threat_type,
            "severity": threat.severity,
            "description": threat.description,
            "confidence": threat.confidence_score,
            "detection_method": threat.detection_method,
            "source": threat.source,
            "target": threat.target,
            "timestamp": threat.detected_at.isoformat(),
            "affected_assets": threat.affected_assets or [],
            "indicators": threat.indicators or [],
            "mitigation": threat.mitigation_recommendations or [],
            "evidence": threat.evidence or [],
            "status": threat.status,
            "assigned_to": threat.assigned_to,
            "notes": threat.notes or ""
        }
    
    def _process_vulnerability(self, vuln: Vulnerability) -> Dict:
        """Process vulnerability finding"""
        return {
            "id": vuln.id,
            "name": vuln.name,
            "description": vuln.description,
            "cvss_score": float(vuln.cvss_score) if vuln.cvss_score else 0,
            "cvss_vector": vuln.cvss_vector,
            "severity": vuln.severity,
            "category": vuln.category,
            "affected_component": vuln.affected_component,
            "exploitation_likelihood": vuln.exploitation_likelihood,
            "exploitation_impact": vuln.exploitation_impact,
            "detected_at": vuln.detected_at.isoformat(),
            "remediation": vuln.remediation_steps or [],
            "references": vuln.references or [],
            "patch_available": vuln.patch_available,
            "patch_url": vuln.patch_url,
            "workaround": vuln.workaround,
            "verified": vuln.verified,
            "false_positive": vuln.false_positive
        }
    
    def _collect_forensic_data(self, scan_id: str) -> Dict:
        """Collect forensic evidence"""
        # Query forensic data from database
        # This is simplified - in reality, you'd query multiple tables
        
        return {
            "file_hashes": self._get_file_hashes(scan_id),
            "memory_analysis": self._get_memory_analysis(scan_id),
            "registry_changes": self._get_registry_changes(scan_id),
            "process_tree": self._get_process_tree(scan_id),
            "network_connections": self._get_network_connections(scan_id),
            "dns_queries": self._get_dns_queries(scan_id),
            "user_activity": self._get_user_activity(scan_id),
            "timeline_events": self._get_timeline_events(scan_id)
        }
    
    def _collect_ai_analysis(self, scan_id: str) -> Dict:
        """Collect AI analysis results"""
        # Query AI analysis results
        return {
            "malware_detection": {
                "score": 0.95,
                "confidence": 0.92,
                "family": "Trojan.Win32.Emotet",
                "behavior_patterns": ["Process injection", "Persistence", "C2 communication"],
                "intent_analysis": {
                    "steal_data": 0.85,
                    "backdoor": 0.92,
                    "ransomware": 0.12,
                    "spyware": 0.78
                }
            },
            "anomaly_detection": {
                "score": 0.88,
                "anomalies": ["Unusual registry access", "Suspicious network traffic"],
                "baseline_deviation": 2.3
            }
        }
    
    def _collect_behavioral_data(self, scan_id: str) -> Dict:
        """Collect behavioral analysis data"""
        return {
            "api_calls": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"],
            "file_operations": ["Created: C:\\Windows\\Temp\\malware.exe"],
            "registry_operations": ["Modified: HKLM\\Software\\Malware\\Config"],
            "process_behavior": ["Process hollowing detected", "Code injection detected"],
            "persistence_mechanisms": ["Registry run key", "Scheduled task", "Service installation"]
        }
    
    def _collect_network_data(self, scan_id: str) -> Dict:
        """Collect network analysis data"""
        return {
            "connections": [
                {"ip": "192.168.1.100", "port": 443, "protocol": "TCP", "status": "ESTABLISHED"},
                {"ip": "10.0.0.5", "port": 8080, "protocol": "TCP", "status": "LISTENING"}
            ],
            "dns_requests": ["malicious-domain.com", "c2-server.net"],
            "http_requests": ["POST /api/data", "GET /config"],
            "suspicious_traffic": ["Beaconing detected", "Data exfiltration attempt"]
        }
    
    def _collect_threat_intel(self, evidence: Dict) -> Dict:
        """Correlate with threat intelligence"""
        return {
            "ioc_matches": self._check_ioc_matches(evidence),
            "threat_actors": self._identify_threat_actors(evidence),
            "campaigns": self._identify_campaigns(evidence),
            "malware_families": self._identify_malware_families(evidence),
            "mitre_att&ck": self._map_to_mitre_attck(evidence)
        }
    
    def _calculate_statistics(self, evidence: Dict) -> Dict:
        """Calculate evidence statistics"""
        threats = evidence.get("threats", [])
        vulnerabilities = evidence.get("vulnerabilities", [])
        
        return {
            "total_threats": len(threats),
            "total_vulnerabilities": len(vulnerabilities),
            "critical_count": sum(1 for t in threats if t.get("severity") == "critical"),
            "high_count": sum(1 for t in threats if t.get("severity") == "high"),
            "medium_count": sum(1 for t in threats if t.get("severity") == "medium"),
            "low_count": sum(1 for t in threats if t.get("severity") == "low"),
            "threat_categories": self._count_categories(threats),
            "vulnerability_types": self._count_vulnerability_types(vulnerabilities),
            "timeline_summary": self._summarize_timeline(evidence.get("timeline", []))
        }
    
    def _generate_timeline(self, scan_id: str) -> List[Dict]:
        """Generate chronological timeline of events"""
        # Query events from database
        return [
            {
                "timestamp": "2024-01-15T10:30:00Z",
                "event": "Scan initiated",
                "source": "User: admin",
                "details": "Full system scan started"
            },
            {
                "timestamp": "2024-01-15T10:31:15Z",
                "event": "Malware detected",
                "source": "AI Engine",
                "details": "Trojan.Win32.Emotet - Confidence: 92%"
            },
            {
                "timestamp": "2024-01-15T10:32:00Z",
                "event": "Behavior anomaly",
                "source": "Behavior Monitor",
                "details": "Process injection detected in svchost.exe"
            },
            {
                "timestamp": "2024-01-15T10:33:45Z",
                "event": "Network threat",
                "source": "Network Monitor",
                "details": "C2 communication to malicious-domain.com"
            },
            {
                "timestamp": "2024-01-15T10:35:00Z",
                "event": "Scan completed",
                "source": "Scan Engine",
                "details": "Scan finished with 5 threats identified"
            }
        ]
    
    # Helper methods (simplified for example)
    def _get_file_hashes(self, scan_id: str) -> List[str]:
        return ["a1b2c3d4e5f6...", "sha256:abc123..."]
    
    def _get_memory_analysis(self, scan_id: str) -> Dict:
        return {"dump_available": True, "size_mb": 256}
    
    def _get_registry_changes(self, scan_id: str) -> List[str]:
        return ["HKLM\\Software\\Malware\\Config"]
    
    def _get_process_tree(self, scan_id: str) -> List[Dict]:
        return [{"pid": 1234, "name": "malware.exe", "parent": "explorer.exe"}]
    
    def _get_network_connections(self, scan_id: str) -> List[Dict]:
        return [{"ip": "192.168.1.100", "port": 443}]
    
    def _get_dns_queries(self, scan_id: str) -> List[str]:
        return ["malicious-domain.com"]
    
    def _get_user_activity(self, scan_id: str) -> List[Dict]:
        return [{"user": "admin", "action": "file_execute", "file": "malware.exe"}]
    
    def _get_timeline_events(self, scan_id: str) -> List[Dict]:
        return []
    
    def _check_ioc_matches(self, evidence: Dict) -> List[Dict]:
        return []
    
    def _identify_threat_actors(self, evidence: Dict) -> List[str]:
        return ["APT29", "Lazarus Group"]
    
    def _identify_campaigns(self, evidence: Dict) -> List[str]:
        return ["Operation GhostShell"]
    
    def _identify_malware_families(self, evidence: Dict) -> List[str]:
        return ["Emotet", "TrickBot"]
    
    def _map_to_mitre_attck(self, evidence: Dict) -> List[Dict]:
        return [
            {"technique": "T1055", "name": "Process Injection", "tactic": "Privilege Escalation"},
            {"technique": "T1543", "name": "Create or Modify System Process", "tactic": "Persistence"}
        ]
    
    def _count_categories(self, threats: List[Dict]) -> Dict:
        categories = {}
        for threat in threats:
            cat = threat.get("type", "unknown")
            categories[cat] = categories.get(cat, 0) + 1
        return categories
    
    def _count_vulnerability_types(self, vulnerabilities: List[Dict]) -> Dict:
        types = {}
        for vuln in vulnerabilities:
            t = vuln.get("category", "unknown")
            types[t] = types.get(t, 0) + 1
        return types
    
    def _summarize_timeline(self, timeline: List[Dict]) -> Dict:
        return {
            "start": timeline[0]["timestamp"] if timeline else None,
            "end": timeline[-1]["timestamp"] if timeline else None,
            "duration_minutes": 5,
            "event_count": len(timeline)
        }
