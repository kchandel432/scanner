"""
Website security scanner
"""
import aiohttp
import ssl
import socket
import whois
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import asyncio
from datetime import datetime
import dns.resolver

from backend.domain.models import ScanResult, RiskLevel, ThreatFinding
from backend.core.logger import logger

class WebsiteScanner:
    """Advanced website security scanner"""
    
    def __init__(self):
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=30)
        
    async def scan_website(self, url: str) -> ScanResult:
        """Comprehensive website security scan"""
        logger.info(f"🌐 Scanning website: {url}")
        
        # Parse URL
        parsed = urlparse(url)
        if not parsed.scheme:
            url = f"https://{url}"
            parsed = urlparse(url)
        
        domain = parsed.netloc
        
        # Initialize HTTP session
        self.session = aiohttp.ClientSession(timeout=self.timeout)
        
        try:
            # Perform multiple checks in parallel
            checks = await asyncio.gather(
                self.check_ssl(domain),
                self.check_http_headers(url),
                self.check_security_headers(url),
                self.check_dns_security(domain),
                self.check_server_info(url),
                self.check_technology_stack(url),
                self.check_vulnerabilities(url),
                return_exceptions=True
            )
            
            # Process results
            threats = []
            indicators = []
            metadata = {}
            
            for check_result in checks:
                if isinstance(check_result, Exception):
                    logger.warning(f"Check failed: {check_result}")
                    continue
                    
                if isinstance(check_result, dict):
                    if "threats" in check_result:
                        threats.extend(check_result["threats"])
                    if "indicators" in check_result:
                        indicators.extend(check_result["indicators"])
                    if "metadata" in check_result:
                        metadata.update(check_result["metadata"])
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(threats)
            risk_level = self._get_risk_level(risk_score)
            
            # Generate AI summary
            ai_summary = self._generate_ai_summary(threats, domain)
            
            return ScanResult(
                scan_id=f"web_{datetime.utcnow().timestamp()}",
                status="completed",
                risk_level=risk_level,
                confidence=0.9 if len(threats) > 0 else 0.95,
                threats=threats,
                indicators=indicators,
                metadata=metadata,
                statistics={
                    "checks_performed": 8,
                    "threats_found": len(threats),
                    "scan_duration": 0
                }
            )
            
        except Exception as e:
            logger.error(f"Website scan error: {e}")
            raise
        finally:
            if self.session:
                await self.session.close()
    
    async def check_ssl(self, domain: str) -> Dict[str, Any]:
        """Check SSL/TLS configuration"""
        threats = []
        indicators = []
        metadata = {}
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate validity
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_valid = (not_after - datetime.utcnow()).days
                    
                    metadata["ssl"] = {
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "subject": dict(x[0] for x in cert['subject']),
                        "version": cert.get('version', 'Unknown'),
                        "serial_number": cert.get('serialNumber', 'Unknown'),
                        "not_before": cert['notBefore'],
                        "not_after": cert['notAfter'],
                        "days_valid": days_valid
                    }
                    
                    # Check for issues
                    if days_valid < 30:
                        threats.append({
                            "type": "ssl_expiring_soon",
                            "severity": "high",
                            "title": "SSL Certificate Expiring Soon",
                            "description": f"Certificate expires in {days_valid} days",
                            "impact": "Service disruption when certificate expires",
                            "remediation": "Renew SSL certificate"
                        })
                        indicators.append("SSL_EXPIRING_SOON")
                    
                    # Check SSL version
                    cipher = ssock.cipher()
                    if cipher:
                        metadata["ssl"]["cipher"] = cipher[0]
                        metadata["ssl"]["protocol"] = cipher[1]
                        
                        # Check for weak protocols
                        if cipher[1] in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']:
                            threats.append({
                                "type": "weak_ssl_protocol",
                                "severity": "high",
                                "title": "Weak SSL/TLS Protocol",
                                "description": f"Using {cipher[1]} which is considered insecure",
                                "impact": "Vulnerable to various attacks (POODLE, BEAST, etc.)",
                                "remediation": "Disable weak protocols, use TLS 1.2 or higher"
                            })
                            indicators.append("WEAK_SSL_PROTOCOL")
        
        except Exception as e:
            threats.append({
                "type": "ssl_error",
                "severity": "high",
                "title": "SSL/TLS Error",
                "description": f"Failed to establish SSL connection: {str(e)}",
                "impact": "Cannot establish secure connection",
                "remediation": "Check SSL configuration and certificate"
            })
            indicators.append("SSL_ERROR")
        
        return {"threats": threats, "indicators": indicators, "metadata": metadata}
    
    async def check_http_headers(self, url: str) -> Dict[str, Any]:
        """Check HTTP headers for security issues"""
        threats = []
        indicators = []
        metadata = {}
        
        try:
            async with self.session.get(url) as response:
                headers = dict(response.headers)
                metadata["headers"] = headers
                
                # Check for missing security headers
                security_headers = {
                    "Content-Security-Policy": "medium",
                    "X-Frame-Options": "medium",
                    "X-Content-Type-Options": "low",
                    "Referrer-Policy": "low",
                    "Permissions-Policy": "medium",
                    "Strict-Transport-Security": "high"
                }
                
                for header, severity in security_headers.items():
                    if header not in headers:
                        threats.append({
                            "type": f"missing_{header.lower().replace('-', '_')}",
                            "severity": severity,
                            "title": f"Missing {header} Header",
                            "description": f"{header} header is not set",
                            "impact": "Increased vulnerability to various attacks",
                            "remediation": f"Configure {header} header appropriately"
                        })
                        indicators.append(f"MISSING_{header.upper().replace('-', '_')}")
                
                # Check for server information disclosure
                if "Server" in headers:
                    server_info = headers["Server"]
                    metadata["server"] = server_info
                    
                    # Check for version disclosure
                    if any(char.isdigit() for char in server_info):
                        threats.append({
                            "type": "server_info_disclosure",
                            "severity": "medium",
                            "title": "Server Information Disclosure",
                            "description": f"Server header reveals: {server_info}",
                            "impact": "Attackers can target specific vulnerabilities",
                            "remediation": "Minimize server header information"
                        })
                        indicators.append("SERVER_INFO_DISCLOSURE")
        
        except Exception as e:
            threats.append({
                "type": "headers_error",
                "severity": "medium",
                "title": "Failed to Retrieve Headers",
                "description": f"Error fetching HTTP headers: {str(e)}",
                "remediation": "Check network connectivity and URL"
            })
        
        return {"threats": threats, "indicators": indicators, "metadata": metadata}
    
    async def check_security_headers(self, url: str) -> Dict[str, Any]:
        """Detailed security header analysis"""
        threats = []
        metadata = {}
        
        try:
            async with self.session.get(url) as response:
                headers = dict(response.headers)
                
                # Analyze CSP if present
                if "Content-Security-Policy" in headers:
                    csp = headers["Content-Security-Policy"]
                    metadata["csp"] = csp
                    
                    # Check for unsafe directives
                    if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                        threats.append({
                            "type": "csp_unsafe_directives",
                            "severity": "medium",
                            "title": "CSP Contains Unsafe Directives",
                            "description": "Content Security Policy includes unsafe-inline or unsafe-eval",
                            "impact": "Reduced effectiveness against XSS attacks",
                            "remediation": "Remove unsafe directives from CSP"
                        })
                
                # Analyze HSTS
                if "Strict-Transport-Security" in headers:
                    hsts = headers["Strict-Transport-Security"]
                    metadata["hsts"] = hsts
                    
                    # Check HSTS settings
                    if "max-age=" in hsts:
                        max_age = int(hsts.split("max-age=")[1].split(";")[0])
                        if max_age < 31536000:  # 1 year
                            threats.append({
                                "type": "hsts_short_max_age",
                                "severity": "medium",
                                "title": "HSTS Max-Age Too Short",
                                "description": f"HSTS max-age is {max_age} seconds",
                                "impact": "Users may not be protected after short period",
                                "remediation": "Set max-age to at least 31536000 (1 year)"
                            })
        
        except Exception as e:
            logger.warning(f"Security header check failed: {e}")
        
        return {"threats": threats, "metadata": metadata}
    
    async def check_dns_security(self, domain: str) -> Dict[str, Any]:
        """Check DNS security configurations"""
        threats = []
        metadata = {}
        
        try:
            resolver = dns.resolver.Resolver()
            
            # Check for DNSSEC
            try:
                answer = resolver.resolve(domain, 'DNSKEY')
                metadata["dnssec"] = True
            except:
                metadata["dnssec"] = False
                threats.append({
                    "type": "dnssec_missing",
                    "severity": "medium",
                    "title": "DNSSEC Not Configured",
                    "description": "Domain does not have DNSSEC enabled",
                    "impact": "Vulnerable to DNS spoofing attacks",
                    "remediation": "Enable DNSSEC for domain"
                })
            
            # Check for SPF record
            try:
                answer = resolver.resolve(domain, 'TXT')
                spf_found = any('spf' in str(record).lower() for record in answer)
                metadata["spf"] = spf_found
                
                if not spf_found:
                    threats.append({
                        "type": "spf_missing",
                        "severity": "medium",
                        "title": "SPF Record Missing",
                        "description": "No SPF record found for domain",
                        "impact": "Vulnerable to email spoofing",
                        "remediation": "Add SPF record"
                    })
            except:
                metadata["spf"] = False
            
            # Check for DMARC
            try:
                answer = resolver.resolve(f"_dmarc.{domain}", 'TXT')
                metadata["dmarc"] = True
            except:
                metadata["dmarc"] = False
                threats.append({
                    "type": "dmarc_missing",
                    "severity": "medium",
                    "title": "DMARC Record Missing",
                    "description": "No DMARC record found for domain",
                    "impact": "Reduced email authentication protection",
                    "remediation": "Add DMARC record"
                })
        
        except Exception as e:
            logger.warning(f"DNS security check failed: {e}")
        
        return {"threats": threats, "metadata": metadata}
    
    async def check_server_info(self, url: str) -> Dict[str, Any]:
        """Gather server information"""
        metadata = {}
        
        try:
            # Send request to get server info
            async with self.session.head(url) as response:
                if "Server" in response.headers:
                    metadata["server_software"] = response.headers["Server"]
                
                if "X-Powered-By" in response.headers:
                    metadata["powered_by"] = response.headers["X-Powered-By"]
        
        except Exception as e:
            logger.warning(f"Server info check failed: {e}")
        
        return {"metadata": metadata}
    
    async def check_technology_stack(self, url: str) -> Dict[str, Any]:
        """Detect technology stack"""
        threats = []
        metadata = {"technologies": []}
        
        try:
            async with self.session.get(url) as response:
                html = await response.text()
                headers = dict(response.headers)
                
                # Detect common technologies
                tech_indicators = {
                    "WordPress": ["wp-content", "wp-includes", "wordpress"],
                    "Joomla": ["joomla", "media/jui"],
                    "Drupal": ["drupal", "sites/all"],
                    "React": ["react", "react-dom"],
                    "Vue.js": ["vue", "vue-router"],
                    "Angular": ["angular", "ng-"],
                    "jQuery": ["jquery"],
                    "Bootstrap": ["bootstrap"],
                    "Nginx": ["nginx"],
                    "Apache": ["apache", "httpd"],
                    "CloudFlare": ["cloudflare"],
                    "PHP": ["php", ".php"],
                    "ASP.NET": ["asp.net", "__viewstate"],
                    "Ruby on Rails": ["rails", "ruby"]
                }
                
                detected_tech = []
                for tech, indicators in tech_indicators.items():
                    for indicator in indicators:
                        if indicator.lower() in html.lower() or \
                           any(indicator.lower() in str(h).lower() for h in headers.values()):
                            detected_tech.append(tech)
                            break
                
                metadata["technologies"] = list(set(detected_tech))
                
                # Check for outdated technologies
                outdated_tech = {
                    "PHP 5.x": "high",
                    "jQuery 1.x": "medium",
                    "WordPress < 6.0": "high",
                    "Apache 2.2": "high"
                }
                
                for tech, severity in outdated_tech.items():
                    if any(tech.split()[0].lower() in t.lower() for t in detected_tech):
                        threats.append({
                            "type": "outdated_technology",
                            "severity": severity,
                            "title": f"Outdated {tech}",
                            "description": f"Using potentially outdated version of {tech}",
                            "impact": "Security vulnerabilities in older versions",
                            "remediation": f"Update {tech} to latest version"
                        })
        
        except Exception as e:
            logger.warning(f"Technology stack check failed: {e}")
        
        return {"threats": threats, "metadata": metadata}
    
    async def check_vulnerabilities(self, url: str) -> Dict[str, Any]:
        """Check for common vulnerabilities"""
        threats = []
        
        try:
            # Check for directory listing
            test_urls = [
                f"{url}/admin/",
                f"{url}/backup/",
                f"{url}/uploads/",
                f"{url}/images/",
                f"{url}/css/",
                f"{url}/js/"
            ]
            
            for test_url in test_urls:
                try:
                    async with self.session.get(test_url) as response:
                        if response.status == 200:
                            text = await response.text()
                            # Check if it looks like directory listing
                            if "<title>Index of" in text or \
                               "<h1>Index of" in text or \
                               "Parent Directory" in text:
                                threats.append({
                                    "type": "directory_listing",
                                    "severity": "medium",
                                    "title": "Directory Listing Enabled",
                                    "description": f"Directory listing found at {test_url}",
                                    "impact": "Information disclosure of directory contents",
                                    "remediation": "Disable directory listing in server configuration"
                                })
                                break
                except:
                    continue
            
            # Check for common files
            common_files = [
                "robots.txt",
                "sitemap.xml",
                ".env",
                ".git/config",
                "wp-config.php",
                "config.php",
                "phpinfo.php",
                "test.php"
            ]
            
            for file in common_files:
                try:
                    async with self.session.get(f"{url}/{file}") as response:
                        if response.status == 200:
                            if file in [".env", ".git/config", "wp-config.php", "config.php"]:
                                threats.append({
                                    "type": "sensitive_file_exposed",
                                    "severity": "high",
                                    "title": f"Sensitive File Exposed: {file}",
                                    "description": f"Sensitive file accessible at {url}/{file}",
                                    "impact": "Information disclosure, configuration leaks",
                                    "remediation": "Restrict access to sensitive files"
                                })
                except:
                    continue
        
        except Exception as e:
            logger.warning(f"Vulnerability check failed: {e}")
        
        return {"threats": threats}
    
    def _calculate_risk_score(self, threats: List[Dict]) -> float:
        """Calculate overall risk score based on threats"""
        if not threats:
            return 10.0  # Low risk if no threats
        
        severity_weights = {
            "critical": 100,
            "high": 75,
            "medium": 50,
            "low": 25,
            "info": 10
        }
        
        total_score = 0
        for threat in threats:
            severity = threat.get("severity", "medium")
            total_score += severity_weights.get(severity, 50)
        
        # Normalize to 0-100 scale
        max_possible = len(threats) * 100
        risk_score = (total_score / max_possible) * 100
        
        # Cap at 100
        return min(risk_score, 100.0)
    
    def _get_risk_level(self, risk_score: float) -> RiskLevel:
        """Convert risk score to risk level"""
        if risk_score >= 80:
            return RiskLevel.CRITICAL
        elif risk_score >= 60:
            return RiskLevel.HIGH
        elif risk_score >= 40:
            return RiskLevel.MEDIUM
        elif risk_score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.CLEAN
    
    def _generate_ai_summary(self, threats: List[Dict], domain: str) -> str:
        """Generate AI-style summary of findings"""
        if not threats:
            return f"✅ {domain} shows good security posture with no critical issues detected."
        
        critical_count = sum(1 for t in threats if t.get("severity") == "critical")
        high_count = sum(1 for t in threats if t.get("severity") == "high")
        
        if critical_count > 0:
            return f"⚠️ CRITICAL: {domain} has {critical_count} critical security issues requiring immediate attention."
        elif high_count > 0:
            return f"⚠️ HIGH: {domain} has {high_count} high-risk security issues that should be addressed."
        else:
            return f"ℹ️ {domain} has {len(threats)} security findings that should be reviewed for improvement."