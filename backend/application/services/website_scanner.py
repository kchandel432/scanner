import aiohttp
import asyncio
import ssl
from urllib.parse import urlparse
import whois
import dns.resolver
from typing import Dict, List, Any, Optional
import numpy as np
from datetime import datetime, timedelta

class AdvancedWebsiteScanner:
    def __init__(self):
        self.threat_intel = self._load_threat_intelligence()
    
    async def scan_website(self, url: str) -> Dict[str, Any]:
        """Comprehensive website security scan"""
        results = {
            "url": url,
            "domain_info": {},
            "security_headers": {},
            "vulnerabilities": [],
            "malware_detected": False,
            "phishing_risk": 0.0,
            "ssl_info": {},
            "threat_level": "clean",
            "scan_timestamp": datetime.utcnow().isoformat()
        }
        
        try:
            # Parse URL
            parsed_url = urlparse(url)
            
            # Domain analysis
            domain_info = await self._analyze_domain(parsed_url.netloc)
            results["domain_info"] = domain_info
            
            # SSL/TLS analysis
            ssl_info = await self._analyze_ssl(url)
            results["ssl_info"] = ssl_info
            
            # Security headers check
            headers = await self._check_security_headers(url)
            results["security_headers"] = headers
            
            # Content analysis
            content_analysis = await self._analyze_content(url)
            results.update(content_analysis)
            
            # Malware scanning
            malware_detected = await self._scan_for_malware(url)
            results["malware_detected"] = malware_detected
            
            # Phishing detection
            phishing_risk = await self._detect_phishing(url, domain_info)
            results["phishing_risk"] = phishing_risk
            
            # Vulnerability scanning
            vulnerabilities = await self._scan_vulnerabilities(url)
            results["vulnerabilities"] = vulnerabilities
            
            # Threat intelligence lookup
            threat_data = self._check_threat_intelligence(url)
            results["threat_intel"] = threat_data
            
            # Calculate overall threat level
            threat_level = self._calculate_website_threat_level(results)
            results["threat_level"] = threat_level
            
        except Exception as e:
            results["error"] = str(e)
            results["threat_level"] = "unknown"
        
        return results
    
    async def _analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze domain registration and DNS"""
        info = {}
        
        try:
            # WHOIS lookup
            w = whois.whois(domain)
            info["whois"] = {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers
            }
            
            # DNS analysis
            dns_info = await self._analyze_dns(domain)
            info["dns"] = dns_info
            
            # Check if domain is newly registered
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                days_old = (datetime.now() - creation_date).days
                info["domain_age_days"] = days_old
                info["is_new_domain"] = days_old < 30
            
        except Exception as e:
            info["error"] = str(e)
        
        return info
    
    async def _analyze_dns(self, domain: str) -> Dict[str, Any]:
        """Analyze DNS records"""
        dns_info = {}
        
        try:
            resolver = dns.resolver.Resolver()
            
            # A records
            try:
                a_records = resolver.resolve(domain, 'A')
                dns_info["a_records"] = [str(r) for r in a_records]
            except:
                dns_info["a_records"] = []
            
            # MX records
            try:
                mx_records = resolver.resolve(domain, 'MX')
                dns_info["mx_records"] = [str(r) for r in mx_records]
            except:
                dns_info["mx_records"] = []
            
            # TXT records
            try:
                txt_records = resolver.resolve(domain, 'TXT')
                dns_info["txt_records"] = [str(r) for r in txt_records]
            except:
                dns_info["txt_records"] = []
            
            # Check for suspicious DNS patterns
            suspicious_patterns = []
            for record in dns_info.get("a_records", []):
                # Check for known malicious IP ranges
                if self._is_suspicious_ip(record):
                    suspicious_patterns.append(f"Suspicious IP: {record}")
            
            dns_info["suspicious_patterns"] = suspicious_patterns
            
        except Exception as e:
            dns_info["error"] = str(e)
        
        return dns_info
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP is in known malicious ranges"""
        suspicious_prefixes = [
            "5.188.", "45.9.", "91.215.", "185.163.", 
            "192.42.116.", "198.51.100.", "203.0.113."
        ]
        
        return any(ip.startswith(prefix) for prefix in suspicious_prefixes)
    
    async def _analyze_ssl(self, url: str) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration"""
        ssl_info = {}
        
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc
            
            # Remove port if present
            if ":" in hostname:
                hostname = hostname.split(":")[0]
            
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        "version": ssock.version(),
                        "cipher": ssock.cipher(),
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "valid_from": cert.get('notBefore'),
                        "valid_until": cert.get('notAfter'),
                        "has_expired": self._is_cert_expired(cert),
                        "is_self_signed": self._is_self_signed(cert)
                    }
            
        except Exception as e:
            ssl_info["error"] = str(e)
            ssl_info["has_ssl"] = False
        
        return ssl_info
    
    def _is_cert_expired(self, cert) -> bool:
        """Check if SSL certificate is expired"""
        not_after = cert.get('notAfter')
        if not_after:
            expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            return expiry_date < datetime.utcnow()
        return True
    
    def _is_self_signed(self, cert) -> bool:
        """Check if certificate is self-signed"""
        issuer = cert.get('issuer', [])
        subject = cert.get('subject', [])
        
        issuer_dict = dict(x[0] for x in issuer)
        subject_dict = dict(x[0] for x in subject)
        
        return issuer_dict == subject_dict
    
    async def _check_security_headers(self, url: str) -> Dict[str, Any]:
        """Check security headers"""
        headers = {}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=False, timeout=10) as response:
                    security_headers = {
                        "Content-Security-Policy": response.headers.get("Content-Security-Policy"),
                        "X-Frame-Options": response.headers.get("X-Frame-Options"),
                        "X-Content-Type-Options": response.headers.get("X-Content-Type-Options"),
                        "Strict-Transport-Security": response.headers.get("Strict-Transport-Security"),
                        "Referrer-Policy": response.headers.get("Referrer-Policy"),
                        "Permissions-Policy": response.headers.get("Permissions-Policy")
                    }
                    
                    # Evaluate security headers
                    missing_headers = []
                    for header, value in security_headers.items():
                        if not value:
                            missing_headers.append(header)
                    
                    headers = {
                        "present": security_headers,
                        "missing": missing_headers,
                        "score": (len(security_headers) - len(missing_headers)) / len(security_headers) * 100
                    }
                    
        except Exception as e:
            headers["error"] = str(e)
        
        return headers
    
    async def _analyze_content(self, url: str) -> Dict[str, Any]:
        """Analyze website content for threats"""
        analysis = {
            "malicious_scripts": [],
            "suspicious_iframes": [],
            "blacklisted_urls": [],
            "content_risk_score": 0.0
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=False, timeout=15) as response:
                    html = await response.text()
                    
                    # Check for malicious scripts
                    malicious_patterns = [
                        r'eval\s*\(', r'document\.write', r'fromCharCode',
                        r'String\.fromCharCode', r'setTimeout', r'setInterval',
                        r'<script[^>]*src=["\'][^"\']*\.js["\']'
                    ]
                    
                    for pattern in malicious_patterns:
                        if re.search(pattern, html, re.IGNORECASE):
                            analysis["malicious_scripts"].append(pattern)
                    
                    # Check for suspicious iframes
                    iframe_pattern = r'<iframe[^>]*src=["\']([^"\']+)["\'][^>]*>'
                    iframes = re.findall(iframe_pattern, html, re.IGNORECASE)
                    
                    for iframe in iframes:
                        if self._is_suspicious_url(iframe):
                            analysis["suspicious_iframes"].append(iframe)
                    
                    # Calculate risk score
                    risk_score = 0.0
                    risk_score += len(analysis["malicious_scripts"]) * 0.2
                    risk_score += len(analysis["suspicious_iframes"]) * 0.3
                    analysis["content_risk_score"] = min(risk_score, 1.0)
                    
        except Exception as e:
            analysis["error"] = str(e)
        
        return analysis
    
    def _is_suspicious_url(self, url: str) -> bool:
        """Check if URL is suspicious"""
        suspicious_domains = [
            "freehosting", "000webhost", "infinityfree",
            "byethost", "x10hosting", "awardspace"
        ]
        
        return any(domain in url.lower() for domain in suspicious_domains)
    
    async def _scan_for_malware(self, url: str) -> bool:
        """Scan website for malware"""
        try:
            # Check against Google Safe Browsing
            async with aiohttp.ClientSession() as session:
                api_key = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"
                safe_browsing_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
                
                payload = {
                    "client": {
                        "clientId": "blacklotus-scanner",
                        "clientVersion": "2.0"
                    },
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}]
                    }
                }
                
                async with session.post(safe_browsing_url, json=payload) as response:
                    if response.status == 200:
                        data = await response.json()
                        return "matches" in data and len(data["matches"]) > 0
            
        except Exception:
            pass
        
        return False
    
    async def _detect_phishing(self, url: str, domain_info: Dict) -> float:
        """Detect phishing attempts"""
        phishing_score = 0.0
        
        # Check domain age
        if domain_info.get("is_new_domain"):
            phishing_score += 0.3
        
        # Check for suspicious characters
        suspicious_chars = ['-', '_', '.', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
        url_chars = list(url.lower())
        
        # Count suspicious characters
        sus_char_count = sum(1 for char in url_chars if char in suspicious_chars)
        if sus_char_count / len(url_chars) > 0.3:
            phishing_score += 0.2
        
        # Check for brand names in suspicious ways
        brands = ['paypal', 'facebook', 'google', 'microsoft', 'apple', 'amazon']
        for brand in brands:
            if brand in url.lower() and brand not in domain_info.get("domain", ""):
                phishing_score += 0.3
        
        # Check for HTTPS
        if not url.startswith("https://"):
            phishing_score += 0.2
        
        return min(phishing_score, 1.0)
    
    async def _scan_vulnerabilities(self, url: str) -> List[Dict[str, Any]]:
        """Scan for common vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check for SQL injection vulnerability
            sql_payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1"]
            
            for payload in sql_payloads:
                test_url = f"{url}?id={payload}"
                async with aiohttp.ClientSession() as session:
                    async with session.get(test_url, ssl=False, timeout=5) as response:
                        content = await response.text()
                        
                        # Check for SQL error messages
                        sql_errors = [
                            "SQL syntax", "MySQL", "PostgreSQL", "ORA-",
                            "Microsoft OLE DB", "ODBC Driver", "SQLite"
                        ]
                        
                        for error in sql_errors:
                            if error.lower() in content.lower():
                                vulnerabilities.append({
                                    "type": "SQL Injection",
                                    "severity": "high",
                                    "description": f"Possible SQL injection vulnerability detected with payload: {payload}",
                                    "url": test_url
                                })
                                break
            
            # Check for XSS vulnerability
            xss_payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "\"><script>alert('XSS')</script>"
            ]
            
            for payload in xss_payloads:
                test_url = f"{url}?search={payload}"
                async with aiohttp.ClientSession() as session:
                    async with session.get(test_url, ssl=False, timeout=5) as response:
                        content = await response.text()
                        
                        if payload in content:
                            vulnerabilities.append({
                                "type": "Cross-Site Scripting (XSS)",
                                "severity": "medium",
                                "description": f"Possible XSS vulnerability detected with payload: {payload}",
                                "url": test_url
                            })
        
        except Exception as e:
            pass
        
        return vulnerabilities
    
    def _check_threat_intelligence(self, url: str) -> Dict[str, Any]:
        """Check URL against threat intelligence feeds"""
        threat_data = {
            "in_blacklists": False,
            "reputation_score": 100,
            "threat_types": []
        }
        
        # Check against local threat database
        for blacklist in self.threat_intel:
            if url in blacklist:
                threat_data["in_blacklists"] = True
                threat_data["reputation_score"] -= 50
                threat_data["threat_types"].append(blacklist[url])
        
        return threat_data
    
    def _calculate_website_threat_level(self, results: Dict) -> str:
        """Calculate overall website threat level"""
        threat_score = 0.0
        
        # Malware detection
        if results.get("malware_detected"):
            threat_score += 0.4
        
        # Phishing risk
        threat_score += results.get("phishing_risk", 0.0) * 0.3
        
        # SSL issues
        ssl_info = results.get("ssl_info", {})
        if ssl_info.get("has_expired") or ssl_info.get("is_self_signed"):
            threat_score += 0.2
        
        # Missing security headers
        headers = results.get("security_headers", {})
        if headers.get("score", 100) < 50:
            threat_score += 0.1
        
        # Vulnerabilities
        vulnerabilities = results.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            if vuln.get("severity") == "high":
                threat_score += 0.2
            elif vuln.get("severity") == "medium":
                threat_score += 0.1
        
        # Content risk
        threat_score += results.get("content_risk_score", 0.0) * 0.2
        
        # Threat intelligence
        if results.get("threat_intel", {}).get("in_blacklists"):
            threat_score += 0.3
        
        # Determine threat level
        threat_score = min(threat_score, 1.0)
        
        if threat_score >= 0.7:
            return "critical"
        elif threat_score >= 0.5:
            return "high"
        elif threat_score >= 0.3:
            return "medium"
        elif threat_score >= 0.1:
            return "low"
        else:
            return "clean"
    
    def _load_threat_intelligence(self):
        """Load threat intelligence data"""
        # In production, this would load from external feeds
        return [
            {"malicious-domain.com": "malware_distribution"},
            {"phishing-site.net": "phishing"},
            {"spam-host.org": "spam"}
        ]
