"""
LatticeGuard - Post-Quantum Cryptography Assessment Tool
Copyright (c) 2026 Waqas Khalid Obeidy
"""

"""
External Attack Surface Management (EASM) Scanner

Integrates with:
- Shodan: Internet-wide asset discovery
- Censys: Certificate transparency & host search
- crt.sh: Free certificate transparency lookup
- SSLLabs: Deep TLS configuration analysis
"""

import os
import json
import requests
import socket
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict, field
from datetime import datetime
import concurrent.futures


@dataclass
class DiscoveredAsset:
    """Represents a discovered internet-facing asset"""
    ip: str
    hostname: str
    port: int
    source: str  # shodan, censys, crt.sh
    cipher_suite: Optional[str] = None
    tls_version: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_subject: Optional[str] = None
    certificate_expiry: Optional[str] = None
    key_algorithm: Optional[str] = None
    key_size: Optional[int] = None
    is_pqc_vulnerable: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


class ShodanScanner:
    """
    Shodan integration for internet-wide asset discovery.
    
    Requires SHODAN_API_KEY environment variable.
    Free tier: 100 queries/month
    """
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("SHODAN_API_KEY")
        self.base_url = "https://api.shodan.io"
        
    def is_available(self) -> bool:
        return bool(self.api_key)
    
    def search_organization(self, org: str, limit: int = 100) -> List[DiscoveredAsset]:
        """Search for SSL/TLS endpoints belonging to an organization"""
        if not self.api_key:
            return []
        
        try:
            url = f"{self.base_url}/shodan/host/search"
            params = {
                "key": self.api_key,
                "query": f'org:"{org}" ssl.cert.issuer.cn:*',
                "limit": limit
            }
            
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            assets = []
            for match in data.get("matches", []):
                ssl_info = match.get("ssl", {})
                cert = ssl_info.get("cert", {})
                cipher = ssl_info.get("cipher", {})
                
                asset = DiscoveredAsset(
                    ip=match.get("ip_str", ""),
                    hostname=", ".join(match.get("hostnames", [])) or match.get("ip_str", ""),
                    port=match.get("port", 443),
                    source="shodan",
                    cipher_suite=cipher.get("name"),
                    tls_version=ssl_info.get("version"),
                    certificate_issuer=cert.get("issuer", {}).get("CN"),
                    certificate_subject=cert.get("subject", {}).get("CN"),
                    certificate_expiry=cert.get("expires"),
                    key_algorithm=cert.get("pubkey", {}).get("type"),
                    key_size=cert.get("pubkey", {}).get("bits"),
                    is_pqc_vulnerable=self._is_pqc_vulnerable(cert.get("pubkey", {}).get("type")),
                    metadata={
                        "org": match.get("org"),
                        "asn": match.get("asn"),
                        "country": match.get("location", {}).get("country_name"),
                        "product": match.get("product"),
                        "version": match.get("version")
                    }
                )
                assets.append(asset)
            
            return assets
            
        except Exception as e:
            print(f"Shodan error: {e}")
            return []
    
    def search_domain(self, domain: str, limit: int = 100) -> List[DiscoveredAsset]:
        """
        Search for SSL/TLS endpoints for a specific domain using host search.
        Uses /shodan/host/search which works on free tier.
        """
        if not self.api_key:
            return []
        
        try:
            # Use host search with SSL filter - works on free tier
            url = f"{self.base_url}/shodan/host/search"
            params = {
                "key": self.api_key,
                "query": f'hostname:{domain} ssl',
                "limit": limit
            }
            
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            assets = []
            for match in data.get("matches", []):
                ssl_info = match.get("ssl", {})
                cert = ssl_info.get("cert", {})
                cipher = ssl_info.get("cipher", {})
                hostnames = match.get("hostnames", [])
                
                asset = DiscoveredAsset(
                    ip=match.get("ip_str", ""),
                    hostname=", ".join(hostnames) if hostnames else match.get("ip_str", ""),
                    port=match.get("port", 443),
                    source="shodan",
                    cipher_suite=cipher.get("name"),
                    tls_version=ssl_info.get("version"),
                    certificate_issuer=cert.get("issuer", {}).get("CN"),
                    certificate_subject=cert.get("subject", {}).get("CN"),
                    certificate_expiry=cert.get("expires"),
                    key_algorithm=cert.get("pubkey", {}).get("type"),
                    key_size=cert.get("pubkey", {}).get("bits"),
                    is_pqc_vulnerable=self._is_pqc_vulnerable(cert.get("pubkey", {}).get("type")),
                    metadata={
                        "org": match.get("org"),
                        "asn": match.get("asn"),
                        "country": match.get("location", {}).get("country_name"),
                        "product": match.get("product"),
                        "version": match.get("version")
                    }
                )
                assets.append(asset)
            
            return assets
            
        except Exception as e:
            print(f"Shodan search error: {e}")
            return []

    def search_ip(self, ip: str) -> Optional[DiscoveredAsset]:
        """
        Look up a single IP address (FREE - no credits required).
        This endpoint works on all Shodan plans including free/oss tier.
        """
        if not self.api_key:
            return None
        
        try:
            url = f"{self.base_url}/shodan/host/{ip}"
            params = {"key": self.api_key}
            
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            # Get SSL info from first HTTPS port
            ssl_info = {}
            cipher = {}
            cert = {}
            port = 443
            
            for item in data.get("data", []):
                if "ssl" in item:
                    ssl_info = item.get("ssl", {})
                    cert = ssl_info.get("cert", {})
                    cipher = ssl_info.get("cipher", {})
                    port = item.get("port", 443)
                    break
            
            return DiscoveredAsset(
                ip=data.get("ip_str", ip),
                hostname=", ".join(data.get("hostnames", [])) or ip,
                port=port,
                source="shodan",
                cipher_suite=cipher.get("name"),
                tls_version=ssl_info.get("version"),
                certificate_issuer=cert.get("issuer", {}).get("CN"),
                certificate_subject=cert.get("subject", {}).get("CN"),
                certificate_expiry=cert.get("expires"),
                key_algorithm=cert.get("pubkey", {}).get("type"),
                key_size=cert.get("pubkey", {}).get("bits"),
                is_pqc_vulnerable=self._is_pqc_vulnerable(cert.get("pubkey", {}).get("type")),
                metadata={
                    "org": data.get("org"),
                    "asn": data.get("asn"),
                    "country": data.get("country_name"),
                    "ports": data.get("ports", [])
                }
            )
            
        except Exception as e:
            print(f"Shodan IP lookup error: {e}")
            return None
    
    def search_domain_via_dns(self, domain: str) -> List[DiscoveredAsset]:
        """
        Search domain by resolving DNS and looking up the IP (FREE tier compatible).
        """
        if not self.api_key:
            return []
        
        assets = []
        
        try:
            # Resolve domain to IP
            ip = socket.gethostbyname(domain)
            print(f"   Resolved {domain} → {ip}")
            
            # Look up the IP (free)
            asset = self.search_ip(ip)
            if asset:
                # Update hostname to domain
                asset.hostname = domain
                assets.append(asset)
                
        except socket.gaierror:
            print(f"   Could not resolve {domain}")
        except Exception as e:
            print(f"   DNS lookup error: {e}")
        
        return assets
    
    def _is_pqc_vulnerable(self, key_type: Optional[str]) -> bool:

        if not key_type:
            return True
        key_upper = key_type.upper()
        pqc_safe = ["KYBER", "DILITHIUM", "ML-KEM", "ML-DSA", "SPHINCS"]
        return not any(safe in key_upper for safe in pqc_safe)


class CensysScanner:
    """
    Censys integration for certificate transparency and host discovery.
    
    Supports both:
    - Single token format: CENSYS_API_TOKEN (e.g., censys_XXX_YYY)
    - Separate credentials: CENSYS_API_ID + CENSYS_API_SECRET
    
    Free tier: 250 queries/month
    """
    
    def __init__(self, api_token: Optional[str] = None, api_id: Optional[str] = None, api_secret: Optional[str] = None):
        # Support single token format: censys_XXX_YYY (split into ID and Secret)
        token = api_token or os.environ.get("CENSYS_API_TOKEN")
        
        if token and token.startswith("censys_"):
            # Parse single token: censys_ID_SECRET
            parts = token.split("_", 2)  # Split into max 3 parts
            if len(parts) >= 3:
                self.api_id = f"{parts[0]}_{parts[1]}"  # censys_ID
                self.api_secret = parts[2]  # SECRET
            else:
                self.api_id = token
                self.api_secret = ""
        else:
            self.api_id = api_id or os.environ.get("CENSYS_API_ID")
            self.api_secret = api_secret or os.environ.get("CENSYS_API_SECRET")
        
        self.base_url = "https://search.censys.io/api/v2"
        
    def is_available(self) -> bool:
        return bool(self.api_id and self.api_secret)

    
    def search_hosts(self, query: str, limit: int = 100) -> List[DiscoveredAsset]:
        """Search for hosts matching a query"""
        if not self.is_available():
            return []
        
        try:
            url = f"{self.base_url}/hosts/search"
            params = {
                "q": query,
                "per_page": min(limit, 100)
            }
            
            response = requests.get(
                url, 
                params=params, 
                auth=(self.api_id, self.api_secret),
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            
            assets = []
            for hit in data.get("result", {}).get("hits", []):
                services = hit.get("services", [])
                for svc in services:
                    if svc.get("service_name") in ["HTTP", "HTTPS"]:
                        tls = svc.get("tls", {})
                        cert = tls.get("certificates", {}).get("leaf", {}).get("parsed", {})
                        
                        asset = DiscoveredAsset(
                            ip=hit.get("ip", ""),
                            hostname=hit.get("name", hit.get("ip", "")),
                            port=svc.get("port", 443),
                            source="censys",
                            tls_version=tls.get("version_selected"),
                            cipher_suite=tls.get("cipher_selected"),
                            certificate_issuer=cert.get("issuer_dn"),
                            certificate_subject=cert.get("subject_dn"),
                            key_algorithm=cert.get("subject_key_info", {}).get("key_algorithm", {}).get("name"),
                            key_size=cert.get("subject_key_info", {}).get("key_size"),
                            is_pqc_vulnerable=True,
                            metadata={
                                "autonomous_system": hit.get("autonomous_system", {}),
                                "location": hit.get("location", {})
                            }
                        )
                        assets.append(asset)
            
            return assets
            
        except Exception as e:
            print(f"Censys error: {e}")
            return []
    
    def search_certificates(self, domain: str, limit: int = 100) -> List[DiscoveredAsset]:
        """Search certificate transparency logs for a domain"""
        if not self.is_available():
            return []
        
        try:
            url = f"{self.base_url}/certificates/search"
            params = {
                "q": f"names: {domain}",
                "per_page": min(limit, 100)
            }
            
            response = requests.get(
                url, 
                params=params, 
                auth=(self.api_id, self.api_secret),
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            
            assets = []
            seen_names = set()
            
            for hit in data.get("result", {}).get("hits", []):
                names = hit.get("names", [])
                for name in names:
                    if name not in seen_names and domain in name:
                        seen_names.add(name)
                        asset = DiscoveredAsset(
                            ip="",
                            hostname=name,
                            port=443,
                            source="censys-ct",
                            certificate_issuer=hit.get("issuer_dn"),
                            certificate_subject=hit.get("subject_dn"),
                            is_pqc_vulnerable=True
                        )
                        assets.append(asset)
            
            return assets
            
        except Exception as e:
            print(f"Censys CT error: {e}")
            return []


class CrtShScanner:
    """
    crt.sh integration for certificate transparency lookup.
    
    FREE - No API key required!
    """
    
    def __init__(self):
        self.base_url = "https://crt.sh"
    
    def is_available(self) -> bool:
        return True  # Always available, no API key needed
    
    def search_domain(self, domain: str, include_expired: bool = False) -> List[DiscoveredAsset]:
        """Search certificate transparency logs for subdomains"""
        try:
            url = f"{self.base_url}/?q=%.{domain}&output=json"
            if not include_expired:
                url += "&exclude=expired"
            
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            # Handle empty response
            if not response.text.strip():
                return []
            
            data = response.json()
            
            assets = []
            seen_names = set()
            
            for cert in data:
                name = cert.get("name_value", "")
                # Handle wildcard and multi-name certs
                names = name.replace("*.", "").split("\n")
                
                for n in names:
                    n = n.strip().lower()
                    if n and n not in seen_names and domain in n:
                        seen_names.add(n)
                        
                        asset = DiscoveredAsset(
                            ip="",
                            hostname=n,
                            port=443,
                            source="crt.sh",
                            certificate_issuer=cert.get("issuer_name"),
                            certificate_expiry=cert.get("not_after"),
                            is_pqc_vulnerable=True,
                            metadata={
                                "cert_id": cert.get("id"),
                                "entry_timestamp": cert.get("entry_timestamp"),
                                "not_before": cert.get("not_before"),
                                "not_after": cert.get("not_after")
                            }
                        )
                        assets.append(asset)
            
            return assets
            
        except Exception as e:
            print(f"crt.sh error: {e}")
            return []


class SSLLabsScanner:
    """
    SSLLabs integration for deep TLS configuration analysis.
    
    FREE - No API key required!
    Rate limited: 1 scan per host per hour (uses cache)
    """
    
    def __init__(self):
        self.base_url = "https://api.ssllabs.com/api/v3"
    
    def is_available(self) -> bool:
        return True
    
    def analyze(self, hostname: str, from_cache: bool = True) -> Dict[str, Any]:
        """
        Analyze a host's SSL/TLS configuration.
        
        Args:
            hostname: Target hostname
            from_cache: Use cached results if available (recommended)
        """
        try:
            # Start analysis or get cached results
            url = f"{self.base_url}/analyze"
            params = {
                "host": hostname,
                "fromCache": "on" if from_cache else "off",
                "all": "done"  # Wait for full results
            }
            
            response = requests.get(url, params=params, timeout=60)
            response.raise_for_status()
            data = response.json()
            
            # Check status
            status = data.get("status")
            if status == "ERROR":
                return {"error": data.get("statusMessage")}
            
            if status == "IN_PROGRESS":
                return {"status": "in_progress", "message": "Analysis in progress, try again later"}
            
            # Parse results
            result = {
                "host": data.get("host"),
                "grade": None,
                "endpoints": []
            }
            
            for endpoint in data.get("endpoints", []):
                grade = endpoint.get("grade") or endpoint.get("gradeTrustIgnored")
                if grade and (result["grade"] is None or grade < result["grade"]):
                    result["grade"] = grade
                
                details = endpoint.get("details", {})
                protocols = details.get("protocols", [])
                suites = details.get("suites", {})
                cert = details.get("cert", {})
                
                ep = {
                    "ip": endpoint.get("ipAddress"),
                    "grade": grade,
                    "protocols": [f"{p.get('name')} {p.get('version')}" for p in protocols],
                    "cipher_suites": [],
                    "certificate": {
                        "subject": cert.get("subject"),
                        "issuer": cert.get("issuerSubject"),
                        "key_algorithm": cert.get("keyAlg"),
                        "key_size": cert.get("keySize"),
                        "signature_algorithm": cert.get("sigAlg"),
                        "not_after": cert.get("notAfter")
                    },
                    "vulnerabilities": {
                        "poodle": details.get("poodle"),
                        "heartbleed": details.get("heartbleed"),
                        "freak": details.get("freak"),
                        "logjam": details.get("logjam"),
                        "robot": details.get("robot"),
                        "zombie_poodle": details.get("zombiePoodle"),
                        "golden_doodle": details.get("goldenDoodle")
                    },
                    "forward_secrecy": details.get("forwardSecrecy"),
                    "supports_tls13": any(p.get("version") == "1.3" for p in protocols if p.get("name") == "TLS")
                }
                
                # Extract cipher suites
                for suite_list in suites.get("list", []):
                    ep["cipher_suites"].append(suite_list.get("name"))
                
                result["endpoints"].append(ep)
            
            return result
            
        except Exception as e:
            return {"error": str(e)}
    
    def get_grade_info(self, grade: str) -> Dict[str, Any]:
        """Get information about an SSL grade"""
        grades = {
            "A+": {"severity": "info", "description": "Excellent - Exceptional security"},
            "A": {"severity": "low", "description": "Good - Strong security configuration"},
            "A-": {"severity": "low", "description": "Good - Minor issues"},
            "B": {"severity": "medium", "description": "Fair - Some weaknesses present"},
            "C": {"severity": "medium", "description": "Weak - Significant issues"},
            "D": {"severity": "high", "description": "Poor - Serious vulnerabilities"},
            "E": {"severity": "high", "description": "Very Poor - Critical issues"},
            "F": {"severity": "critical", "description": "Fail - Severe vulnerabilities"},
            "T": {"severity": "critical", "description": "Trust issues - Certificate problems"}
        }
        return grades.get(grade, {"severity": "unknown", "description": "Unknown grade"})


class EASMManager:
    """
    Unified External Attack Surface Management interface.
    
    Coordinates all EASM scanners and provides batch scanning.
    """
    
    def __init__(self):
        self.shodan = ShodanScanner()
        self.censys = CensysScanner()
        self.crtsh = CrtShScanner()
        self.ssllabs = SSLLabsScanner()
    
    def get_available_sources(self) -> List[str]:
        """Return list of available data sources"""
        sources = []
        if self.shodan.is_available():
            sources.append("shodan")
        if self.censys.is_available():
            sources.append("censys")
        if self.crtsh.is_available():
            sources.append("crt.sh")
        if self.ssllabs.is_available():
            sources.append("ssllabs")
        return sources
    
    def discover_domain(self, domain: str, sources: Optional[List[str]] = None) -> List[DiscoveredAsset]:
        """
        Discover all assets for a domain using available sources.
        
        Args:
            domain: Target domain (e.g., "example.com")
            sources: List of sources to use, or None for all available
        """
        all_assets = []
        available = self.get_available_sources()
        sources = sources or available
        
        for source in sources:
            if source not in available:
                continue
                
            if source == "shodan" and self.shodan.is_available():
                # Try search first, fall back to DNS+IP lookup (free tier)
                assets = self.shodan.search_domain(domain)
                if not assets:
                    # Fallback: resolve DNS → lookup IP (works on free/oss tier)
                    assets = self.shodan.search_domain_via_dns(domain)
                all_assets.extend(assets)
                
            elif source == "censys" and self.censys.is_available():
                assets = self.censys.search_certificates(domain)
                all_assets.extend(assets)
                
            elif source == "crt.sh":
                assets = self.crtsh.search_domain(domain)
                all_assets.extend(assets)
        
        # Deduplicate by hostname
        seen = set()
        unique = []
        for asset in all_assets:
            key = f"{asset.hostname}:{asset.port}"
            if key not in seen:
                seen.add(key)
                unique.append(asset)
        
        return unique
    
    def discover_organization(self, org: str) -> List[DiscoveredAsset]:
        """Discover all assets for an organization (requires Shodan)"""
        if not self.shodan.is_available():
            print("Warning: Shodan API key required for organization search")
            return []
        
        return self.shodan.search_organization(org)
    
    def deep_analyze(self, hostname: str) -> Dict[str, Any]:
        """Run deep SSL/TLS analysis using SSLLabs"""
        return self.ssllabs.analyze(hostname)
    
    def batch_probe(
        self, 
        assets: List[DiscoveredAsset], 
        max_workers: int = 5,
        callback=None
    ) -> List[Dict[str, Any]]:
        """
        Probe multiple assets for PQC readiness in parallel.
        
        Args:
            assets: List of discovered assets
            max_workers: Number of concurrent probes
            callback: Optional function to call after each probe
        """
        from scanner.network import NetworkScanner
        
        results = []
        
        def probe_asset(asset: DiscoveredAsset) -> Dict[str, Any]:
            try:
                # Resolve hostname if IP not available
                hostname = asset.hostname.split(",")[0].strip()
                if not asset.ip:
                    try:
                        asset.ip = socket.gethostbyname(hostname)
                    except:
                        pass
                
                scanner = NetworkScanner(hostname, asset.port)
                findings = scanner.scan()
                score = scanner.calculate_resilience_score()
                
                return {
                    "hostname": hostname,
                    "ip": asset.ip,
                    "port": asset.port,
                    "source": asset.source,
                    "quantum_resilience_score": score,
                    "pqc_ready": score >= 70,
                    "findings": [
                        {
                            "name": f.name,
                            "algorithm": f.algorithm,
                            "is_pqc_vulnerable": f.is_pqc_vulnerable

                        }
                        for f in findings
                    ]
                }
            except Exception as e:
                return {
                    "hostname": asset.hostname,
                    "ip": asset.ip,
                    "port": asset.port,
                    "source": asset.source,
                    "error": str(e)
                }
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(probe_asset, asset): asset for asset in assets}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                results.append(result)
                if callback:
                    callback(result)
        
        return results
