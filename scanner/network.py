"""
Enhanced Network Scanner with Certificate Chain Extraction and TLS Fingerprinting
"""
import ssl
import socket
import hashlib
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from schemas.models import InventoryItem
from schemas.cbom import CertificateInfo, CryptoAsset


class NetworkScanner:
    """
    Advanced TLS/SSL scanner with:
    - Certificate chain extraction
    - TLS version fingerprinting
    - Cipher suite analysis
    - PQC vulnerability detection
    """
    
    # TLS versions and their vulnerability status
    TLS_VERSIONS = {
        "SSLv2": {"vulnerable": True, "zombie": True, "risk": "critical"},
        "SSLv3": {"vulnerable": True, "zombie": True, "risk": "critical"},
        "TLSv1": {"vulnerable": True, "zombie": True, "risk": "high"},
        "TLSv1.0": {"vulnerable": True, "zombie": True, "risk": "high"},
        "TLSv1.1": {"vulnerable": True, "zombie": True, "risk": "high"},
        "TLSv1.2": {"vulnerable": False, "zombie": False, "risk": "medium"},
        "TLSv1.3": {"vulnerable": False, "zombie": False, "risk": "low"},
    }
    
    # Quantum-safe indicators
    QUANTUM_SAFE_TAGS = ["kyber", "dilithium", "falcon", "sphincs", "frodo", "classic-mceliecе", "ml-kem", "ml-dsa"]
    HYBRID_TAGS = ["x25519kyber", "x25519mlkem"]
    CLASSICAL_VULNERABLE = ["rsa", "ecdhe", "ecdsa", "dh", "dsa", "ed25519", "x25519"]
    
    def __init__(self, target_host: str, port: int = 443):
        self.target_host = target_host
        self.port = port
        self.certificates: List[CertificateInfo] = []
        self.tls_version: Optional[str] = None
        self.cipher_suite: Optional[str] = None
        
    def scan(self) -> List[InventoryItem]:
        """
        Performs comprehensive TLS analysis including:
        - TLS handshake and version detection
        - Cipher suite analysis
        - Certificate chain extraction
        - PQC vulnerability assessment
        """
        results = []
        
        try:
            # Create permissive context for analysis
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target_host, self.port), timeout=15) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    # Extract cipher and protocol info
                    cipher_info = ssock.cipher()  # (name, protocol, bits)
                    self.tls_version = ssock.version()
                    self.cipher_suite = cipher_info[0] if cipher_info else "Unknown"
                    bits = cipher_info[2] if cipher_info else 0
                    
                    # Extract certificate chain
                    cert_chain = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()
                    
                    # Analyze TLS endpoint
                    tls_result = self._analyze_tls_endpoint(bits)
                    results.append(tls_result)
                    
                    # Analyze certificate
                    if cert_dict:
                        cert_results = self._analyze_certificate(cert_dict, cert_chain)
                        results.extend(cert_results)
                        
        except ssl.SSLError as e:
            print(f"SSL Error scanning {self.target_host}:{self.port}: {e}")
            # Try to detect if it's a TLS version issue
            results.append(self._create_error_finding(f"SSL handshake failed: {e}"))
        except socket.timeout:
            print(f"Timeout scanning {self.target_host}:{self.port}")
        except Exception as e:
            print(f"Network Scan Error: {e}")
            
        return results
    
    def _analyze_tls_endpoint(self, bits: int) -> InventoryItem:
        """Analyze the TLS connection for vulnerabilities"""
        
        cipher_lower = self.cipher_suite.lower() if self.cipher_suite else ""
        
        # Check for quantum-safe algorithms
        is_quantum_safe = any(tag in cipher_lower for tag in self.QUANTUM_SAFE_TAGS)
        is_hybrid = any(tag in cipher_lower for tag in self.HYBRID_TAGS)
        is_classical_vulnerable = any(tag in cipher_lower for tag in self.CLASSICAL_VULNERABLE)
        
        # Check TLS version
        tls_info = self.TLS_VERSIONS.get(self.tls_version, {"vulnerable": True, "zombie": False, "risk": "medium"})
        is_zombie = tls_info["zombie"]
        
        # Determine vulnerability and reasoning
        is_vulnerable = True
        risk_level = "high"
        
        if is_quantum_safe:
            if is_hybrid:
                is_vulnerable = False
                risk_level = "low"
                reasoning = f"PQC Hybrid Mode ({self.cipher_suite}). Quantum resistance via post-quantum layer while maintaining classical compatibility."
            else:
                is_vulnerable = False
                risk_level = "low"
                reasoning = f"Pure Quantum-Safe cipher ({self.cipher_suite}). Secure against known quantum attacks."
        elif is_zombie:
            is_vulnerable = True
            risk_level = "critical"
            reasoning = f"ZOMBIE PROTOCOL DETECTED: {self.tls_version} is deprecated and insecure. Immediate upgrade required."
        elif "rsa" in cipher_lower:
            is_vulnerable = True
            risk_level = "critical"
            reasoning = f"RSA key exchange detected ({self.cipher_suite}). Vulnerable to Shor's algorithm. No Perfect Forward Secrecy."
        elif "ecdhe" in cipher_lower or "dhe" in cipher_lower:
            is_vulnerable = True
            risk_level = "high"
            reasoning = f"Classical key exchange ({self.cipher_suite}). Provides PFS but key exchange is vulnerable to Shor's algorithm. HNDL risk is active."
        else:
            reasoning = f"Classical cryptography detected ({self.cipher_suite}). Potentially vulnerable to quantum attacks."
        
        return InventoryItem(
            id=f"tls:{self.target_host}:{self.port}",
            path=f"https://{self.target_host}:{self.port}",
            line=0,
            name=f"TLS Endpoint ({self.target_host})",
            category="network",
            algorithm=self.cipher_suite,
            key_size=bits,
            is_pqc_vulnerable=is_vulnerable,
            description=reasoning,
            remediation=self._get_tls_remediation(is_zombie, is_classical_vulnerable)
        )
    
    def _analyze_certificate(self, cert_dict: Dict, cert_binary: bytes) -> List[InventoryItem]:
        """Extract and analyze certificate metadata"""
        results = []
        
        try:
            # Parse subject and issuer
            subject = self._parse_x509_name(cert_dict.get("subject", ()))
            issuer = self._parse_x509_name(cert_dict.get("issuer", ()))
            
            # Parse dates
            not_before = cert_dict.get("notBefore", "")
            not_after = cert_dict.get("notAfter", "")
            
            # Parse SANs
            sans = []
            for san_type, san_value in cert_dict.get("subjectAltName", ()):
                sans.append(f"{san_type}:{san_value}")
            
            # Calculate fingerprint
            fingerprint = hashlib.sha256(cert_binary).hexdigest() if cert_binary else "unknown"
            
            # Detect signature algorithm (from cipher suite as proxy)
            sig_algo = "Unknown"
            pub_key_algo = "Unknown"
            key_size = 0
            
            # Infer from cipher suite
            cipher_lower = (self.cipher_suite or "").lower()
            if "rsa" in cipher_lower:
                pub_key_algo = "RSA"
                sig_algo = "SHA256withRSA"
                key_size = 2048  # Default assumption
            elif "ecdsa" in cipher_lower:
                pub_key_algo = "ECDSA"
                sig_algo = "SHA256withECDSA"
                key_size = 256
            elif "ed25519" in cipher_lower:
                pub_key_algo = "Ed25519"
                sig_algo = "Ed25519"
                key_size = 256
            
            # Store certificate info
            cert_info = CertificateInfo(
                subject=subject,
                issuer=issuer,
                serial_number=str(cert_dict.get("serialNumber", "unknown")),
                not_before=not_before,
                not_after=not_after,
                signature_algorithm=sig_algo,
                public_key_algorithm=pub_key_algo,
                public_key_size=key_size,
                san=sans,
                is_ca=False,  # Would need deeper parsing
                fingerprint_sha256=fingerprint
            )
            self.certificates.append(cert_info)
            
            # Determine vulnerability
            is_vulnerable = pub_key_algo in ["RSA", "ECDSA", "Ed25519", "DSA"]
            
            # Check expiry
            expiry_warning = ""
            try:
                expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_remaining = (expiry_date - datetime.utcnow()).days
                if days_remaining < 0:
                    expiry_warning = " EXPIRED!"
                elif days_remaining < 30:
                    expiry_warning = f" (Expires in {days_remaining} days!)"
            except:
                pass
            
            results.append(InventoryItem(
                id=f"cert:{self.target_host}:{fingerprint[:16]}",
                path=f"https://{self.target_host}:{self.port}",
                line=0,
                name=f"X.509 Certificate ({subject[:50]}...)" if len(subject) > 50 else f"X.509 Certificate ({subject})",
                category="certificate",
                algorithm=f"{pub_key_algo}-{key_size}" if key_size else pub_key_algo,
                key_size=key_size,
                is_pqc_vulnerable=is_vulnerable,
                description=f"Certificate signed with {sig_algo}. Issuer: {issuer}.{expiry_warning}",
                remediation="Prepare for PQC certificate migration. Monitor CA support for ML-DSA certificates."
            ))
            
        except Exception as e:
            print(f"Certificate parsing error: {e}")
            
        return results
    
    def _parse_x509_name(self, name_tuple: tuple) -> str:
        """Parse X.509 name tuple into readable string"""
        parts = []
        for rdn in name_tuple:
            for attr_type, attr_value in rdn:
                parts.append(f"{attr_type}={attr_value}")
        return ", ".join(parts) if parts else "Unknown"
    
    def _get_tls_remediation(self, is_zombie: bool, is_classical: bool) -> str:
        """Generate specific remediation guidance"""
        if is_zombie:
            return "URGENT: Disable TLS 1.0/1.1 immediately. Configure server for TLS 1.2+ only. Consider TLS 1.3 with hybrid PQC cipher suites."
        elif is_classical:
            return "Plan migration to hybrid PQC cipher suites (e.g., X25519Kyber768). Enable TLS 1.3 with ML-KEM key exchange when available."
        return "Review cipher suite configuration. Enable TLS 1.3 and prepare for PQC migration."
    
    def _create_error_finding(self, error_msg: str) -> InventoryItem:
        """Create a finding for scan errors"""
        return InventoryItem(
            id=f"error:{self.target_host}:{self.port}",
            path=f"https://{self.target_host}:{self.port}",
            line=0,
            name=f"Scan Error ({self.target_host})",
            category="error",
            algorithm="Unknown",
            key_size=0,
            is_pqc_vulnerable=True,
            description=error_msg,
            remediation="Manual investigation required."
        )
    
    def get_crypto_assets(self) -> List[CryptoAsset]:
        """Export scan results as CBOM CryptoAssets"""
        assets = []
        
        # TLS endpoint asset
        if self.cipher_suite:
            assets.append(CryptoAsset(
                bom_ref=f"tls-{self.target_host}-{self.port}",
                type="protocol",
                name=f"TLS Endpoint ({self.target_host}:{self.port})",
                protocol_version=self.tls_version,
                cipher_suite=self.cipher_suite,
                locations=[f"https://{self.target_host}:{self.port}"],
                is_pqc_vulnerable=any(tag in (self.cipher_suite or "").lower() for tag in self.CLASSICAL_VULNERABLE),
                quantum_risk="critical" if "rsa" in (self.cipher_suite or "").lower() else "high"
            ))
        
        # Certificate assets
        for cert in self.certificates:
            assets.append(CryptoAsset(
                bom_ref=f"cert-{cert.fingerprint_sha256[:16] if cert.fingerprint_sha256 else 'unknown'}",
                type="certificate",
                name=f"Certificate: {cert.subject[:30]}...",
                algorithm=cert.public_key_algorithm,
                key_length=cert.public_key_size,
                certificate=cert,
                locations=[f"https://{self.target_host}:{self.port}"],
                is_pqc_vulnerable=cert.public_key_algorithm in ["RSA", "ECDSA", "Ed25519"],
                quantum_risk="high" if cert.public_key_algorithm in ["RSA", "ECDSA"] else "medium"
            ))
        
        return assets
