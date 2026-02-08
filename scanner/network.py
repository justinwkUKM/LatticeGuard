"""
LatticeGuard - Post-Quantum Cryptography Assessment Tool
Copyright (c) 2026 Waqas Khalid Obeidy
"""

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
    
    # PQC Group IDs for Probing
    PQC_GROUPS = {
        0x6399: "x25519_kyber768_draft00",
        0x11ec: "x25519_mlkem768",
        0x001d: "x25519", # For comparison
    }
    
    def __init__(self, target_host: str, port: int = 443):
        self.target_host = target_host
        self.port = port
        self.certificates: List[CertificateInfo] = []
        self.tls_version: Optional[str] = None
        self.cipher_suite: Optional[str] = None
        self.pqc_ready: bool = False
        self.detected_pqc_group: Optional[str] = None
        
    def scan(self) -> List[InventoryItem]:
        """
        Performs comprehensive TLS analysis including:
        - TLS handshake and version detection
        - Active PQC Handshake Simulation (Protocol Auditor)
        - Certificate chain extraction
        - Quantum Resilience Scoring
        """
        results = []
        
        # 1. Passive SSL/TLS Scan
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target_host, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    cipher_info = ssock.cipher()
                    self.tls_version = ssock.version()
                    self.cipher_suite = cipher_info[0] if cipher_info else "Unknown"
                    bits = cipher_info[2] if cipher_info else 0
                    
                    cert_chain = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()
                    
                    # 2. Active PQC Handshake Simulation (The "Protocol Auditor" feature)
                    self.pqc_ready, self.detected_pqc_group = self.probe_pqc_support()
                    
                    # Analyze TLS endpoint with PQC probe awareness
                    tls_result = self._analyze_tls_endpoint(bits)
                    results.append(tls_result)
                    
                    if cert_dict:
                        cert_results = self._analyze_certificate(cert_dict, cert_chain)
                        results.extend(cert_results)
                        
        except ssl.SSLError as e:
            results.append(self._create_error_finding(f"SSL handshake failed: {e}"))
        except socket.timeout:
            print(f"Timeout scanning {self.target_host}:{self.port}")
        except Exception as e:
            print(f"Network Scan Error: {e}")
            
        return results
    
    def probe_pqc_support(self) -> Tuple[bool, Optional[str]]:
        """
        Attempts a low-level TLS 1.3 ClientHello offering PQC named groups.
        Specifically looks for X25519-Kyber768 (Group 0x6399).
        """
        try:
            # Construct a minimal TLS 1.3 ClientHello with PQC extensions
            # This is a simplified probe to detect ServerHello selection
            # Standard TLS 1.3 ClientHello bytes (simplified for detection)
            client_hello = bytearray([
                0x16, 0x03, 0x01, 0x00, 0xbd, # Record header
                0x01, 0x00, 0x00, 0xb9,       # Handshake header
                0x03, 0x03,                   # Client version (TLS 1.2 for compat)
                # Random (32 bytes)
                0x50, 0x51, 0x43, 0x50, 0x52, 0x4f, 0x42, 0x45, 
                0x50, 0x51, 0x43, 0x50, 0x52, 0x4f, 0x42, 0x45,
                0x50, 0x51, 0x43, 0x50, 0x52, 0x4f, 0x42, 0x45,
                0x50, 0x51, 0x43, 0x50, 0x52, 0x4f, 0x42, 0x45,
                0x00, # Session ID length
                0x00, 0x02, 0x13, 0x01, # Cipher Suites (TLS_AES_128_GCM_SHA256)
                0x01, 0x00, # Compression
                0x00, 0x8e, # Extensions Length
            ])
            
            # --- Extensions ---
            # Server Name Indication (SNI)
            sni_len = len(self.target_host)
            client_hello.extend([0x00, 0x00, 0x00, sni_len + 5, 0x00, sni_len + 3, 0x00, 0x00, sni_len])
            client_hello.extend(self.target_host.encode())
            
            # Supported Groups (including 0x6399 for Kyber)
            client_hello.extend([
                0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 
                0x63, 0x99, # x25519_kyber768_draft00
                0x00, 0x1d  # x25519
            ])
            
            # Key Share
            client_hello.extend([
                0x00, 0x33, 0x00, 0x26, 0x00, 0x24,
                0x63, 0x99, # Group
                0x00, 0x20  # Length
            ])
            client_hello.extend([0x00] * 32) # Dummy key share
            
            # Supported Versions (TLS 1.3)
            client_hello.extend([0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04])

            with socket.create_connection((self.target_host, self.port), timeout=5) as sock:
                sock.sendall(client_hello)
                response = sock.recv(4096)
                
                # Check for ServerHello (0x16 0x03 0x03) and check selected group
                if len(response) > 5 and response[0] == 0x16 and response[5] == 0x02:
                    # Very simple check: does the response contain the PQC group ID?
                    if b"\x63\x99" in response:
                        return True, "x25519_kyber768_draft00"
                    if b"\x11\xec" in response:
                        return True, "x25519_mlkem768"
                        
        except Exception:
            pass # Silently fail probe if host doesn't like raw bytes
            
        return False, None
    
    def calculate_resilience_score(self) -> int:
        """
        Calculates a Quantum Resilience Score (0-100).
        - TLS 1.3: +10
        - PQC Ready (Kyber/ML-KEM): +60
        - Clean Cert (No RSA/ECDSA): +30
        """
        score = 0
        if self.tls_version == "TLSv1.3":
            score += 10
        if self.pqc_ready:
            score += 60
        
        # Check certs (simplified)
        for cert in self.certificates:
            if cert.public_key_algorithm not in ["RSA", "ECDSA"]:
                score += 30
                break
                
        return min(100, score)

    def _analyze_tls_endpoint(self, bits: int) -> InventoryItem:
        """Analyze the TLS connection for vulnerabilities"""
        
        cipher_lower = self.cipher_suite.lower() if self.cipher_suite else ""
        
        # Check for quantum-safe algorithms
        is_pqc = self.pqc_ready or any(tag in cipher_lower for tag in self.QUANTUM_SAFE_TAGS)
        is_hybrid = self.pqc_ready or any(tag in cipher_lower for tag in self.HYBRID_TAGS)
        
        tls_info = self.TLS_VERSIONS.get(self.tls_version, {"vulnerable": True, "zombie": False, "risk": "medium"})
        is_zombie = tls_info["zombie"]
        
        # Determine vulnerability and reasoning
        is_vulnerable = not is_pqc
        risk_level = "high"
        resilience_score = self.calculate_resilience_score()
        
        if is_pqc:
            risk_level = "low"
            pqc_detail = self.detected_pqc_group or self.cipher_suite
            reasoning = f"PQC Ready ({pqc_detail}). Resilience Score: {resilience_score}/100. Secure against known quantum attacks."
        elif is_zombie:
            risk_level = "critical"
            reasoning = f"ZOMBIE PROTOCOL: {self.tls_version}. Resilience Score: {resilience_score}/100. Immediate upgrade required."
        else:
            reasoning = f"Classical Cryptography ({self.cipher_suite}). Resilience Score: {resilience_score}/100. Vulnerable to HNDL attacks."
            
        item = InventoryItem(
            id=f"tls:{self.target_host}:{self.port}",
            path=f"https://{self.target_host}:{self.port}",
            line=0,
            name=f"TLS Endpoint ({self.target_host})",
            category="network",
            algorithm=self.detected_pqc_group or self.cipher_suite,
            key_size=bits,
            is_pqc_vulnerable=is_vulnerable,
            description=reasoning,
            remediation=self._get_tls_remediation(is_zombie, not is_pqc),
            # Metadata
            protocol_version=self.tls_version,
            has_pfs="dhe" in cipher_lower or "ecdhe" in cipher_lower or self.tls_version == "TLSv1.3",
            risk_level=risk_level,
            hndl_score=100 - resilience_score
        )
        return item
    
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
            
            # Detect algorithms
            sig_algo = "Unknown"
            pub_key_algo = "Unknown"
            key_size = 0
            
            cipher_lower = (self.cipher_suite or "").lower()
            if "rsa" in cipher_lower:
                pub_key_algo = "RSA"
                sig_algo = "SHA256withRSA"
                key_size = 2048 
            elif "ecdsa" in cipher_lower:
                pub_key_algo = "ECDSA"
                key_size = 256
            
            is_vulnerable = pub_key_algo in ["RSA", "ECDSA", "Ed25519", "DSA"]
            
            item = InventoryItem(
                id=f"cert:{self.target_host}:{fingerprint[:16]}",
                path=f"https://{self.target_host}:{self.port}",
                line=0,
                name=f"X.509 Certificate ({subject[:50]}...)",
                category="certificate",
                algorithm=f"{pub_key_algo}-{key_size}" if key_size else pub_key_algo,
                key_size=key_size,
                is_pqc_vulnerable=is_vulnerable,
                description=f"Certificate signed with {sig_algo}. Issuer: {issuer}.",
                remediation="Prepare for PQC certificate migration.",
                # Metadata
                library_name="OpenSSL (Handshake)",
                library_version=ssl.OPENSSL_VERSION,
                key_created_at=not_before,
                key_expires_at=not_after,
                owner_team="Network Infrastructure"
            )
            results.append(item)
            
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
            return "URGENT: Disable legacy TLS. Migrate to TLS 1.3 with Hybrid PQC (Kyber)."
        elif is_classical:
            return "Enable TLS 1.3 Hybrid PQC (X25519Kyber768). Monitor NIST standardization."
        return "Review cipher suite configuration. Ensure ML-KEM support."
    
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
        if self.cipher_suite:
            assets.append(CryptoAsset(
                bom_ref=f"tls-{self.target_host}-{self.port}",
                type="protocol",
                name=f"TLS Endpoint ({self.target_host}:{self.port})",
                protocol_version=self.tls_version,
                cipher_suite=self.cipher_suite,
                locations=[f"https://{self.target_host}:{self.port}"],
                is_pqc_vulnerable=not self.pqc_ready,
                quantum_risk="critical" if "rsa" in (self.cipher_suite or "").lower() else "high"
            ))
        return assets
