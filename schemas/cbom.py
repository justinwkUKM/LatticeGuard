"""
LatticeGuard - Post-Quantum Cryptography Assessment Tool
Copyright (c) 2026 Waqas Khalid Obeidy
"""

"""
Cryptography Bill of Materials (CBOM) Schema
Based on CycloneDX 1.6 Cryptographic Assets specification
"""
from typing import List, Optional, Dict, Literal
from pydantic import BaseModel, Field
from datetime import datetime


class CertificateInfo(BaseModel):
    """X.509 Certificate metadata"""
    subject: str
    issuer: str
    serial_number: str
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    signature_algorithm: str
    public_key_algorithm: str
    public_key_size: int
    san: List[str] = Field(default_factory=list)  # Subject Alternative Names
    is_ca: bool = False
    fingerprint_sha256: Optional[str] = None


class CryptoAsset(BaseModel):
    """Individual cryptographic asset in the CBOM"""
    bom_ref: str  # Unique reference ID
    type: Literal["certificate", "key", "algorithm", "protocol", "library"]
    name: str
    description: Optional[str] = None
    
    # Algorithm details
    algorithm: Optional[str] = None
    algorithm_family: Optional[Literal["rsa", "ecc", "dsa", "aes", "chacha", "sha", "pqc", "hybrid", "other"]] = None
    key_length: Optional[int] = None
    
    # Certificate-specific
    certificate: Optional[CertificateInfo] = None
    
    # Protocol-specific
    protocol_version: Optional[str] = None  # e.g., "TLS 1.2", "TLS 1.3"
    cipher_suite: Optional[str] = None
    
    # Location
    locations: List[str] = Field(default_factory=list)
    
    # Risk assessment
    is_pqc_vulnerable: bool = True
    quantum_risk: Literal["critical", "high", "medium", "low", "none"] = "high"
    hndl_risk: Literal["critical", "high", "medium", "low", "none"] = "medium"
    
    # Longevity & Sensitivity (for HNDL calculation)
    data_longevity_years: Optional[int] = None
    data_sensitivity: Optional[Literal["public", "internal", "confidential", "secret", "top_secret"]] = None
    
    # Remediation
    pqc_recommendation: Optional[str] = None
    
    # Metadata
    discovered_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    tags: List[str] = Field(default_factory=list)


class CBOMMetadata(BaseModel):
    """CBOM document metadata"""
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    tool_name: str = "LatticeGuard"
    tool_version: str = "1.0.0"
    scan_id: str
    target: str


class CBOM(BaseModel):
    """
    Cryptography Bill of Materials
    CycloneDX 1.6 compatible schema for cryptographic assets
    """
    bom_format: str = "CycloneDX"
    spec_version: str = "1.6"
    version: int = 1
    metadata: CBOMMetadata
    components: List[CryptoAsset] = Field(default_factory=list)
    
    # Summary statistics
    total_assets: int = 0
    vulnerable_assets: int = 0
    critical_risks: int = 0
    
    def add_asset(self, asset: CryptoAsset):
        """Add a crypto asset and update statistics"""
        self.components.append(asset)
        self.total_assets = len(self.components)
        self.vulnerable_assets = sum(1 for c in self.components if c.is_pqc_vulnerable)
        self.critical_risks = sum(1 for c in self.components if c.quantum_risk == "critical")
    
    def to_cyclonedx(self) -> Dict:
        """Export as CycloneDX-compatible JSON"""
        return {
            "bomFormat": self.bom_format,
            "specVersion": self.spec_version,
            "version": self.version,
            "metadata": {
                "timestamp": self.metadata.timestamp,
                "tools": [{
                    "name": self.metadata.tool_name,
                    "version": self.metadata.tool_version
                }],
                "component": {
                    "type": "application",
                    "name": self.metadata.target,
                    "bom-ref": self.metadata.scan_id
                }
            },
            "components": [
                {
                    "type": "cryptographic-asset",
                    "bom-ref": c.bom_ref,
                    "name": c.name,
                    "description": c.description,
                    "cryptoProperties": {
                        "assetType": c.type,
                        "algorithmProperties": {
                            "algorithm": c.algorithm,
                            "keyLength": c.key_length,
                            "quantumVulnerable": c.is_pqc_vulnerable
                        } if c.algorithm else None,
                        "certificateProperties": {
                            "subjectName": c.certificate.subject,
                            "issuerName": c.certificate.issuer,
                            "notValidBefore": c.certificate.not_before,
                            "notValidAfter": c.certificate.not_after,
                            "signatureAlgorithmRef": c.certificate.signature_algorithm
                        } if c.certificate else None,
                        "protocolProperties": {
                            "version": c.protocol_version,
                            "cipherSuites": [c.cipher_suite] if c.cipher_suite else []
                        } if c.protocol_version else None
                    },
                    "properties": [
                        {"name": "hndl-risk", "value": c.hndl_risk},
                        {"name": "quantum-risk", "value": c.quantum_risk},
                        {"name": "pqc-recommendation", "value": c.pqc_recommendation or "N/A"}
                    ]
                }
                for c in self.components
            ],
            "vulnerabilities": [
                {
                    "id": f"PQC-{c.bom_ref}",
                    "description": f"{c.algorithm or c.name} is vulnerable to quantum attacks",
                    "ratings": [{
                        "severity": c.quantum_risk,
                        "method": "LatticeGuard-HNDL"
                    }],
                    "recommendation": c.pqc_recommendation
                }
                for c in self.components if c.is_pqc_vulnerable
            ]
        }


def generate_cbom_from_findings(run_id: str, target: str, findings: List[Dict]) -> CBOM:
    """
    Convert LatticeGuard findings into a CBOM
    """
    cbom = CBOM(
        metadata=CBOMMetadata(
            scan_id=run_id,
            target=target
        )
    )
    
    for f in findings:
        # Determine algorithm family
        algo = (f.get("algorithm") or "").upper()
        family = "other"
        if "RSA" in algo:
            family = "rsa"
        elif any(x in algo for x in ["ECC", "ECDSA", "ECDHE", "ED25519", "P-256", "P-384"]):
            family = "ecc"
        elif any(x in algo for x in ["AES", "CHACHA"]):
            family = "aes" if "AES" in algo else "chacha"
        elif any(x in algo for x in ["SHA", "MD5"]):
            family = "sha"
        elif any(x in algo for x in ["KYBER", "DILITHIUM", "FALCON", "SPHINCS"]):
            family = "pqc"
        
        # Calculate HNDL risk
        hndl = "medium"
        if f.get("is_pqc") or f.get("is_pqc_vulnerable"):
            if "RSA" in algo or "ECDHE" in algo:
                hndl = "critical" if "1024" in algo or "2048" in algo else "high"
        
        asset = CryptoAsset(
            bom_ref=f.get("id", f.get("path", "unknown")),
            type="algorithm",
            name=f.get("name", "Unknown Asset"),
            description=f.get("description"),
            algorithm=f.get("algorithm"),
            algorithm_family=family,
            key_length=f.get("key_size"),
            locations=[f.get("path", "")],
            is_pqc_vulnerable=f.get("is_pqc", f.get("is_pqc_vulnerable", True)),
            quantum_risk="critical" if f.get("risk_level") == "critical" else "high" if f.get("is_pqc") else "medium",
            hndl_risk=hndl,
            pqc_recommendation=f.get("remediation", "Migrate to NIST PQC standard (ML-KEM or ML-DSA)")
        )
        cbom.add_asset(asset)
    
    return cbom
