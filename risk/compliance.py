"""
LatticeGuard - Post-Quantum Cryptography Assessment Tool
Copyright (c) 2026 Waqas Khalid Obeidy
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from datetime import datetime


@dataclass
class ComplianceRequirement:
    """A single compliance requirement."""
    id: str
    framework: str
    title: str
    description: str
    remediation_guidance: str


@dataclass
class ComplianceMapping:
    """Mapping of a finding to compliance requirements."""
    finding_type: str
    requirements: List[ComplianceRequirement]
    
    def to_dict(self) -> dict:
        return {
            "finding_type": self.finding_type,
            "requirements": [
                {
                    "id": r.id,
                    "framework": r.framework,
                    "title": r.title,
                    "description": r.description,
                    "remediation_guidance": r.remediation_guidance
                }
                for r in self.requirements
            ]
        }


# Compliance framework definitions
COMPLIANCE_FRAMEWORKS = {
    "BNM-RMiT": "Bank Negara Malaysia - Risk Management in Technology",
    "PCI-DSS-4.0": "Payment Card Industry Data Security Standard v4.0",
    "NIST-SP-800-131A": "NIST Transitioning Use of Cryptographic Algorithms",
    "NIST-SP-800-52r2": "NIST Guidelines for TLS Implementations",
    "ISO-27001": "Information Security Management",
    "MAS-TRM": "Monetary Authority of Singapore - Technology Risk Management",
}


# Compliance requirement definitions
REQUIREMENTS_DB: Dict[str, ComplianceRequirement] = {
    # BNM RMiT Requirements
    "BNM-RMiT-10.49": ComplianceRequirement(
        id="BNM-RMiT-10.49",
        framework="BNM-RMiT",
        title="Cryptographic Controls",
        description="Financial institutions must implement strong cryptographic controls for data protection.",
        remediation_guidance="Upgrade to approved cryptographic algorithms with adequate key lengths."
    ),
    "BNM-RMiT-10.50": ComplianceRequirement(
        id="BNM-RMiT-10.50",
        framework="BNM-RMiT",
        title="Encryption Key Management",
        description="Proper key management procedures must be established.",
        remediation_guidance="Implement HSM-backed key management with rotation policies."
    ),
    "BNM-RMiT-10.51": ComplianceRequirement(
        id="BNM-RMiT-10.51",
        framework="BNM-RMiT",
        title="Encryption in Transit",
        description="Data must be encrypted during transmission using approved protocols.",
        remediation_guidance="Enforce TLS 1.2+ with strong cipher suites."
    ),
    
    # PCI-DSS 4.0 Requirements
    "PCI-DSS-4.0-3.5": ComplianceRequirement(
        id="PCI-DSS-4.0-3.5",
        framework="PCI-DSS-4.0",
        title="Protect Stored Account Data",
        description="Primary account numbers must be rendered unreadable using strong cryptography.",
        remediation_guidance="Use AES-256 or stronger for PAN encryption."
    ),
    "PCI-DSS-4.0-4.2.1": ComplianceRequirement(
        id="PCI-DSS-4.0-4.2.1",
        framework="PCI-DSS-4.0",
        title="Strong Cryptography for Transmission",
        description="Strong cryptography must be used during transmission of cardholder data.",
        remediation_guidance="Use TLS 1.2+ with PFS cipher suites, prepare for PQC."
    ),
    "PCI-DSS-4.0-4.2.2": ComplianceRequirement(
        id="PCI-DSS-4.0-4.2.2",
        framework="PCI-DSS-4.0",
        title="Certificate Validation",
        description="Certificates used for transmission must be valid and trusted.",
        remediation_guidance="Implement proper certificate validation and use RSA-2048+ or ECDSA P-256+."
    ),
    
    # NIST SP 800-131A Requirements
    "NIST-800-131A-RSA": ComplianceRequirement(
        id="NIST-800-131A-RSA",
        framework="NIST-SP-800-131A",
        title="RSA Key Size Requirements",
        description="RSA keys must be at least 2048 bits through 2030.",
        remediation_guidance="Upgrade to RSA-3072 for longevity beyond 2030."
    ),
    "NIST-800-131A-ECDSA": ComplianceRequirement(
        id="NIST-800-131A-ECDSA",
        framework="NIST-SP-800-131A",
        title="ECDSA Curve Requirements",
        description="ECDSA must use P-256 or stronger curves.",
        remediation_guidance="Use P-384 for additional security margin."
    ),
    "NIST-800-131A-HASH": ComplianceRequirement(
        id="NIST-800-131A-HASH",
        framework="NIST-SP-800-131A",
        title="Hash Function Requirements",
        description="SHA-1 is disallowed for digital signatures.",
        remediation_guidance="Use SHA-256 or SHA-3 for all security applications."
    ),
    
    # NIST SP 800-52r2 Requirements (TLS)
    "NIST-800-52r2-TLS": ComplianceRequirement(
        id="NIST-800-52r2-TLS",
        framework="NIST-SP-800-52r2",
        title="TLS Version Requirements",
        description="TLS 1.2 is the minimum acceptable version; TLS 1.3 preferred.",
        remediation_guidance="Disable TLS 1.0/1.1, enable TLS 1.3 where possible."
    ),
}


# Mapping of finding patterns to compliance requirements
FINDING_TO_COMPLIANCE: Dict[str, List[str]] = {
    # RSA findings
    "RSA": ["BNM-RMiT-10.49", "PCI-DSS-4.0-4.2.1", "NIST-800-131A-RSA"],
    "AST-JAVA_KEYPAIRGENERATOR": ["BNM-RMiT-10.49", "PCI-DSS-4.0-3.5", "NIST-800-131A-RSA"],
    "AST-CPP_RSA_GENERATE_KEY": ["BNM-RMiT-10.49", "NIST-800-131A-RSA"],
    "Terraform_RSA": ["BNM-RMiT-10.50", "NIST-800-131A-RSA"],
    
    # ECDSA/EC findings
    "ECDSA": ["BNM-RMiT-10.49", "PCI-DSS-4.0-4.2.1", "NIST-800-131A-ECDSA"],
    "AST-JAVA_SIGNATURE_GETINSTANCE": ["BNM-RMiT-10.49", "NIST-800-131A-ECDSA"],
    
    # TLS findings
    "Weak_TLS": ["BNM-RMiT-10.51", "PCI-DSS-4.0-4.2.1", "NIST-800-52r2-TLS"],
    "K8s_Weak_TLS": ["BNM-RMiT-10.51", "PCI-DSS-4.0-4.2.1", "NIST-800-52r2-TLS"],
    "Terraform_Legacy_TLS": ["NIST-800-52r2-TLS"],
    
    # Hash findings
    "Weak_Hash": ["NIST-800-131A-HASH"],
    "MD5": ["NIST-800-131A-HASH"],
    "SHA1": ["NIST-800-131A-HASH"],
    
    # Key management
    "K8s_TLS_Secret": ["BNM-RMiT-10.50", "PCI-DSS-4.0-4.2.2"],
    "K8s_CertManager_RSA": ["BNM-RMiT-10.50", "PCI-DSS-4.0-4.2.2"],
    
    # Secrets
    "AWS_Key": ["BNM-RMiT-10.50", "PCI-DSS-4.0-3.5"],
    "Generic_Secret": ["BNM-RMiT-10.50", "PCI-DSS-4.0-3.5"],
}


class ComplianceMapper:
    """Maps findings to compliance requirements."""
    
    def map_finding(self, rule_id: str, algorithm: str = None) -> ComplianceMapping:
        """Get compliance requirements for a finding."""
        requirement_ids = []
        
        # Try exact match on rule_id
        if rule_id in FINDING_TO_COMPLIANCE:
            requirement_ids = FINDING_TO_COMPLIANCE[rule_id]
        else:
            # Try pattern matching
            for pattern, req_ids in FINDING_TO_COMPLIANCE.items():
                if pattern in rule_id:
                    requirement_ids = req_ids
                    break
        
        # Also check algorithm name
        if algorithm and not requirement_ids:
            algo_upper = algorithm.upper()
            for pattern, req_ids in FINDING_TO_COMPLIANCE.items():
                if pattern.upper() in algo_upper:
                    requirement_ids = req_ids
                    break
        
        requirements = [REQUIREMENTS_DB[rid] for rid in requirement_ids if rid in REQUIREMENTS_DB]
        
        return ComplianceMapping(
            finding_type=rule_id,
            requirements=requirements
        )
    
    def generate_audit_report(self, findings: List[dict]) -> dict:
        """Generate a compliance audit report from findings."""
        by_framework: Dict[str, List[dict]] = {}
        all_requirements: Dict[str, int] = {}
        
        for finding in findings:
            mapping = self.map_finding(finding.get("rule_id", ""), finding.get("algorithm"))
            
            for req in mapping.requirements:
                # Count requirement violations
                all_requirements[req.id] = all_requirements.get(req.id, 0) + 1
                
                # Group by framework
                if req.framework not in by_framework:
                    by_framework[req.framework] = []
                
                by_framework[req.framework].append({
                    "requirement_id": req.id,
                    "title": req.title,
                    "finding": finding.get("rule_id"),
                    "file": finding.get("path"),
                    "remediation": req.remediation_guidance
                })
        
        return {
            "generated_at": datetime.now().isoformat(),
            "total_findings": len(findings),
            "frameworks_affected": list(by_framework.keys()),
            "requirements_violated": len(all_requirements),
            "by_framework": by_framework,
            "requirement_counts": all_requirements
        }
