"""
LatticeGuard - Post-Quantum Cryptography Assessment Tool
Copyright (c) 2026 Waqas Khalid Obeidy
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
from enum import Enum


class MigrationComplexity(Enum):
    """Migration complexity levels."""
    TRIVIAL = "trivial"      # Config change only
    EASY = "easy"            # Library upgrade, drop-in replacement
    MEDIUM = "medium"        # Algorithm swap, same API patterns
    HARD = "hard"            # Key management refactor
    MAJOR_REFACTOR = "major_refactor"  # Full crypto redesign


@dataclass
class MigrationEstimate:
    """Migration effort estimate for a finding."""
    complexity: MigrationComplexity
    estimated_hours: float
    description: str
    recommended_action: str
    pqc_alternative: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "complexity": self.complexity.value,
            "estimated_hours": self.estimated_hours,
            "description": self.description,
            "recommended_action": self.recommended_action,
            "pqc_alternative": self.pqc_alternative
        }


# Migration patterns and their complexity
MIGRATION_RULES: Dict[str, dict] = {
    # TLS/Config changes
    "Weak_TLS": {
        "complexity": MigrationComplexity.TRIVIAL,
        "hours": 0.5,
        "description": "TLS version configuration change",
        "action": "Update TLS minimum version to 1.2 or 1.3 in configuration",
        "pqc_alt": "Enable PQC hybrid key exchange groups when available"
    },
    "K8s_Weak_TLS": {
        "complexity": MigrationComplexity.TRIVIAL,
        "hours": 1.0,
        "description": "Kubernetes TLS annotation update",
        "action": "Update ingress annotations to enforce TLS 1.2+",
        "pqc_alt": "Configure PQC cipher suites when ingress controller supports them"
    },
    "Terraform_Legacy_TLS": {
        "complexity": MigrationComplexity.TRIVIAL,
        "hours": 0.5,
        "description": "Terraform TLS configuration change",
        "action": "Update min_tls_version in Terraform resource",
        "pqc_alt": None
    },
    
    # Library upgrades
    "SCA-CRYPTO-JS": {
        "complexity": MigrationComplexity.EASY,
        "hours": 2.0,
        "description": "JavaScript crypto library upgrade",
        "action": "Replace crypto-js with Web Crypto API or modern alternative",
        "pqc_alt": "Use liboqs-node when stable"
    },
    "SCA-NODE-RSA": {
        "complexity": MigrationComplexity.MEDIUM,
        "hours": 8.0,
        "description": "Node.js RSA library replacement",
        "action": "Migrate to node-forge or crypto module with larger key sizes",
        "pqc_alt": "Use ML-KEM via liboqs-node when available"
    },
    "SCA-RSA": {
        "complexity": MigrationComplexity.MEDIUM,
        "hours": 8.0,
        "description": "RSA library replacement",
        "action": "Upgrade to RSA-3072 minimum, prepare for PQC migration",
        "pqc_alt": "ML-KEM (Kyber) for key encapsulation"
    },
    
    # Algorithm swaps
    "AST-JAVA_KEYPAIRGENERATOR": {
        "complexity": MigrationComplexity.MEDIUM,
        "hours": 8.0,
        "description": "Java KeyPairGenerator algorithm change",
        "action": "Update to RSA-3072 or ECDSA P-384 minimum",
        "pqc_alt": "Use BouncyCastle PQC provider for ML-KEM/ML-DSA"
    },
    "AST-JAVA_SIGNATURE_GETINSTANCE": {
        "complexity": MigrationComplexity.MEDIUM,
        "hours": 8.0,
        "description": "Java Signature algorithm change",
        "action": "Migrate from ECDSA to hybrid or PQC signatures",
        "pqc_alt": "ML-DSA (Dilithium) via BouncyCastle"
    },
    "AST-JAVA_CIPHER_GETINSTANCE": {
        "complexity": MigrationComplexity.MEDIUM,
        "hours": 8.0,
        "description": "Java Cipher algorithm change",
        "action": "Replace RSA encryption with hybrid scheme",
        "pqc_alt": "ML-KEM + AES-GCM hybrid"
    },
    "AST-CPP_RSA_GENERATE_KEY": {
        "complexity": MigrationComplexity.HARD,
        "hours": 24.0,
        "description": "C++ OpenSSL RSA key generation refactor",
        "action": "Update to OpenSSL 3.x EVP API with RSA-3072+",
        "pqc_alt": "OpenSSL 3.4+ OQS provider for ML-KEM"
    },
    "AST-CPP_EVP_PKEY_KEYGEN": {
        "complexity": MigrationComplexity.HARD,
        "hours": 24.0,
        "description": "C++ OpenSSL key generation refactor",
        "action": "Audit key algorithm parameter, prepare for PQC",
        "pqc_alt": "OpenSSL OQS provider"
    },
    
    # Key management
    "K8s_TLS_Secret": {
        "complexity": MigrationComplexity.HARD,
        "hours": 16.0,
        "description": "Kubernetes TLS secret certificate rotation",
        "action": "Generate new certificates with stronger algorithms",
        "pqc_alt": "Hybrid certificates when CA supports them"
    },
    "K8s_CertManager_RSA": {
        "complexity": MigrationComplexity.MEDIUM,
        "hours": 4.0,
        "description": "cert-manager certificate algorithm update",
        "action": "Update Certificate resource to use stronger algorithm",
        "pqc_alt": "Wait for cert-manager PQC support"
    },
    
    # Secrets and credentials
    "AWS_Key": {
        "complexity": MigrationComplexity.EASY,
        "hours": 2.0,
        "description": "AWS credential rotation",
        "action": "Rotate exposed AWS keys, implement secret management",
        "pqc_alt": None
    },
    "Generic_Secret": {
        "complexity": MigrationComplexity.EASY,
        "hours": 2.0,
        "description": "Secret rotation and vault migration",
        "action": "Move secrets to vault, rotate exposed credentials",
        "pqc_alt": None
    },
    
    # Hash algorithms
    "Weak_Hash": {
        "complexity": MigrationComplexity.MEDIUM,
        "hours": 8.0,
        "description": "Weak hash algorithm replacement",
        "action": "Replace MD5/SHA1 with SHA-256 or SHA-3",
        "pqc_alt": "SHA-3 is quantum-resistant for hashing"
    },
    
    # Full redesign cases
    "Terraform_RSA": {
        "complexity": MigrationComplexity.HARD,
        "hours": 24.0,
        "description": "Infrastructure RSA key migration",
        "action": "Plan phased migration to stronger algorithms",
        "pqc_alt": "Cloud provider PQC support when available"
    },
}

# Default for unknown patterns
DEFAULT_MIGRATION = {
    "complexity": MigrationComplexity.MEDIUM,
    "hours": 8.0,
    "description": "Cryptographic algorithm assessment required",
    "action": "Analyze usage context and plan migration strategy",
    "pqc_alt": "Consult NIST PQC standards for alternatives"
}


class MigrationEstimator:
    """Estimates migration effort for PQC remediation."""
    
    def estimate(self, rule_id: str, algorithm: str = None) -> MigrationEstimate:
        """Get migration estimate for a finding."""
        # Try exact match first
        rule = MIGRATION_RULES.get(rule_id)
        
        # Try pattern matching on rule_id
        if not rule:
            for pattern, config in MIGRATION_RULES.items():
                if pattern in rule_id:
                    rule = config
                    break
        
        # Use default if no match
        if not rule:
            rule = DEFAULT_MIGRATION
        
        return MigrationEstimate(
            complexity=rule["complexity"],
            estimated_hours=rule["hours"],
            description=rule["description"],
            recommended_action=rule["action"],
            pqc_alternative=rule.get("pqc_alt")
        )
    
    def total_effort(self, findings: List[dict]) -> dict:
        """Calculate total migration effort across all findings."""
        total_hours = 0.0
        by_complexity: Dict[str, int] = {c.value: 0 for c in MigrationComplexity}
        
        for finding in findings:
            estimate = self.estimate(finding.get("rule_id", ""))
            total_hours += estimate.estimated_hours
            by_complexity[estimate.complexity.value] += 1
        
        return {
            "total_hours": total_hours,
            "total_developer_days": round(total_hours / 8, 1),
            "by_complexity": by_complexity,
            "finding_count": len(findings)
        }
