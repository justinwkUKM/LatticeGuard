"""
LatticeGuard - Post-Quantum Cryptography Assessment Tool
Copyright (c) 2026 Waqas Khalid Obeidy
"""

"""
Strategic Advisory Engine
Provides contextual guidance and enterprise risk advice based on scan findings.
Addresses "blind spots" that static analysis alone cannot fully resolve.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class Advisory:
    title: str
    category: str  # "Hardware", "Governance", "Supply Chain", "Infrastructure"
    guidance: str
    action_items: List[str]
    linked_findings: List[str]
    urgency: str  # "High", "Medium", "Low"

class StrategicAdvisoryEngine:
    def __init__(self):
        self.advisories = []

    def generate_advisories(self, findings: List[Dict[str, Any]]) -> List[Advisory]:
        """Analyzes findings to produce strategic guidance"""
        generated = []
        
        # Normalize finding text for matching
        finding_texts = " ".join([f"{f.get('name', '')} {f.get('type', '')}".upper() for f in findings])
        
        # 1. HSM & Hardware Lifecycle Advisory
        hsm_keywords = ["HSM", "PKCS11", "YUBIKEY", "KEYSTORE", "HARDWARE", "HSM_SIGN", "TPM"]
        if any(kw in finding_texts for kw in hsm_keywords):
            generated.append(Advisory(
                title="Hardware Security Module (HSM) Lifecycle Audit",
                category="Hardware",
                guidance="Automated scans detected calls to hardware-backed key storage or hardware-specific APIs. While software can be patched, many legacy HSMs have fixed-function chips that cannot support PQC algorithms like ML-KEM or ML-DSA.",
                action_items=[
                    "Inventory all physical HSM and TPM hardware versions.",
                    "Contact vendors (Thales, Entrust, etc.) for PQC firmware roadmap.",
                    "Budget for potential hardware refresh for devices >5 years old."
                ],
                linked_findings=[f.get("name") for f in findings if any(kw in f.get("name", "").upper() for kw in hsm_keywords)][:5],
                urgency="High"
            ))

        # 2. Trusted Root & PKI Advisory
        pki_keywords = ["CERTIFICATE", "CERT-MANAGER", "CA-BUNDLE", "X509", "CSR", "TLS_RSA", "TLS_ECDHE"]
        if any(kw in finding_texts for kw in pki_keywords):
            generated.append(Advisory(
                title="PKI Trust Chain Transition Strategy",
                category="Infrastructure",
                guidance="Standard certificates or TLS handshake patterns were detected. The transition to PQC requires not just new leaf certificates, but a complete Root CA refresh, as most current Roots use RSA-4096 or ECDSA-P384.",
                action_items=[
                    "Audit the internal Root CA and Intermediate CAs.",
                    "Plan for 'Dual-Signature' certificates to support hybrid transition.",
                    "Verify if client devices support larger PQC certificate sizes."
                ],
                linked_findings=[f.get("name") for f in findings if any(kw in f.get("name", "").upper() for kw in pki_keywords)][:5],
                urgency="Medium"
            ))

        # 3. SaaS & Third-Party Dependency Advisory (SCA)
        # Check rule_id for SCA patterns
        if any("SCA_" in f.get("type", "") for f in findings) or "DEPENDENCY" in finding_texts:
            generated.append(Advisory(
                title="Supply Chain & Vendor Quantum Risk",
                category="Supply Chain",
                guidance="Vulnerable dependencies were found in your software bill of materials. Cryptographic risk extends to your vendors and SaaS providers who process your data.",
                action_items=[
                    "Add PQC readiness clauses to new vendor contracts.",
                    "Request PQC roadmaps from critical SaaS providers (Salesforce, AWS, etc.).",
                    "Prioritize vendors that handle 'Long-Lived Data' (>7 years retention)."
                ],
                linked_findings=[f.get("name") for f in findings if "SCA_" in f.get("type", "") or "DEPENDENCY" in f.get("name", "").upper()][:5],
                urgency="High"
            ))

        # 4. Crypto-Agility & Interoperability Advisory (General)
        if len(findings) > 0:
            critical_findings = [f for f in findings if f.get("severity") in ["CRITICAL", "HIGH"]]
            
            # Advise on general agility if we see a lot of legacy crypto
            legacy_keywords = ["RSA", "ECDSA", "SHA1", "MD5", "AES_CBC"]
            if any(kw in finding_texts for kw in legacy_keywords):
                generated.append(Advisory(
                    title="Enterprise Cryptographic Agility Program",
                    category="Governance",
                    guidance="High volume of legacy crypto patterns detected. This indicates a 'Static Crypto' pattern that makes PQC migration significantly harder across the enterprise.",
                    action_items=[
                        "Establish a centralized Cryptographic Provider/Library.",
                        "Abstract crypto calls into a standard internal API.",
                        "Conduct PQC performance benchmarking for legacy devices."
                    ],
                    linked_findings=[f.get("name") for f in critical_findings[:5]] if critical_findings else [f.get("name") for f in findings[:5]],
                    urgency="Medium"
                ))

        return generated
