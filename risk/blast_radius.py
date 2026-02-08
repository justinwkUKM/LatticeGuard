"""
LatticeGuard - Post-Quantum Cryptography Assessment Tool
Copyright (c) 2026 Waqas Khalid Obeidy
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional
from pathlib import Path
from collections import defaultdict
import re


@dataclass
class BlastRadiusResult:
    """Result of blast radius analysis for a single algorithm."""
    algorithm: str
    file_count: int
    line_count: int
    affected_components: List[str]
    affected_flows: List[str]
    files: List[str]
    severity: str  # critical, high, medium, low
    
    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "file_count": self.file_count,
            "line_count": self.line_count,
            "affected_components": self.affected_components,
            "affected_flows": self.affected_flows,
            "files": self.files,
            "severity": self.severity
        }


@dataclass 
class BlastRadiusReport:
    """Complete blast radius analysis report."""
    algorithms: Dict[str, BlastRadiusResult] = field(default_factory=dict)
    total_files_at_risk: int = 0
    total_components_at_risk: int = 0
    highest_risk_algorithm: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "algorithms": {k: v.to_dict() for k, v in self.algorithms.items()},
            "total_files_at_risk": self.total_files_at_risk,
            "total_components_at_risk": self.total_components_at_risk,
            "highest_risk_algorithm": self.highest_risk_algorithm
        }


# Component detection patterns (directory/path-based)
COMPONENT_PATTERNS = {
    r"payment|checkout|billing": "payment-service",
    r"auth|login|session|token": "auth-service", 
    r"user|profile|account": "user-service",
    r"api|gateway|proxy": "api-gateway",
    r"settlement|transfer|rtgs": "settlement-service",
    r"hsm|vault|key": "key-management",
    r"cert|tls|ssl": "certificate-service",
    r"qr|merchant|pos": "merchant-service",
    r"iso20022|swift|sepa": "interbank-messaging",
    r"config|infra|terraform|k8s": "infrastructure",
}

# Flow detection based on file content/context
FLOW_PATTERNS = {
    r"sign|signature|verify": "digital signatures",
    r"encrypt|decrypt|cipher": "data encryption",
    r"auth|authenticate|login": "authentication",
    r"token|jwt|session": "token management",
    r"key.*exchange|handshake|tls": "key exchange",
    r"certificate|x509|pem": "certificate validation",
    r"payment|transaction|transfer": "payment processing",
    r"hash|digest|checksum": "data integrity",
}


class BlastRadiusAnalyzer:
    """Analyzes the blast radius of cryptographic algorithm usage."""
    
    def __init__(self):
        self.algorithm_usage: Dict[str, List[dict]] = defaultdict(list)
    
    def add_finding(self, algorithm: str, file_path: str, line: int, 
                    content: str, severity: str = "high"):
        """Add a finding to the analysis."""
        self.algorithm_usage[algorithm].append({
            "file": file_path,
            "line": line,
            "content": content,
            "severity": severity
        })
    
    def _detect_component(self, file_path: str) -> str:
        """Detect which component a file belongs to."""
        path_lower = file_path.lower()
        for pattern, component in COMPONENT_PATTERNS.items():
            if re.search(pattern, path_lower):
                return component
        
        # Fallback: use top-level directory
        parts = Path(file_path).parts
        if len(parts) > 1:
            return parts[0] if parts[0] not in ('.', '..') else parts[1] if len(parts) > 2 else "unknown"
        return "root"
    
    def _detect_flows(self, content: str) -> List[str]:
        """Detect which flows/operations are affected based on content."""
        flows = set()
        content_lower = content.lower()
        for pattern, flow in FLOW_PATTERNS.items():
            if re.search(pattern, content_lower):
                flows.add(flow)
        return list(flows) if flows else ["general crypto operations"]
    
    def _calculate_severity(self, algorithm: str, file_count: int) -> str:
        """Calculate severity based on algorithm type and usage extent."""
        high_risk_algos = {"RSA", "ECDSA", "DSA", "EC", "DH", "ECDH"}
        
        if algorithm.upper() in high_risk_algos or any(a in algorithm.upper() for a in high_risk_algos):
            if file_count >= 10:
                return "critical"
            elif file_count >= 5:
                return "high"
            else:
                return "medium"
        else:
            return "medium" if file_count >= 10 else "low"
    
    def analyze(self) -> BlastRadiusReport:
        """Generate the blast radius report."""
        report = BlastRadiusReport()
        all_files: Set[str] = set()
        all_components: Set[str] = set()
        max_files = 0
        highest_risk_algo = None
        
        for algorithm, findings in self.algorithm_usage.items():
            files = list(set(f["file"] for f in findings))
            components = list(set(self._detect_component(f["file"]) for f in findings))
            
            # Collect all flows from all findings
            all_flows: Set[str] = set()
            for finding in findings:
                all_flows.update(self._detect_flows(finding["content"]))
            
            severity = self._calculate_severity(algorithm, len(files))
            
            result = BlastRadiusResult(
                algorithm=algorithm,
                file_count=len(files),
                line_count=len(findings),
                affected_components=components,
                affected_flows=list(all_flows),
                files=files,
                severity=severity
            )
            
            report.algorithms[algorithm] = result
            all_files.update(files)
            all_components.update(components)
            
            if len(files) > max_files:
                max_files = len(files)
                highest_risk_algo = algorithm
        
        report.total_files_at_risk = len(all_files)
        report.total_components_at_risk = len(all_components)
        report.highest_risk_algorithm = highest_risk_algo
        
        return report
    
    def format_summary(self, report: BlastRadiusReport) -> str:
        """Format a human-readable summary."""
        lines = [
            "=" * 80,
            "BLAST RADIUS ANALYSIS",
            "=" * 80,
            f"Total Files at Risk: {report.total_files_at_risk}",
            f"Total Components at Risk: {report.total_components_at_risk}",
            f"Highest Risk Algorithm: {report.highest_risk_algorithm}",
            "-" * 80,
        ]
        
        for algo, result in sorted(report.algorithms.items(), 
                                   key=lambda x: x[1].file_count, reverse=True):
            lines.append(f"\n📊 {algo}")
            lines.append(f"   Severity: {result.severity.upper()}")
            lines.append(f"   Files: {result.file_count} | Occurrences: {result.line_count}")
            lines.append(f"   Components: {', '.join(result.affected_components)}")
            lines.append(f"   Flows: {', '.join(result.affected_flows)}")
        
        lines.append("=" * 80)
        return "\n".join(lines)
