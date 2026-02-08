"""
LatticeGuard - Post-Quantum Cryptography Assessment Tool
Copyright (c) 2026 Waqas Khalid Obeidy
"""

#!/usr/bin/env python3
"""
LatticeGuard CI/CD Scanner
Pipeline-ready CLI tool for PQC vulnerability scanning with exit codes and SARIF output.

Exit Codes:
    0 = Pass (no findings above threshold)
    1 = Warnings (findings below threshold, non-blocking)
    2 = Failure (findings at or above threshold, blocking)

Usage:
    # Basic scan
    latticeguard scan /path/to/repo
    
    # With threshold (fail on high or critical)
    latticeguard scan /path/to/repo --fail-on high
    
    # SARIF output for GitHub Security tab
    latticeguard scan /path/to/repo --format sarif -o results.sarif
    
    # Tag data longevity for HNDL scoring
    latticeguard scan /path/to/repo --longevity 10 --sensitivity confidential
"""
import argparse
import json
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Literal
from dataclasses import dataclass, asdict


# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner.files import ArtifactScanner
from scanner.patterns import PatternScanner
from scanner.dependencies import DependencyScanner
from scanner.db import save_suspects, init_db, save_inventory_item
from scanner.suppression import SuppressionManager
from scanner.cloud_discovery import CloudDiscoveryManager
from scanner.treesitter_scanner import TreeSitterScanner
from scanner.kubernetes import KubernetesScanner
from schemas.models import InventoryItem


@dataclass
class ScanResult:
    """Result from a single finding"""
    path: str
    line: int
    rule_id: str
    message: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    algorithm: Optional[str] = None
    pqc_recommendation: Optional[str] = None
    hndl_score: Optional[float] = None
    run_id: Optional[str] = None


@dataclass
class ScanSummary:
    """Overall scan summary"""
    total_files: int
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    passed: bool
    exit_code: int
    run_id: str


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def calculate_hndl_score(
    algorithm: str,
    longevity_years: int = 5,
    sensitivity: str = "internal"
) -> float:
    """
    Calculate HNDL (Harvest Now, Decrypt Later) risk score.
    
    Formula: HNDL = (LONGEVITY × SENSITIVITY × ALGORITHM_RISK) / QUANTUM_TIMELINE
    
    Returns score from 0.0 (safe) to 10.0 (critical)
    """
    # Algorithm risk factors
    algo_upper = algorithm.upper() if algorithm else ""
    if any(tag in algo_upper for tag in ["KYBER", "DILITHIUM", "ML-KEM", "ML-DSA"]):
        algo_risk = 1  # Quantum-safe
    elif "RSA-1024" in algo_upper or "DES" in algo_upper:
        algo_risk = 10  # Critical
    elif "RSA-2048" in algo_upper:
        algo_risk = 8
    elif "RSA-4096" in algo_upper:
        algo_risk = 6
    elif any(tag in algo_upper for tag in ["ECDSA", "ECDHE", "ED25519", "P-256", "P-384"]):
        algo_risk = 7
    elif "AES" in algo_upper:
        algo_risk = 3  # Symmetric is more resistant
    else:
        algo_risk = 5  # Default unknown
    
    # Sensitivity factors
    sensitivity_map = {
        "public": 1,
        "internal": 3,
        "confidential": 5,
        "secret": 8,
        "top_secret": 10,
        "pii": 7,
        "financial": 8,
        "health": 9
    }
    sens_factor = sensitivity_map.get(sensitivity.lower(), 3)
    
    # Longevity factor (normalized to 1-10)
    longevity_factor = min(10, max(1, longevity_years / 3))
    
    # Quantum timeline (estimated years until CRQC - cryptographically relevant quantum computer)
    quantum_timeline = 10  # Conservative estimate
    
    # Calculate HNDL score
    hndl = (longevity_factor * sens_factor * algo_risk) / quantum_timeline
    return round(min(10.0, hndl), 2)


def severity_from_hndl(hndl_score: float) -> str:
    """Map HNDL score to severity level"""
    if hndl_score >= 7:
        return "critical"
    elif hndl_score >= 5:
        return "high"
    elif hndl_score >= 3:
        return "medium"
    elif hndl_score >= 1:
        return "low"
    return "info"


def scan_repository(
    repo_path: str,
    longevity_years: int = 5,
    sensitivity: str = "internal",
    config_path: Optional[str] = None
) -> List[ScanResult]:
    """Run all scanners on a repository"""
    results = []
    repo = Path(repo_path)
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    db_path = "data/pqc.db"
    
    # Ensure DB is initialized
    os.makedirs("data", exist_ok=True)
    init_db(db_path)
    
    if not repo.exists():
        print(f"Error: Path {repo_path} does not exist", file=sys.stderr)
        sys.exit(2)
    
    # Initialize suppression manager
    suppressor = SuppressionManager(config_path or ".latticeguard.yaml")
    
    # Initialize scanners
    artifact_scanner = ArtifactScanner(str(repo))
    pattern_scanner = PatternScanner(str(repo))
    dep_scanner = DependencyScanner(str(repo))
    ts_scanner = TreeSitterScanner()
    k8s_scanner = KubernetesScanner(str(repo))
    
    # Run scans
    print(f"🔍 Scanning {repo_path} (Run ID: {run_id})...", file=sys.stderr)
    
    # Pattern scan
    suspects = pattern_scanner.scan()
    for suspect in suspects:
        if suppressor.should_suppress(suspect):
            continue
            
        algo = suspect.pattern_matched if hasattr(suspect, 'pattern_matched') else "Unknown"
        hndl = calculate_hndl_score(algo, longevity_years, sensitivity)
        severity = severity_from_hndl(hndl)
        
        scan_res = ScanResult(
            path=suspect.path,
            line=suspect.line,
            rule_id=f"PQC-{algo.upper().replace(' ', '-')[:20]}",
            message=f"Potential PQC vulnerability: {algo}",
            severity=severity,
            algorithm=algo,
            pqc_recommendation="Migrate to NIST PQC standard (ML-KEM or ML-DSA)",
            hndl_score=hndl,
            run_id=run_id
        )
        results.append(scan_res)
        
        # Auto-sync to inventory
        inventory_item = InventoryItem(
            id=f"{run_id}:{suspect.path}:{suspect.line}",
            path=suspect.path,
            line=suspect.line,
            name=f"Cryptographic Asset ({algo})",
            category="code",
            algorithm=algo,
            is_pqc_vulnerable=True,
            description=scan_res.message,
            hndl_score=hndl,
            risk_level=severity,
            remediation=scan_res.pqc_recommendation
        )
        save_inventory_item(db_path, inventory_item, run_id)
    
    # Dependency scan
    dep_suspects = dep_scanner.scan()
    for dep in dep_suspects:
        if suppressor.should_suppress(dep):
            continue
            
        algo = dep.pattern_matched if hasattr(dep, 'pattern_matched') else "Unknown Dependency"
        hndl = calculate_hndl_score(algo, longevity_years, sensitivity)
        severity = severity_from_hndl(hndl)
        
        scan_res = ScanResult(
            path=dep.path,
            line=dep.line,
            rule_id=f"SCA-{algo.upper().replace(' ', '-')[:20]}",
            message=f"Vulnerable cryptographic dependency: {algo}",
            severity=severity,
            algorithm=algo,
            pqc_recommendation="Update to a PQC-compatible version or alternative library",
            hndl_score=hndl,
            run_id=run_id
        )
        results.append(scan_res)
        
        # Auto-sync to inventory
        inventory_item = InventoryItem(
            id=f"{run_id}:{dep.path}:{dep.line}",
            path=dep.path,
            line=dep.line,
            name=f"Dependency ({algo})",
            category="dependency",
            algorithm=algo,
            is_pqc_vulnerable=True,
            description=scan_res.message,
            hndl_score=hndl,
            risk_level=severity,
            remediation=scan_res.pqc_recommendation
        )
        save_inventory_item(db_path, inventory_item, run_id)
    
    # AST-Based Tree-Sitter Scan
    print(f"🌳 Running AST analysis for Java, C++, Rust, and C#...", file=sys.stderr)
    for dirpath, dirnames, filenames in os.walk(repo):
        # Skip hidden and excluded dirs
        dirnames[:] = [d for d in dirnames if not d.startswith('.') and d not in ["node_modules", "venv", "env", "dist", "build"]]
        for f in filenames:
            file_path = Path(dirpath) / f
            if file_path.suffix in [".java", ".cpp", ".cc", ".cxx", ".rs", ".cs", ".h", ".hpp"]:
                ts_suspects = ts_scanner.scan_file(file_path)
                for suspect in ts_suspects:
                    algo = suspect.pattern_matched
                    hndl = calculate_hndl_score(algo, longevity_years, sensitivity)
                    severity = severity_from_hndl(hndl)
                    
                    scan_res = ScanResult(
                        path=suspect.path,
                        line=suspect.line,
                        rule_id=f"AST-{algo.upper().replace(' ', '-')[:20]}",
                        message=f"AST detected PQC vulnerability: {algo}",
                        severity=severity,
                        algorithm=algo,
                        pqc_recommendation="Migrate to PQC-compliant libraries (e.g., ring, BouncyCastle PQC)",
                        hndl_score=hndl,
                        run_id=run_id
                    )
                    results.append(scan_res)
                    
                    # Sync to inventory
                    inventory_item = InventoryItem(
                        id=f"{run_id}:{suspect.path}:{suspect.line}",
                        path=suspect.path,
                        line=suspect.line,
                        name=f"Code Asset ({algo})",
                        category="code",
                        algorithm=algo,
                        is_pqc_vulnerable=True,
                        description=scan_res.message,
                        hndl_score=hndl,
                        risk_level=severity,
                        remediation=scan_res.pqc_recommendation
                    )
                    save_inventory_item(db_path, inventory_item, run_id)

    # Infrastructure (K8s) Scan
    print(f"☸️  Scanning Kubernetes manifests...", file=sys.stderr)
    k8s_suspects = k8s_scanner.scan()
    for suspect in k8s_suspects:
        algo = suspect.pattern_matched
        hndl = calculate_hndl_score(algo, longevity_years, sensitivity)
        severity = severity_from_hndl(hndl)
        
        scan_res = ScanResult(
            path=suspect.path,
            line=suspect.line,
            rule_id=f"INFRA-{algo.upper().replace(' ', '-')[:20]}",
            message=f"Infra PQC vulnerability: {suspect.content_snippet}",
            severity=severity,
            algorithm=algo,
            pqc_recommendation="Update TLS config to PQC-ready groups",
            hndl_score=hndl,
            run_id=run_id
        )
        results.append(scan_res)
    
    # Also sync K8s findings to inventory
    for item in k8s_scanner.get_inventory():
        save_inventory_item(db_path, item, run_id)
    
    return results, run_id


def output_table(results: List[ScanResult], summary: ScanSummary):
    """Output results as a formatted table"""
    print("\n" + "=" * 80)
    print("LatticeGuard PQC Assessment Report")
    print("=" * 80)
    
    if not results:
        print("\n✅ No PQC vulnerabilities found!")
    else:
        print(f"\n{'SEVERITY':<10} {'FILE':<40} {'LINE':<6} {'RULE':<20}")
        print("-" * 80)
        
        for r in sorted(results, key=lambda x: SEVERITY_ORDER.get(x.severity, 0), reverse=True):
            sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(r.severity, "⚪")
            path_short = r.path[-38:] if len(r.path) > 40 else r.path
            print(f"{sev_icon} {r.severity:<8} {path_short:<40} {r.line:<6} {r.rule_id:<20}")
    
    print("\n" + "-" * 80)
    print(f"Summary: {summary.total_findings} findings in {summary.total_files} files")
    print(f"  Critical: {summary.critical} | High: {summary.high} | Medium: {summary.medium} | Low: {summary.low}")
    print(f"  Status: {'PASSED ✅' if summary.passed else 'FAILED ❌'}")
    print(f"  Exit Code: {summary.exit_code}")
    print("=" * 80 + "\n")


def output_json(results: List[ScanResult], summary: ScanSummary) -> str:
    """Output results as JSON"""
    return json.dumps({
        "summary": asdict(summary),
        "findings": [asdict(r) for r in results]
    }, indent=2)


def output_sarif(results: List[ScanResult], repo_path: str) -> str:
    """
    Output results in SARIF 2.1.0 format for GitHub Security tab integration.
    """
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "LatticeGuard",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/latticeguard/pqc-assessment",
                    "rules": []
                }
            },
            "results": []
        }]
    }
    
    rules_seen = set()
    
    for r in results:
        # Add rule if not seen
        if r.rule_id not in rules_seen:
            rules_seen.add(r.rule_id)
            sarif["runs"][0]["tool"]["driver"]["rules"].append({
                "id": r.rule_id,
                "name": r.rule_id,
                "shortDescription": {"text": f"PQC Vulnerability: {r.algorithm}"},
                "fullDescription": {"text": r.message},
                "help": {"text": r.pqc_recommendation or "Migrate to PQC-safe algorithms"},
                "defaultConfiguration": {
                    "level": "error" if r.severity in ["critical", "high"] else "warning"
                },
                "properties": {
                    "security-severity": str(SEVERITY_ORDER.get(r.severity, 5) * 2)
                }
            })
        
        # Add result
        sarif["runs"][0]["results"].append({
            "ruleId": r.rule_id,
            "level": "error" if r.severity in ["critical", "high"] else "warning",
            "message": {"text": r.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": r.path,
                        "uriBaseId": "%SRCROOT%"
                    },
                    "region": {
                        "startLine": max(1, r.line)
                    }
                }
            }],
            "properties": {
                "hndl-score": r.hndl_score,
                "algorithm": r.algorithm,
                "pqc-recommendation": r.pqc_recommendation
            }
        })
    
    return json.dumps(sarif, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="LatticeGuard CI/CD Scanner - PQC Vulnerability Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit Codes:
  0 = Pass (no findings above threshold)
  1 = Warnings (findings exist but below threshold)
  2 = Failure (findings at or above threshold)

Examples:
  latticeguard scan ./src --fail-on high
  latticeguard scan ./src --format sarif -o results.sarif
  latticeguard scan ./src --longevity 10 --sensitivity pii
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a repository for PQC vulnerabilities")
    scan_parser.add_argument("path", help="Path to repository or directory to scan")
    scan_parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default="high",
        help="Minimum severity to cause a failure exit code (default: high)"
    )
    scan_parser.add_argument(
        "--format",
        choices=["table", "json", "sarif"],
        default="table",
        help="Output format (default: table)"
    )
    scan_parser.add_argument(
        "-o", "--output",
        help="Output file (default: stdout)"
    )
    scan_parser.add_argument(
        "--longevity",
        type=int,
        default=5,
        help="Data longevity in years for HNDL scoring (default: 5)"
    )
    scan_parser.add_argument(
        "--sensitivity",
        choices=["public", "internal", "confidential", "secret", "pii", "financial", "health"],
        default="internal",
        help="Data sensitivity classification (default: internal)"
    )
    scan_parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode - only output results, no progress"
    )
    scan_parser.add_argument(
        "-c", "--config",
        default=None,
        help="Path to .latticeguard.yaml configuration file"
    )
    
    # Agility command - show algorithm registry
    agility_parser = subparsers.add_parser("agility", help="Show cryptographic agility report")
    agility_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)"
    )
    agility_parser.add_argument(
        "--vulnerable-only",
        action="store_true",
        help="Show only PQC-vulnerable algorithms"
    )
    
    # Discover command
    discover_parser = subparsers.add_parser("discover", help="Discover cryptographic assets in cloud providers")
    discover_parser.add_argument("provider", choices=["aws", "gcp", "azure", "mock"], help="Cloud provider to scan")
    discover_parser.add_argument("--region", help="Cloud region to scan")
    discover_parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    
    # CBOM command - Cryptographic Bill of Materials
    cbom_parser = subparsers.add_parser("cbom", help="Generate Cryptographic Bill of Materials (CycloneDX format)")
    cbom_parser.add_argument("path", help="Path to repository to scan")
    cbom_parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    cbom_parser.add_argument("--format", choices=["json", "cyclonedx"], default="cyclonedx", help="Output format")
    
    # Blast Radius command
    blast_parser = subparsers.add_parser("blast-radius", help="Analyze blast radius of algorithm compromise")
    blast_parser.add_argument("path", help="Path to repository to scan")
    blast_parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    
    # Compliance command
    compliance_parser = subparsers.add_parser("compliance", help="Generate compliance mapping report")
    compliance_parser.add_argument("path", help="Path to repository to scan")
    compliance_parser.add_argument("--framework", choices=["all", "bnm-rmit", "pci-dss", "nist"], default="all", help="Compliance framework")
    compliance_parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    compliance_parser.add_argument("-o", "--output", help="Output file for audit report")
    
    # Temporal Risk command
    temporal_parser = subparsers.add_parser("temporal-risk", help="Calculate time-to-CRQC risk assessment")
    temporal_parser.add_argument("path", help="Path to repository to scan")
    temporal_parser.add_argument("--retention", type=int, default=7, help="Data retention period in years (default: 7)")
    temporal_parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    
    # Migration Effort command
    migration_parser = subparsers.add_parser("migration-effort", help="Estimate PQC migration complexity and effort")
    migration_parser.add_argument("path", help="Path to repository to scan")
    migration_parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    
    # Probe command - TLS/PQC endpoint scanning
    probe_parser = subparsers.add_parser("probe", help="Probe a TLS endpoint for PQC readiness")
    probe_parser.add_argument("url", help="URL or hostname to probe (e.g., https://example.com or example.com)")
    probe_parser.add_argument("--port", type=int, default=443, help="Port to connect to (default: 443)")
    probe_parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    probe_parser.add_argument("-o", "--output", help="Output file path")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
    
    # Handle probe command - TLS/PQC endpoint scanning
    if args.command == "probe":
        from scanner.network import NetworkScanner
        import re
        
        # Parse URL to extract hostname
        url = args.url
        hostname = url
        
        # Remove protocol prefix if present
        if url.startswith("https://"):
            hostname = url[8:]
        elif url.startswith("http://"):
            hostname = url[7:]
        
        # Remove path if present
        hostname = hostname.split("/")[0]
        
        # Remove port if present in hostname
        if ":" in hostname:
            hostname, _ = hostname.rsplit(":", 1)
        
        print(f"🔍 Probing TLS endpoint: {hostname}:{args.port}...", file=sys.stderr)
        
        try:
            scanner = NetworkScanner(hostname, args.port)
            findings = scanner.scan()
            score = scanner.calculate_resilience_score()
            
            if args.format == "json":
                output_data = {
                    "target": f"{hostname}:{args.port}",
                    "quantum_resilience_score": score,
                    "pqc_ready": score >= 70,
                    "status": "PQC-Ready" if score >= 70 else "Partially Ready" if score >= 40 else "Quantum Vulnerable",
                    "findings": [
                        {
                            "name": f.name,
                            "category": f.category,
                            "algorithm": f.algorithm,
                            "key_size": f.key_size,
                            "is_pqc_vulnerable": f.is_pqc_vulnerable,
                            "description": f.description,
                            "remediation": f.remediation
                        }
                        for f in findings
                    ]
                }
                output_content = json.dumps(output_data, indent=2)
            else:
                lines = [
                    "",
                    "=" * 80,
                    "LatticeGuard TLS/PQC Endpoint Scan",
                    f"Target: {hostname}:{args.port}",
                    "=" * 80,
                    ""
                ]
                
                for f in findings:
                    severity_icon = "🔴" if f.category == "critical" else "🟠" if f.category == "high" else "🟡" if f.category == "medium" else "🟢"
                    lines.append(f"{severity_icon} [{f.category.upper()}] {f.name}")
                    lines.append(f"   Algorithm: {f.algorithm}")
                    lines.append(f"   Key Size: {f.key_size}")
                    lines.append(f"   PQC Vulnerable: {f.is_pqc_vulnerable}")
                    lines.append(f"   Description: {f.description}")
                    if f.remediation:
                        lines.append(f"   Remediation: {f.remediation}")
                    lines.append("")
                
                lines.append("=" * 80)
                lines.append(f"QUANTUM RESILIENCE SCORE: {score}/100")
                if score >= 70:
                    lines.append("Status: ✅ PQC-Ready")
                elif score >= 40:
                    lines.append("Status: 🟡 Partially Ready")
                else:
                    lines.append("Status: 🔴 Quantum Vulnerable")
                lines.append("=" * 80)
                lines.append("")
                
                output_content = "\n".join(lines)
            
            if args.output:
                with open(args.output, "w") as f:
                    f.write(output_content)
                print(f"✅ Report written to {args.output}", file=sys.stderr)
            else:
                print(output_content)
            
            # Exit with appropriate code based on score
            if score >= 70:
                sys.exit(0)  # PQC-Ready
            elif score >= 40:
                sys.exit(1)  # Partially Ready (warning)
            else:
                sys.exit(2)  # Quantum Vulnerable (failure)
                
        except Exception as e:
            print(f"❌ Error scanning {hostname}:{args.port}: {e}", file=sys.stderr)
            sys.exit(2)
    
    # Handle discover command
    if args.command == "discover":
        manager = CloudDiscoveryManager(args.provider, args.region)
        print(f"🌐 Discovering assets in {args.provider}...", file=sys.stderr)
        assets = manager.discover()
        
        run_id = datetime.now().strftime("cloud-%Y%m%d-%H%M")
        db_path = "data/pqc.db"
        init_db(db_path)
        
        for asset in assets:
            save_inventory_item(db_path, asset, run_id)
            
        if args.format == "json":
            print(json.dumps([asdict(a) for a in assets], indent=2))
        else:
            print(f"\n✅ Discovered {len(assets)} assets in {args.provider}")
            print("-" * 50)
            for a in assets:
                print(f"[{a.category.upper()}] {a.name} ({a.algorithm})")
            print("-" * 50 + "\n")
        sys.exit(0)
    
    # Handle agility command
    if args.command == "agility":
        import sqlite3
        # Check multiple possible database paths
        possible_paths = [
            os.environ.get("DATABASE_URL", "").replace("sqlite:///", ""),
            "data/pqc.db",
            "data/pqc_assessment.db",
            "/app/data/pqc.db"
        ]
        db_path = None
        for p in possible_paths:
            if p and os.path.exists(p):
                db_path = p
                break
        
        if not db_path:
            print("Error: Database not found. Run a scan first.", file=sys.stderr)
            sys.exit(1)

        
        try:
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute("""
                SELECT algorithm, COUNT(*) as count, 
                       GROUP_CONCAT(DISTINCT path) as locations,
                       MAX(CASE WHEN is_pqc_vulnerable = 1 THEN 1 ELSE 0 END) as is_vulnerable
                FROM inventory 
                WHERE algorithm IS NOT NULL AND algorithm != ''
                GROUP BY algorithm
                ORDER BY count DESC
            """)
            
            algorithms = []
            for row in c.fetchall():
                algo, count, locations, is_vuln = row
                algo_upper = (algo or "").upper()
                is_quantum_safe = any(tag in algo_upper for tag in ["KYBER", "DILITHIUM", "ML-KEM", "ML-DSA", "AES", "SHA-256", "SHA-384", "SHA-512"])
                
                if args.vulnerable_only and not is_vuln:
                    continue
                    
                algorithms.append({
                    "algorithm": algo,
                    "count": count,
                    "locations": (locations or "").split(",")[:3],
                    "vulnerable": bool(is_vuln),
                    "quantum_safe": is_quantum_safe,
                    "priority": "critical" if count > 10 and is_vuln else "high" if count > 5 and is_vuln else "medium" if is_vuln else "low"
                })
            conn.close()
            
            if args.format == "json":
                print(json.dumps({"algorithms": algorithms, "total": len(algorithms)}, indent=2))
            else:
                print("\n" + "=" * 80)
                print("🔐 LatticeGuard Cryptographic Agility Report")
                print("=" * 80 + "\n")
                
                if not algorithms:
                    print("No algorithms found. Run a scan first.")
                else:
                    print(f"{'ALGORITHM':<30} {'COUNT':<8} {'VULNERABLE':<12} {'PRIORITY':<10}")
                    print("-" * 70)
                    for a in algorithms:
                        vuln_icon = "🔴 YES" if a["vulnerable"] else "🟢 NO"
                        print(f"{a['algorithm']:<30} {a['count']:<8} {vuln_icon:<12} {a['priority']:<10}")
                    
                    print("\n" + "-" * 70)
                    vuln_count = sum(1 for a in algorithms if a["vulnerable"])
                    print(f"Total: {len(algorithms)} unique algorithms, {vuln_count} PQC-vulnerable")
                print("=" * 80 + "\n")
                
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)
    
    # Handle report command
    if args.command == "report":
        import sqlite3
        import requests
        
        api_url = os.environ.get("API_URL", "http://localhost:8000")
        job_id = args.job_id
        
        # If no job ID, try to get the latest completed job
        if not job_id:
            try:
                resp = requests.get(f"{api_url}/jobs", timeout=5)
                jobs = resp.json()
                completed = [j for j in jobs if j.get("status") == "completed"]
                if completed:
                    job_id = completed[0].get("job_id")
            except:
                pass
        
        if not job_id:
            print("Error: No job ID specified and no completed jobs found.", file=sys.stderr)
            print("Usage: latticeguard report cbom --job-id <JOB_ID>", file=sys.stderr)
            sys.exit(1)
        
        try:
            if args.type == "cbom":
                resp = requests.get(f"{api_url}/reports/cbom/{job_id}", timeout=10)
                output = json.dumps(resp.json(), indent=2)
            elif args.type == "graph":
                resp = requests.get(f"{api_url}/reports/{job_id}/graph", timeout=10)
                output = json.dumps(resp.json(), indent=2)
            elif args.type == "summary":
                resp = requests.get(f"{api_url}/scans/{job_id}", timeout=10)
                data = resp.json()
                output = json.dumps({
                    "job_id": job_id,
                    "status": data.get("status"),
                    "findings_count": len(data.get("findings", [])),
                    "findings": data.get("findings", [])[:10]  # First 10
                }, indent=2)
            
            if args.output:
                with open(args.output, "w") as f:
                    f.write(output)
                print(f"Report written to {args.output}", file=sys.stderr)
            else:
                print(output)
                
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)
    
    # Handle CBOM command
    if args.command == "cbom":
        from schemas.cbom import CBOM, CBOMMetadata, generate_cbom_from_findings
        
        print(f"📜 Generating CBOM for {args.path}...", file=sys.stderr)
        results, run_id = scan_repository(args.path)
        
        findings = [{"path": r.path, "algorithm": r.algorithm, "rule_id": r.rule_id, 
                     "is_pqc": r.severity in ["critical", "high"]} for r in results]
        
        cbom = generate_cbom_from_findings(run_id, args.path, findings)
        
        if args.format == "cyclonedx":
            output_content = json.dumps(cbom.to_cyclonedx(), indent=2)
        else:
            output_content = json.dumps(cbom.model_dump(), indent=2)
        
        if args.output:
            with open(args.output, "w") as f:
                f.write(output_content)
            print(f"✅ CBOM written to {args.output}", file=sys.stderr)
        else:
            print(output_content)
        
        sys.exit(0)
    
    # Handle Blast Radius command
    if args.command == "blast-radius":
        from risk.blast_radius import BlastRadiusAnalyzer
        
        print(f"💥 Analyzing blast radius for {args.path}...", file=sys.stderr)
        results, run_id = scan_repository(args.path)
        
        analyzer = BlastRadiusAnalyzer()
        for r in results:
            analyzer.add_finding(r.algorithm or "Unknown", r.path, r.line, r.message, r.severity)
        
        report = analyzer.analyze()
        
        if args.format == "json":
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(analyzer.format_summary(report))
        
        sys.exit(0)
    
    # Handle Compliance command
    if args.command == "compliance":
        from risk.compliance import ComplianceMapper
        
        print(f"📋 Generating compliance report for {args.path}...", file=sys.stderr)
        results, run_id = scan_repository(args.path)
        
        mapper = ComplianceMapper()
        findings = [{"rule_id": r.rule_id, "algorithm": r.algorithm, "path": r.path} for r in results]
        audit_report = mapper.generate_audit_report(findings)
        
        if args.format == "json":
            output_content = json.dumps(audit_report, indent=2)
        else:
            print("\n" + "=" * 80)
            print("COMPLIANCE AUDIT REPORT")
            print("=" * 80)
            print(f"Generated: {audit_report['generated_at']}")
            print(f"Total Findings: {audit_report['total_findings']}")
            print(f"Frameworks Affected: {', '.join(audit_report['frameworks_affected'])}")
            print(f"Requirements Violated: {audit_report['requirements_violated']}")
            print("-" * 80)
            
            for framework, items in audit_report['by_framework'].items():
                print(f"\n📋 {framework}")
                for item in items[:5]:  # Show top 5 per framework
                    print(f"   [{item['requirement_id']}] {item['title']}")
                    print(f"      File: {item['file']}")
                if len(items) > 5:
                    print(f"   ... and {len(items) - 5} more")
            
            print("=" * 80 + "\n")
            output_content = None
        
        if output_content:
            if args.output:
                with open(args.output, "w") as f:
                    f.write(output_content)
                print(f"✅ Report written to {args.output}", file=sys.stderr)
            else:
                print(output_content)
        
        sys.exit(0)
    
    # Handle Temporal Risk command
    if args.command == "temporal-risk":
        from risk.assessor import calculate_temporal_risk, CRQC_ESTIMATE_YEAR, CRQC_UNCERTAINTY_YEARS
        
        print(f"⏰ Calculating temporal risk for {args.path}...", file=sys.stderr)
        results, run_id = scan_repository(args.path)
        
        temporal_results = []
        for r in results:
            if r.severity in ["critical", "high"]:
                tr = calculate_temporal_risk(r.algorithm or "", args.retention)
                temporal_results.append({
                    "path": r.path,
                    "algorithm": r.algorithm,
                    "temporal_risk": tr
                })
        
        if args.format == "json":
            print(json.dumps(temporal_results, indent=2))
        else:
            print("\n" + "=" * 80)
            print("TEMPORAL RISK ASSESSMENT (Time-to-CRQC)")
            print("=" * 80)
            print(f"CRQC Estimate: {CRQC_ESTIMATE_YEAR} (±{CRQC_UNCERTAINTY_YEARS} years)")
            print(f"Data Retention: {args.retention} years")
            print("-" * 80)
            
            for tr in temporal_results:
                urgency = tr['temporal_risk']['urgency'].upper()
                icon = "🔴" if urgency == "CRITICAL" else "🟠" if urgency == "HIGH" else "🟡" if urgency == "MEDIUM" else "🟢"
                print(f"\n{icon} {tr['algorithm']} - {urgency}")
                print(f"   File: {tr['path']}")
                print(f"   Years to Act: {tr['temporal_risk']['years_to_act']}")
                print(f"   Exposure Window: {tr['temporal_risk']['data_exposure_window_years']} years")
                print(f"   Recommendation: {tr['temporal_risk']['recommendation']}")
            
            print("=" * 80 + "\n")
        
        sys.exit(0)
    
    # Handle Migration Effort command
    if args.command == "migration-effort":
        from risk.migration_estimator import MigrationEstimator
        
        print(f"📊 Estimating migration effort for {args.path}...", file=sys.stderr)
        results, run_id = scan_repository(args.path)
        
        estimator = MigrationEstimator()
        findings = [{"rule_id": r.rule_id} for r in results]
        total_effort = estimator.total_effort(findings)
        
        estimates = []
        for r in results:
            est = estimator.estimate(r.rule_id, r.algorithm)
            estimates.append({
                "path": r.path,
                "rule_id": r.rule_id,
                "complexity": est.complexity.value,
                "hours": est.estimated_hours,
                "action": est.recommended_action,
                "pqc_alternative": est.pqc_alternative
            })
        
        if args.format == "json":
            print(json.dumps({"total": total_effort, "estimates": estimates}, indent=2))
        else:
            print("\n" + "=" * 80)
            print("PQC MIGRATION EFFORT ESTIMATE")
            print("=" * 80)
            print(f"Total Findings: {total_effort['finding_count']}")
            print(f"Estimated Hours: {total_effort['total_hours']:.1f}")
            print(f"Developer Days: {total_effort['total_developer_days']}")
            print("-" * 80)
            print("By Complexity:")
            for complexity, count in total_effort['by_complexity'].items():
                if count > 0:
                    print(f"   {complexity.upper()}: {count} items")
            print("-" * 80)
            
            for est in estimates[:10]:  # Show top 10
                print(f"\n[{est['complexity'].upper()}] {est['rule_id']} - {est['hours']}h")
                print(f"   File: {est['path']}")
                print(f"   Action: {est['action']}")
                if est['pqc_alternative']:
                    print(f"   PQC: {est['pqc_alternative']}")
            
            if len(estimates) > 10:
                print(f"\n... and {len(estimates) - 10} more items")
            
            print("=" * 80 + "\n")
        
        sys.exit(0)
    
    # Handle scan command
    if args.command != "scan":
        parser.print_help()
        sys.exit(0)
    
    # Run scan
    results, run_id = scan_repository(args.path, args.longevity, args.sensitivity, args.config)
    
    # Count severities
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in results:
        if r.severity in counts:
            counts[r.severity] += 1
    
    # Determine pass/fail
    fail_threshold = SEVERITY_ORDER[args.fail_on]
    has_blocking = any(SEVERITY_ORDER.get(r.severity, 0) >= fail_threshold for r in results)
    
    if not results:
        exit_code = 0
        passed = True
    elif has_blocking:
        exit_code = 2
        passed = False
    else:
        exit_code = 1
        passed = True
    
    summary = ScanSummary(
        total_files=len(set(r.path for r in results)),
        total_findings=len(results),
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        passed=passed,
        exit_code=exit_code,
        run_id=run_id
    )
    
    # Generate output
    if args.format == "table":
        output_table(results, summary)
        output_content = None
    elif args.format == "json":
        output_content = output_json(results, summary)
    elif args.format == "sarif":
        output_content = output_sarif(results, args.path)
    
    # Write output
    if output_content:
        if args.output:
            with open(args.output, "w") as f:
                f.write(output_content)
            print(f"Results written to {args.output}", file=sys.stderr)
        else:
            print(output_content)
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
