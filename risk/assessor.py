"""
LatticeGuard - Post-Quantum Cryptography Assessment Tool
Copyright (c) 2026 Waqas Khalid Obeidy
"""

import sqlite3
import json
from typing import List, Dict
from pathlib import Path
from schemas.models import RiskAssessment, InventoryItem
from agents.remediation import RemediationAgent
from risk.blast_radius import BlastRadiusAnalyzer
from risk.migration_estimator import MigrationEstimator
from risk.compliance import ComplianceMapper


# Temporal Risk Scoring Constants
CRQC_ESTIMATE_YEAR = 2028  # Estimated year for Cryptographically Relevant Quantum Computer
CRQC_UNCERTAINTY_YEARS = 3  # ±3 years uncertainty window

# Algorithm-specific threat timelines (years until critical)
ALGORITHM_THREAT_TIMELINE = {
    "RSA-1024": 0,    # Already weak, immediate risk
    "RSA-2048": 5,    # Moderate buffer
    "RSA-3072": 8,    # Better margin
    "RSA-4096": 10,   # Longer runway
    "ECDSA-256": 5,   # Similar to RSA-2048
    "ECDSA-384": 7,
    "ECDSA-521": 8,
    "DH-2048": 5,
    "DSA": 0,         # Deprecated
    "MD5": 0,         # Already broken
    "SHA1": 0,        # Deprecated for signatures
}


def calculate_temporal_risk(algorithm: str, data_retention_years: int = 7) -> dict:
    """
    Calculate temporal risk based on algorithm and data retention requirements.
    
    Args:
        algorithm: The cryptographic algorithm in use
        data_retention_years: How long the data must be protected
    
    Returns:
        Temporal risk assessment with CRQC timeline
    """
    current_year = 2026
    crqc_earliest = CRQC_ESTIMATE_YEAR - CRQC_UNCERTAINTY_YEARS
    crqc_latest = CRQC_ESTIMATE_YEAR + CRQC_UNCERTAINTY_YEARS
    
    # Calculate years until data expires
    data_expiry_year = current_year + data_retention_years
    
    # Check if data will still be sensitive when CRQC arrives
    years_at_risk = max(0, data_expiry_year - crqc_earliest)
    
    # Determine algorithm-specific threat adjustment
    algo_upper = algorithm.upper() if algorithm else ""
    algo_buffer = 5  # Default buffer
    for pattern, buffer in ALGORITHM_THREAT_TIMELINE.items():
        if pattern in algo_upper:
            algo_buffer = buffer
            break
    
    # Calculate urgency
    effective_years_to_act = crqc_earliest - current_year - (data_retention_years - algo_buffer)
    
    if effective_years_to_act <= 0:
        urgency = "critical"
    elif effective_years_to_act <= 2:
        urgency = "high"
    elif effective_years_to_act <= 5:
        urgency = "medium"
    else:
        urgency = "low"
    
    return {
        "crqc_eta": f"{CRQC_ESTIMATE_YEAR} (±{CRQC_UNCERTAINTY_YEARS} years)",
        "crqc_earliest": crqc_earliest,
        "crqc_latest": crqc_latest,
        "data_expiry_year": data_expiry_year,
        "data_exposure_window_years": years_at_risk,
        "years_to_act": max(0, effective_years_to_act),
        "urgency": urgency,
        "recommendation": _get_temporal_recommendation(urgency, years_at_risk)
    }


def _get_temporal_recommendation(urgency: str, years_at_risk: int) -> str:
    """Get action recommendation based on urgency."""
    if urgency == "critical":
        return "Immediate migration required. Data will be at risk before CRQC arrival."
    elif urgency == "high":
        return "Begin migration planning now. Limited runway before data exposure."
    elif urgency == "medium":
        return "Schedule migration in next planning cycle. Monitor CRQC developments."
    else:
        return "Low priority. Continue monitoring quantum computing advances."


class RiskAssessor:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.remediator = RemediationAgent()

    def assess_risk(self, run_id: str, output_dir: Path):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # 1. Fetch Fast Scan Results (Suspects)
        c.execute("SELECT count(*) as count FROM suspects WHERE run_id = ?", (run_id,))
        fast_scan_count = c.fetchone()['count']
        
        c.execute("SELECT * FROM suspects WHERE run_id = ? LIMIT 50", (run_id,))
        suspects_top = c.fetchall()
        
        # 2. Fetch AI Verified Findings (Inventory)
        c.execute("SELECT * FROM inventory WHERE run_id = ?", (run_id,))
        rows = c.fetchall()
        conn.close()
        
        # Process Inventory
        risks = []
        high_risk_findings = []
        
        for row in rows:
            level = "low"
            if row['is_pqc_vulnerable']:
                level = "high"
            elif row['category'] == 'safe' or row['algorithm'] == 'None':
                level = "safe"
            elif row['category'] in ['hashing', 'symmetric']:
                level = "low"
            
            item = InventoryItem(
                id=row['id'],
                path=row['path'],
                line=row['line'],
                name=row['name'],
                category=row['category'],
                algorithm=row['algorithm'],
                key_size=row['key_size'],
                is_pqc_vulnerable=row['is_pqc_vulnerable'],
                description=row['description'],
                remediation=None 
            )
            
            if level == "high":
                high_risk_findings.append(item)
            
            risk = {
                "id": row['id'],
                "path": row['path'],
                "line": row['line'],
                "algo": row['algorithm'],
                "level": level,
                "desc": row['description'],
                "item": item
            }
            risks.append(risk)

        # 3. Generate Remediation Suggestions
        remediations = self.remediator.process_findings(high_risk_findings)

        # Generate Reports
        self._generate_markdown(risks, suspects_top, fast_scan_count, remediations, output_dir / "pqc_risk_report.md", run_id)
        self._generate_sarif(risks, output_dir / "pqc_scan.sarif", run_id)
    
    def _generate_markdown(self, risks: List[Dict], suspects: List[sqlite3.Row], suspect_total: int, remediations: List[dict], path: Path, run_id: str):
        content = f"# PQC Risk Assessment Report\n\n**Run ID:** {run_id}\n\n"
        
        high_risks = [r for r in risks if r['level'] in ['high', 'critical']]
        safe_findings = [r for r in risks if r['level'] == 'safe']
        
        # --- 1. Executive Summary ---
        content += "## 1. Executive Summary\n"
        content += f"- **Quantum-Vulnerable Assets (AI Verified):** {len(high_risks)}\n"
        content += f"- **Verified Safe / Non-Critical:** {len(safe_findings)}\n"
        content += f"- **Total Suspicious Files (Fast Scan):** {suspect_total}\n\n"
        
        # --- 2. Cost Analysis ---
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT SUM(input_tokens), SUM(output_tokens), SUM(cost_usd) FROM scan_metrics WHERE run_id = ?", (run_id,))
        row = c.fetchone()
        conn.close()
        
        in_tok = row[0] or 0
        out_tok = row[1] or 0
        total_cost = row[2] or 0.0
        
        content += "### AI Usage & Cost\n"
        content += f"- **Total Cost:** ${total_cost:.4f}\n"
        content += f"- **Tokens:** {in_tok:,} In / {out_tok:,} Out\n\n"

        # --- 3. AI Verified Risks (Inventory) ---
        content += "## 2. AI Verified Risks (Inventory)\n"
        if not high_risks:
            content += "No cryptographic assets confirmed by AI analysis.\n\n"
        else:
            for r in high_risks:
                 content += f"- 🔴 **{r['algo']}** in `{r['path']}:{r['line']}`\n"
                 content += f"  - Context: {r['desc']}\n"
            content += "\n"

        # --- 4. Remediation & Migration Plans ---
        content += "## 3. Remediation Recommendations\n"
        content += "*AI-generated migration paths for detected PQC vulnerabilities.*\n\n"
        if not remediations:
            content += "No high-risk vulnerabilities requiring immediate remediation were identified.\n\n"
        else:
            for rem in remediations:
                content += f"### Mitigation: {rem['item']} (`{rem['path']}`)\n"
                content += f"{rem['remediation']}\n\n"
            content += "---\n\n"

        # --- 5. AI Verified Safe / Dismissed ---
        content += "## 4. AI Verified Safe / Dismissed\n"
        content += "*Files that were flagged by scanners but cleared by AI analysis.*\n\n"
        if not safe_findings:
            content += "No files were explicitly dismissed as safe (or no suspects were found).\n\n"
        else:
            for r in safe_findings:
                content += f"- 🟢 **{r['desc']}**\n"
                content += f"  - File: `{r['path']}`\n"
            content += "\n"

        # --- 6. Fast Scan Findings (Raw) ---
        content += f"## 5. Fast Scan Findings (Raw Suspects: Top {len(suspects)})\n"
        content += "*Files flagged by pattern/extension matching before AI analysis.*\n\n"
        
        if not suspects:
            content += "No suspects found.\n"
        else:
            content += "| File Path | Pattern | Confidence |\n"
            content += "| --- | --- | --- |\n"
            for s in suspects:
                # Truncate path if too long
                short_path = s['path'][-60:] if len(s['path']) > 60 else s['path']
                content += f"| `...{short_path}` | `{s['pattern_matched']}` | {s['confidence']} |\n"
        
        with open(path, "w") as f:
            f.write(content)

    def _generate_sarif(self, risks: List[Dict], path: Path, run_id: str):
        rules = [
            {
                "id": "PQC-001",
                "name": "QuantumVulnerableAlgorithm",
                "shortDescription": {"text": "Algorithm vulnerable to quantum attacks"},
                "defaultConfiguration": {"level": "error"}
            }
        ]
        
        results = []
        for r in risks:
            if r['level'] == 'high':
                results.append({
                    "ruleId": "PQC-001",
                    "level": "error",
                    "message": {"text": f"Found vulnerable {r['algo']}: {r['desc']}"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": r['path']},
                            "region": {"startLine": int(r['line']) if r['line'] else 1}
                        }
                    }]
                })
        
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "PQC-Scanner",
                        "rules": rules
                    }
                },
                "results": results
            }]
        }
        
        with open(path, "w") as f:
            json.dump(sarif, f, indent=2)
