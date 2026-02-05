import sqlite3
import json
from typing import List, Dict
from pathlib import Path
from schemas.models import RiskAssessment

class RiskAssessor:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def assess_risk(self, run_id: str, output_dir: Path):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute("SELECT * FROM inventory WHERE run_id = ?", (run_id,))
        rows = c.fetchall()
        
        risks = []
        high_risk_count = 0
        
        for row in rows:
            # Logic: If is_pqc_vulnerable, it's High/Critical
            # If symmetric/hash, it's Low/Info
            
            level = "low"
            if row['is_pqc_vulnerable']:
                level = "high"
                high_risk_count += 1
            elif row['category'] in ['hashing', 'symmetric']:
                level = "low"
            
            # Simple assessment for MVP
            risk = {
                "id": row['id'],
                "path": row['path'],
                "line": row['line'],
                "algo": row['algorithm'],
                "level": level,
                "desc": row['description']
            }
            risks.append(risk)

        # Generate Reports
        self._generate_markdown(risks, output_dir / "pqc_risk_report.md", run_id)
        self._generate_sarif(risks, output_dir / "pqc_scan.sarif", run_id)
        
        conn.close()

    def _generate_markdown(self, risks: List[Dict], path: Path, run_id: str):
        content = f"# PQC Risk Assessment Report\n\n**Run ID:** {run_id}\n\n"
        
        high_risks = [r for r in risks if r['level'] in ['high', 'critical']]
        content += f"## Executive Summary\nFound **{len(high_risks)}** high-risk Quantum-Vulnerable assets.\n\n"
        
        content += "## Top Hotspots\n"
        for r in high_risks:
            content += f"- **{r['algo']}** in `{r['path']}:{r['line']}`\n"
            content += f"  - > {r['desc']}\n\n"
            
        content += "## Inventory\n"
        for r in risks:
             icon = "🔴" if r['level'] == "high" else "🟢"
             content += f"- {icon} [{r['level'].upper()}] {r['algo']} ({r['path']})\n"
             
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
