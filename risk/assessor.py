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
        
        # 1. Fetch Fast Scan Results (Suspects)
        c.execute("SELECT count(*) as count FROM suspects WHERE run_id = ?", (run_id,))
        fast_scan_count = c.fetchone()['count']
        
        c.execute("SELECT * FROM suspects WHERE run_id = ? LIMIT 50", (run_id,)) # Limit for readability in report
        suspects_top = c.fetchall()
        
        # 2. Fetch AI Verified Findings (Inventory)
        c.execute("SELECT * FROM inventory WHERE run_id = ?", (run_id,))
        rows = c.fetchall()
        conn.close()
        
        # Process Inventory
        risks = []
        high_risk_count = 0
        for row in rows:
            level = "low"
            if row['is_pqc_vulnerable']:
                level = "high"
                high_risk_count += 1
            elif row['category'] in ['hashing', 'symmetric']:
                level = "low"
            
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
        self._generate_markdown(risks, suspects_top, fast_scan_count, output_dir / "pqc_risk_report.md", run_id)
        self._generate_sarif(risks, output_dir / "pqc_scan.sarif", run_id)
    
    def _generate_markdown(self, risks: List[Dict], suspects: List[sqlite3.Row], suspect_total: int, path: Path, run_id: str):
        content = f"# PQC Risk Assessment Report\n\n**Run ID:** {run_id}\n\n"
        
        high_risks = [r for r in risks if r['level'] in ['high', 'critical']]
        
        # --- 1. Executive Summary ---
        content += "## 1. Executive Summary\n"
        content += f"- **Quantum-Vulnerable Assets (AI Verified):** {len(high_risks)}\n"
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

        # --- 3. AI Scan Results (Inventory) ---
        content += "## 2. AI Verified Risks (Inventory)\n"
        if not risks:
            content += "No cryptographic assets confirmed by AI analysis.\n\n"
        else:
            for r in risks:
                 icon = "🔴" if r['level'] == "high" else "🟢"
                 content += f"- {icon} **{r['algo']}** in `{r['path']}:{r['line']}`\n"
                 content += f"  - Context: {r['desc']}\n"
            content += "\n"

        # --- 4. Fast Scan Results (Raw) ---
        content += f"## 3. Fast Scan Findings (Raw Suspects: Top {len(suspects)})\n"
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
