"""
LatticeGuard - Post-Quantum Cryptography Assessment Tool
Copyright (c) 2026 Waqas Khalid Obeidy
"""

from typing import List, Optional
import json
from pathlib import Path
from backend.ai_client import AIClient
from schemas.models import InventoryItem

class RemediationAgent:
    def __init__(self):
        self.ai = AIClient()

    def suggest_fix(self, item: InventoryItem, file_content: str) -> str:
        """
        Queries Gemini to suggest a PQC-safe remediation for a finding.
        """
        prompt = f"""
        You are a Post-Quantum Cryptography Migration Expert.
        
        A vulnerability has been identified:
        Algorithm: {item.algorithm} (Vulnerable: {item.is_pqc_vulnerable})
        Location: {item.path}:{item.line}
        
        Context Code:
        {file_content}

        Task:
        1. Explain why this algorithm is vulnerable to Quantum computers.
        2. Provide a specific, drop-in code replacement or a migration path to a PQC-safe algorithm.
        3. If it's a symmetric algorithm like AES-128, suggest upgrading to AES-256.

        Return a JSON object with the following structure:
        {{
            "migration_plan": "Detailed explanation and migration steps...",
            "code_suggestion": "The actual code snippet for replacement..."
        }}
        """
        
        try:
            response_json, _ = self.ai.generate_json(prompt, model_name=self.ai.default_pro_model)
            
            # Format as Markdown for the report
            md_output = f"#### Migration Plan\n{response_json.get('migration_plan', 'No plan provided.')}\n\n"
            md_output += f"#### Code Suggestion\n```\n{response_json.get('code_suggestion', 'No code provided.')}\n```"
            
            return md_output
        except Exception as e:
            return f"Error generating remediation: {e}"

    def process_findings(self, findings: List[InventoryItem]) -> List[dict]:
        results = []
        for item in findings:
            if not item.is_pqc_vulnerable:
                continue
                
            try:
                with open(item.path, 'r', errors='ignore') as f:
                    content = f.read()
                
                # Extract relevant context (e.g. 20 lines around the finding)
                lines = content.splitlines()
                start = max(0, item.line - 10)
                end = min(len(lines), item.line + 10)
                context = "\n".join(lines[start:end])
                
                fix_suggestion = self.suggest_fix(item, context)
                results.append({
                    "item": item.name,
                    "path": item.path,
                    "remediation": fix_suggestion
                })
            except Exception as e:
                print(f"Error generating remediation for {item.path}: {e}")
                
        return results
