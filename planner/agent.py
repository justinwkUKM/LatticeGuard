import os
import json
import google.generativeai as genai
from pathlib import Path
from typing import List, Optional
from planner.fingerprint import RepoFingerprinter
from schemas.models import ScanPlan, ScanBudget

class PlannerAgent:
    def __init__(self, model_name: str = "gemini-2.0-flash"):
        self.model_name = model_name
        self.api_key = os.getenv("GOOGLE_API_KEY")
        if self.api_key:
            genai.configure(api_key=self.api_key)
        else:
            print("Warning: GOOGLE_API_KEY not found. Agent will fail if called.")

    def generate_plan(self, 
                      repo_path: str, 
                      run_id: str, 
                      budget: ScanBudget = ScanBudget(),
                      hints: List[str] = []) -> ScanPlan:
        
        # 1. Fingerprint
        fp = RepoFingerprinter(repo_path).fingerprint()
        
        # 2. Construct Prompt
        prompt = f"""
        You are a PQC (Post-Quantum Cryptography) Security Architect.
        Analyze this repository fingerprint and generate a scan strategy.

        Fingerprint:
        {json.dumps(fp, indent=2)}

        Stack Hints: {hints}

        Goal: Identify all cryptographic assets (keys, certs, code, config) to assess Quantum vulnerability.
        
        Output a JSON object satisfying this schema:
        {{
            "run_id": "{run_id}",
            "target_repo": "{repo_path}",
            "strategy": "app|infra|mixed", 
            "prioritized_queues": {{
                "hotspots": ["list of high priority paths/patterns"],
                "neighbors": ["list of secondary paths"],
                "longtail": ["remaining paths"]
            }},
            "budget": {{
                 "max_files": {budget.max_files},
                 "max_depth": {budget.max_depth},
                 "max_file_bytes": {budget.max_file_bytes}
            }}
        }}

        Rules:
        1. If 'infra' tools (terraform, k8s) are present, Strategy MUST be 'infra' or 'mixed'.
        2. 'hotspots' should include standard crypto paths for the detected languages (e.g. 'auth/', 'security/', 'tls/', 'jwt').
        3. Return ONLY valid JSON.
        """

        # 3. Call Gemini
        try:
            model = genai.GenerativeModel(self.model_name)
            response = model.generate_content(prompt, generation_config={"response_mime_type": "application/json"})
            plan_json = json.loads(response.text)
            
            # 4. Validate & Return
            plan = ScanPlan(**plan_json)
            return plan

        except Exception as e:
            print(f"Error generating plan: {e}")
            # Fallback plan if LLM fails
            return ScanPlan(
                run_id=run_id,
                target_repo=repo_path,
                strategy="mixed",
                budget=budget,
                prioritized_queues={
                    "hotspots": ["**/*crypto*", "**/*auth*", "**/*tls*", "**/*ssl*"],
                    "neighbors": ["**/*.py", "**/*.tf", "**/*.yaml"],
                    "longtail": ["**/*"]
                }
            )

if __name__ == "__main__":
    # Test
    agent = PlannerAgent()
    plan = agent.generate_plan(".", "test_run_1")
    print(plan.model_dump_json(indent=2))
