import os
import sqlite3
import json
import google.generativeai as genai
from typing import List, Optional
from schemas.models import InventoryItem

class FileAnalystAgent:
    def __init__(self, db_path: str, model_name: str = "gemini-2.0-flash"):
        self.db_path = db_path
        self.model_name = model_name
        self.api_key = os.getenv("GOOGLE_API_KEY")
        if self.api_key:
            genai.configure(api_key=self.api_key)

    def analyze_suspects(self, run_id: str):
        conn = sqlite3.connect(self.db_path)
        # Enable ROW_FACTORY to get dict-like objects if needed, but tuple is fine
        c = conn.cursor()
        
        # Select suspects for this run that are "code" type or "artifact" (skip deps for deep analysis for now?)
        # Let's analyze everything that isn't already processed. 
        # For simplicity, we just fetch all suspects for the run.
        c.execute("SELECT id, path, line, content_snippet, type FROM suspects WHERE run_id = ?", (run_id,))
        rows = c.fetchall()
        
        if not rows:
            print("No suspects found to analyze.")
            return

        print(f"Analyzing {len(rows)} suspects with Gemini...")
        
        inventory_items = []
        for row in rows:
            s_id, path, line, content, s_type = row
            
            # Context retrieval (mocked for now: using content_snippet)
            # In a real app, we would read the file at 'path' around 'line'
            context = f"File: {path}\nLine: {line}\nContext:\n{content}"
            
            if s_type == "artifact":
                 # Simple heuristic for artifacts, maybe skipping LLM to save cost, 
                 # or use LLM to parse PEM headers. Let's use LLM for uniformity.
                 pass

            analysis = self._ask_gemini(context)
            if analysis and analysis.get("is_crypto"):
                item = InventoryItem(
                    id=f"{path}:{line}",
                    path=path,
                    line=line,
                    name=analysis.get("name", "Unknown"),
                    category=analysis.get("category", "protocol"),
                    algorithm=analysis.get("algorithm"),
                    key_size=analysis.get("key_size"),
                    is_pqc_vulnerable=analysis.get("is_pqc_vulnerable", False),
                    description=analysis.get("reasoning", "")
                )
                inventory_items.append(item)

        # Save to Inventory
        for item in inventory_items:
            c.execute('''
            INSERT OR REPLACE INTO inventory (id, path, line, name, category, algorithm, key_size, is_pqc_vulnerable, description, run_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (item.id, item.path, item.line, item.name, item.category, item.algorithm, item.key_size, item.is_pqc_vulnerable, item.description, run_id))
        
        conn.commit()
        conn.close()

    def _ask_gemini(self, context: str) -> Optional[dict]:
        prompt = f"""
        Analyze this code snippet/artifact for Cryptography.

        {context}

        Task:
        1. Identify if this is a cryptographic operation/asset.
        2. Identify the Algorithm (e.g. RSA, AES, ECDSA).
        3. Identify Key Size if visible.
        4. Determine if it is vulnerable to Quantum Computers (Shor's Algo).
           - RSA, ECC, DH -> Vulnerable (True)
           - AES, SHA, HMAC -> Safe (False)
        
        Output JSON:
        {{
            "is_crypto": true/false,
            "name": "Brief Name",
            "category": "symmetric|hashing|key_exchange|signing|pki|protocol",
            "algorithm": "RSA",
            "key_size": 2048,
            "is_pqc_vulnerable": true,
            "reasoning": "RSA is vulnerable to Shor's algorithm"
        }}
        """
        try:
            model = genai.GenerativeModel(self.model_name)
            response = model.generate_content(prompt, generation_config={"response_mime_type": "application/json"})
            return json.loads(response.text)
        except Exception:
            return None
