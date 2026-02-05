import os
import sqlite3
import json
import google.generativeai as genai
from typing import List, Optional
from schemas.models import InventoryItem

class FileAnalystAgent:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.flash_model_name = os.getenv("GEMINI_FLASH_MODEL", "gemini-3-flash-preview")
        self.pro_model_name = os.getenv("GEMINI_PRO_MODEL", "gemini-3-pro-preview")
        self.api_key = os.getenv("GEMINI_API_KEY")
        
        if self.api_key:
            genai.configure(api_key=self.api_key)
        else:
            print("Warning: GEMINI_API_KEY not set. AI analysis will fail.")

    def analyze_file_tiered(self, file_path: str, suspects: List[object], run_id: str):
        """
        Tiered Analysis:
        1. Fast Check (Flash) -> Is this strictly Cryptographic?
        2. Deep Audit (Pro) -> Extract details and assess PQC risk.
        """
        if not suspects:
            return

        # Prepare Context
        # We assume suspects contains snippets. We can verify if we need to read the full file.
        # For cost saving, let's just use the snippets combined.
        snippets = "\n".join([f"Line {s.line}: {s.content_snippet}" for s in suspects])
        context = f"File: {file_path}\nTarget Pattern Matches:\n{snippets}"

        # --- TIER 1: FLASH ---
        is_relevant = self._ask_flash_triage(context)
        if not is_relevant:
            print(f"⚡️ [Flash] Dismissed {file_path} as non-crypto/irrelevant.")
            return

        print(f"🧠 [Flash] Flagged {file_path}. Escalating to Pro...")

        # --- TIER 2: PRO ---
        # We might want to read the FULL file content here for the Pro model to have full context.
        # But for large files, that's risky. Let's stick to snippets + some window for now.
        full_analysis = self._ask_pro_deep_dive(context)
        
        if full_analysis:
             self._save_results(file_path, run_id, full_analysis)

    def _ask_flash_triage(self, context: str) -> bool:
        """Returns True if the content looks like relevant cryptography."""
        prompt = f"""
        You are a fast security filter.
        Analyze these code snippets. Do they contain ACTUAL cryptographic operations, key material, or security configurations?
        
        Ignore:
        - Comments, Tests, Documentation
        - Generic variable names like 'key' or 'random' without context
        - HTML/CSS
        
        Context:
        {context}
        
        Reply strictly valid JSON: {{"is_relevant": true}} or {{"is_relevant": false}}
        """
        try:
            model = genai.GenerativeModel(self.flash_model_name)
            response = model.generate_content(prompt, generation_config={"response_mime_type": "application/json"})
            res_json = json.loads(response.text)
            return res_json.get("is_relevant", False)
        except Exception as e:
            print(f"Tier 1 Error: {e}")
            return True # Fail open (escalate to Pro if Flash fails)

    def _ask_pro_deep_dive(self, context: str) -> List[InventoryItem]:
        """Returns detailed inventory items."""
        prompt = f"""
        You are a Senior Cryptography Auditor.
        Analyze the following technical artifacts.
        
        {context}
        
        Task:
        1. Identify the Algorithm (e.g. RSA-2048, AES-GCM, ECDSA-P256).
        2. Assess Quantum Vulnerability (Shor/Grover).
           - VULNERABLE: RSA, DH, ECC, DSA
           - SAFE: AES-256, SHA-3, Kyber, Dilithium
        3. Extract Key Size if visible.
        
        Output JSON List:
        [
            {{
                "name": "RSA Key Pair",
                "category": "pki",
                "algorithm": "RSA",
                "key_size": 2048,
                "is_pqc_vulnerable": true,
                "line": 45,
                "reasoning": "Found standard PEM header"
            }}
        ]
        """
        try:
            model = genai.GenerativeModel(self.pro_model_name)
            response = model.generate_content(prompt, generation_config={"response_mime_type": "application/json"})
            return json.loads(response.text)
        except Exception as e:
             print(f"Tier 2 Error: {e}")
             return []

    def _save_results(self, file_path, run_id, items):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        for item in items:
            # Generate a unique ID for the finding
            finding_id = f"{file_path}:{item.get('line', 0)}:{item.get('algorithm')}"
            
            c.execute('''
            INSERT OR REPLACE INTO inventory (id, path, line, name, category, algorithm, key_size, is_pqc_vulnerable, description, run_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                finding_id, 
                str(file_path), 
                item.get('line', 0), 
                item.get('name', 'Unknown'), 
                item.get('category', 'other'), 
                item.get('algorithm', 'Unknown'), 
                item.get('key_size', 0), 
                item.get('is_pqc_vulnerable', False), 
                item.get('reasoning', ''), 
                run_id
            ))
        
        conn.commit()
        conn.close()
