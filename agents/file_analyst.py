import os
import sqlite3
import json
from backend.ai_client import AIClient
from typing import List, Optional
from schemas.models import InventoryItem

class FileAnalystAgent:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.flash_model_name = os.getenv("GEMINI_FLASH_MODEL", "gemini-3-flash-preview")
        self.pro_model_name = os.getenv("GEMINI_PRO_MODEL", "gemini-3-pro-preview")
        self.ai = AIClient()
        self.arch_context = ""

    def analyze_suspects(self, run_id: str):
        """
        Fetches suspects from the DB and runs tiered analysis on them.
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Get all suspects for this run
        c.execute("SELECT path, line, content_snippet, type, pattern_matched, confidence FROM suspects WHERE run_id = ?", (run_id,))
        rows = c.fetchall()
        
        # Resume support: Get already processed files
        c.execute("SELECT DISTINCT path FROM inventory WHERE run_id = ?", (run_id,))
        processed_files = {r[0] for r in c.fetchall()}
        
        conn.close()

        if not rows:
            print("No suspects found to analyze.")
            return

        # Fetch Architectural Context first
        self._load_arch_context(run_id)

        # Group by file path to avoid re-reading file multiple times
        # Row: 0=path, 1=line, 2=snippet, 3=type, 4=pattern, 5=confidence
        suspects_by_file = {}
        from schemas.models import Suspect # Import locally to avoid circular dep if any
        
        for r in rows:
            path = r[0]
            if path in processed_files:
                continue
                
            if path not in suspects_by_file:
                suspects_by_file[path] = []
            
            # Reconstruct Suspect object (simplified)
            s = Suspect(
                path=path,
                line=r[1],
                content_snippet=r[2],
                type=r[3],
                pattern_matched=r[4],
                confidence=r[5]
            )
            suspects_by_file[path].append(s)

        if not suspects_by_file and rows:
            print("All previously detected suspects have already been analyzed. Resuming completed.")
            return

        print(f"Analyzing {len(suspects_by_file)} files containing suspects (Skipped {len(processed_files)} previously analyzed)...")
        
        total_to_analyze = len(suspects_by_file)
        for i, (file_path, suspects) in enumerate(suspects_by_file.items(), 1):
            try:
                print(f"[{i}/{total_to_analyze}] Analyzing {file_path}...")
                self.analyze_file_tiered(file_path, suspects, run_id)
            except Exception as e:
                print(f"Error analyzing {file_path}: {e}")

    def _load_arch_context(self, run_id: str):
        """Loads architectural summaries from documentation."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT content_snippet FROM suspects WHERE run_id = ? AND (pattern_matched = 'Architectural_Doc' OR pattern_matched = 'Architectural_MD')", (run_id,))
        rows = c.fetchall()
        conn.close()
        
        if rows:
            self.arch_context = "\n---\nARCHITECTURAL CONTEXT:\n" + "\n".join([r[0] for r in rows]) + "\n---\n"
            print(f"🧠 Loaded {len(rows)} architectural context(s).")

    def analyze_file_tiered(self, file_path: str, suspects: List[object], run_id: str):
        """
        Tiered Analysis:
        1. Fast Check (Flash) -> Is this strictly Cryptographic?
        2. Deep Audit (Pro) -> Extract details and assess PQC risk.
        """
        # Prepare Context
        if suspects:
            snippets = "\n".join([f"Line {s.line}: {s.content_snippet}" for s in suspects])
        else:
            # Forced analysis for high-signal artifacts that didn't hit regex
            try:
                # Read more of the file (up to 500KB) to ensure we find risks deep in JSON/metadata
                with open(file_path, "r", errors="ignore") as f:
                    content = f.read(500000)
                    snippets = "GENERIC ARTIFACT AUDIT (Content Sample):\n" + content
            except Exception as e:
                snippets = f"Error reading file for forced analysis: {e}"
        
        context = f"File: {file_path}\nTarget Pattern Matches:\n{snippets}"
        
        if self.arch_context:
            context = f"{self.arch_context}\nTARGET FILE CONTEXT:\n{context}"

        # --- TIER 1: FLASH ---
        is_relevant = self._ask_flash_triage(context, run_id)
        if not is_relevant:
            print(f"⚡️ [Flash] Dismissed {file_path} as non-crypto/irrelevant.")
            # Record as Safe for resume support
            self._save_results(file_path, run_id, [{
                "name": "Audit Dismissed",
                "category": "safe",
                "algorithm": "None",
                "line": 0,
                "reasoning": "Dismissed by Flash triage as non-cryptographic."
            }])
            return

        print(f"🧠 [Flash] Flagged {file_path}. Escalating to Pro...")

        # --- TIER 2: PRO ---
        # We might want to read the FULL file content here for the Pro model to have full context.
        # But for large files, that's risky. Let's stick to snippets + some window for now.
        full_analysis = self._ask_pro_deep_dive(context, run_id)
        
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
            res_json = self.ai.generate_json(prompt, self.flash_model_name)
            return res_json.get("is_relevant", False)
        except Exception as e:
            print(f"Tier 1 Error: {e}")
            return True # Fail open (escalate to Pro if Flash fails)

    def _calculate_cost(self, model_name: str, input_tokens: int, output_tokens: int) -> float:
        # Approximate Public Pricing (per 1M tokens) - Update as needed
        rates = {
            "gemini-2.0-flash": {"in": 0.10, "out": 0.40},
            "gemini-1.5-flash": {"in": 0.075, "out": 0.30},
            "gemini-2.0-pro":   {"in": 3.50, "out": 10.50}, # Placeholder
            "gemini-3-pro":     {"in": 3.50, "out": 10.50}, # Placeholder
        }
        
        # Default to Flash rates if unknown
        rate = rates.get("gemini-1.5-flash")
        for k, v in rates.items():
            if k in model_name:
                rate = v
                break
        
        cost = (input_tokens / 1_000_000 * rate["in"]) + (output_tokens / 1_000_000 * rate["out"])
        return cost

    def _ask_flash_triage(self, context: str, run_id: str) -> bool:
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
            res_json, usage = self.ai.generate_json(prompt, self.flash_model_name)
            
            # Save Metric
            from scanner.db import save_scan_metric
            cost = self._calculate_cost(self.flash_model_name, usage["input_tokens"], usage["output_tokens"])
            save_scan_metric(self.db_path, run_id, self.flash_model_name, usage["input_tokens"], usage["output_tokens"], cost)
            
            return res_json.get("is_relevant", False)
        except Exception as e:
            print(f"Tier 1 Error: {e}")
            return True # Fail open

    def _ask_pro_deep_dive(self, context: str, run_id: str) -> List[InventoryItem]:
        """Returns detailed inventory items."""
        prompt = f"""
        You are a Senior Cryptography Auditor.
        Analyze the following technical artifacts in the context of the provided architectural requirements (if any).
        
        {context}
        
        Task:
        1. Identify the Algorithm (e.g. RSA-2048, AES-GCM, ECDSA-P256).
        2. Assess Quantum Vulnerability.
           - SHOR'S ALGO (Asymmetric):
             * VULNERABLE: RSA, DH, ECC, DSA, ECDSA.
             * SAFE: Kyber, Dilithium, Falcon, SPHINCS+.
           - GROVER'S ALGO (Symmetric):
             * VULNERABLE: AES-128, SHA-256 (Weak collision resistance), DES/3DES.
             * SAFE: AES-256, SHA-384, SHA-512, ChaCha20-Poly1305.
        3. Extract Key Size if visible.
        4. Cross-Reference: Does this finding align with or violate the Architectural Context provided above?
        
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

        CRITICAL: If NO cryptographic vulnerabilities are found (e.g. standard infrastructure config, random tokens, or safe algorithms), you MUST return a single "Safe" record:
        [
            {{
                "name": "Safe File",
                "category": "safe",
                "algorithm": "None",
                "key_size": 0,
                "is_pqc_vulnerable": false,
                "line": 0,
                "reasoning": "Explanation of why this file is safe (e.g. 'AWS Config only', 'Random hex string')"
            }}
        ]
        """
        try:
            res_json, usage = self.ai.generate_json(prompt, self.pro_model_name)
            
            # Save Metric
            from scanner.db import save_scan_metric
            cost = self._calculate_cost(self.pro_model_name, usage["input_tokens"], usage["output_tokens"])
            save_scan_metric(self.db_path, run_id, self.pro_model_name, usage["input_tokens"], usage["output_tokens"], cost)
            
            return res_json
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
