import os
import mimetypes
from pathlib import Path
from typing import List
from schemas.models import Suspect
from backend.ai_client import AIClient
from scanner.db import save_scan_metric

class DocScanner:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.ai = AIClient()
        self.model_name = os.getenv("GEMINI_FLASH_MODEL", "gemini-3-flash-preview")

    def scan_file(self, file_path: Path, run_id: str) -> List[Suspect]:
        """
        Uses multimodal AI to analyze architectural documentation.
        """
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT id FROM suspects WHERE path = ? AND run_id = ?", (str(file_path), run_id))
        existing = c.fetchone()
        conn.close()
        
        if existing:
            # We already have a result or flagged this as a suspect
            return []

        suspects = []
        ext = file_path.suffix.lower()
        
        # Supported multimodal extensions
        multimodal_exts = {".pdf", ".png", ".jpg", ".jpeg"}
        
        try:
            if ext in multimodal_exts:
                mime_type, _ = mimetypes.guess_type(file_path)
                if not mime_type:
                    if ext == ".pdf":
                        mime_type = "application/pdf"
                    else:
                        mime_type = "image/jpeg"
                
                with open(file_path, "rb") as f:
                    data = f.read()
                
                prompt = """
                Analyze this architectural document/diagram specifically for cryptographic requirements and usage.
                
                Tasks:
                1. Identify mentioned encryption algorithms (RSA, AES, ECC, etc.).
                2. Identify mentioned hashing algorithms (SHA-256, MD5, etc.).
                3. Describe the cryptographic architecture (e.g., "Uses AWS KMS for disk encryption", "TLS 1.2 required for all ingress").
                4. Extract any specific key sizes or compliance requirements mentioned.
                
                Output strictly valid JSON:
                {
                    "has_crypto": true,
                    "summary": "Full architectural summary here...",
                    "detected_algorithms": ["RSA-2048", "AES-GCM"],
                    "risk_notes": "Any immediate PQC risks visible in diagrams?"
                }
                """
                
                print(f"  [Multimodal] Analyzing document: {file_path.name}")
                res_json, usage = self.ai.generate_multimodal(prompt, data, mime_type, self.model_name)
                
                # Save Metric
                from scanner.db import save_scan_metric
                # Using approximate cost for Flash
                cost = (usage["input_tokens"] / 1_000_000 * 0.10) + (usage["output_tokens"] / 1_000_000 * 0.40)
                save_scan_metric(self.db_path, run_id, self.model_name, usage["input_tokens"], usage["output_tokens"], cost)
                
                if res_json.get("has_crypto"):
                    summary = f"Architectural Insight: {res_json.get('summary')}\nAlgorithms: {', '.join(res_json.get('detected_algorithms', []))}\nNotes: {res_json.get('risk_notes')}"
                    suspects.append(Suspect(
                        path=str(file_path),
                        line=0,
                        content_snippet=summary,
                        type="artifact",
                        pattern_matched="Architectural_Doc",
                        confidence="high"
                    ))
            
            elif ext == ".md":
                # For Markdown, just read text
                with open(file_path, "r", errors="ignore") as f:
                    content = f.read()
                
                prompt = f"""
                Analyze this architectural markdown file for cryptographic context.
                
                Content:
                {content[:5000]} 
                
                Output strictly valid JSON:
                {{
                    "has_crypto": true,
                    "summary": "Summary of crypto requirements...",
                    "detected_algorithms": []
                }}
                """
                res_json, usage = self.ai.generate_json(prompt, self.model_name)
                
                if res_json.get("has_crypto"):
                    suspects.append(Suspect(
                        path=str(file_path),
                        line=0,
                        content_snippet=f"Textual Insight: {res_json.get('summary')}",
                        type="artifact",
                        pattern_matched="Architectural_MD",
                        confidence="high"
                    ))

        except Exception as e:
            print(f"Doc Scanner Error {file_path}: {e}")
            
        return suspects
