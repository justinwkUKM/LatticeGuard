"""
LatticeGuard - Post-Quantum Cryptography Assessment Tool
Copyright (c) 2026 Waqas Khalid Obeidy
"""

import subprocess
import re
from pathlib import Path
from typing import List
from schemas.models import Suspect
from scanner.secret_scanner import SecretScanner

class GitHistoryScanner:
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.secret_scanner = SecretScanner()

    def scan_history(self, limit: int = 1000) -> List[Suspect]:
        """
        Scans git log -p for secrets in diffs (deleted/modified).
        Mimics TruffleHog.
        """
        suspects = []
        try:
            # Run git log -p to see diffs
            # We limit to last N commits to avoid performance explosion on huge repos
            cmd = ["git", "log", "-p", f"-n {limit}"]
            
            # Use subprocess to stream output if possible, but for simplicity read all
            process = subprocess.run(
                cmd, 
                cwd=self.repo_path, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True, 
                errors="ignore"
            )
            
            if process.returncode != 0:
                print(f"Git scan failed: {process.stderr}")
                return []

            current_commit = "Unknown"
            current_file = "Unknown"
            
            # Simple line-by-line parsing
            for line in process.stdout.splitlines():
                if line.startswith("commit "):
                    current_commit = line.split(" ")[1]
                elif line.startswith("diff --git"):
                    # Extract filename if needed, usually 'diff --git a/foo b/foo'
                    parts = line.split(" ")
                    if len(parts) > 2:
                        current_file = parts[-1].lstrip("b/")
                
                # Check for secrets in added/removed lines
                if line.startswith("+") or line.startswith("-"):
                    content = line[1:].strip()
                    if not content:
                        continue
                        
                    # Use existing secret scanner logic on the line
                    # 1. Patterns
                    for name, pattern in self.secret_scanner.patterns.items():
                        if re.search(pattern, content):
                            suspects.append(Suspect(
                                path=f"{current_file} (History: {current_commit[:8]})",
                                line=0,
                                content_snippet=content[:100],
                                type="secret",
                                pattern_matched=f"{name}_History",
                                confidence="high"
                            ))
                            
        except Exception as e:
            print(f"Git History Scanner Error: {e}")
            
        return suspects
