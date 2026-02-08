"""
LatticeGuard - Post-Quantum Cryptography Assessment Tool
Copyright (c) 2026 Waqas Khalid Obeidy
"""

import subprocess
import re
from typing import List
from schemas.models import InventoryItem
from scanner.patterns import CRYPTO_PATTERNS

class HistoryScanner:
    def __init__(self, repo_path: str):
        self.repo_path = repo_path

    def scan(self) -> List[InventoryItem]:
        results = []
        try:
            # Git log with patch, limiting to recent history for speed in MVP
            # In deep audit mode, remove -n 1000
            cmd = ["git", "log", "-p", "-n", "1000", "--unified=0"]
            
            process = subprocess.Popen(
                cmd, 
                cwd=self.repo_path, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True,
                errors="ignore"
            )
            
            current_commit = "UNKNOWN"
            
            # Streaming output to avoid memory issues
            for line in process.stdout:
                if line.startswith("commit "):
                    current_commit = line.split(" ")[1].strip()
                    continue
                
                # Check for secrets in diff additions
                if line.startswith("+"):
                    clean_line = line[1:].strip()
                    if not clean_line: continue
                    
                    for name, pattern in CRYPTO_PATTERNS.items():
                        if re.search(pattern, clean_line):
                            results.append(InventoryItem(
                                id=f"git-history:{current_commit}:{name}",
                                path=f"git://{current_commit}",
                                line=0,
                                name=f"Ghost Secret ({name})",
                                category="secret_leak",
                                algorithm="Unknown",
                                key_size=0,
                                is_pqc_vulnerable=True, # Secrets in git are always critical
                                description=f"Found in commit history: {current_commit}"
                            ))

        except Exception as e:
            print(f"History Scan Error: {e}")
            
        return results
