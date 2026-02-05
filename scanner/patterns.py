import subprocess
import json
from typing import List
from pathlib import Path
from schemas.models import Suspect
import re

# Basic high-signal patterns
CRYPTO_PATTERNS = {
    "RSA_Key": r"BEGIN (RSA )?PRIVATE KEY",
    "EC_Key": r"BEGIN EC PRIVATE KEY",
    "AES_Usage": r"AES\/[A-Z0-9-]+\/[A-Z]+",  # e.g. AES/GCM/NoPadding
    "Weak_Hash": r"(MD5|SHA1)",
    "PQC_Keyword": r"(Kyber|Dilithium|Falcon|SPHINCS)",
    "Generic_Secret": r"(api_key|secret_key|private_key)\s*[:=]\s*['\"][A-Za-z0-9+/=]{20,}['\"]",
    "Terraform_RSA": r'algorithm\s*=\s*"RSA"',
    "Terraform_Legacy_TLS": r'min_tls_version\s*=\s*"1\.[01]"',
    
    # Extended Infra (Docker/K8s)
    "Docker_Secret": r'(?i)ENV\s+(?:\w*_)?(SECRET|KEY|PASSWORD|TOKEN)\s*=',
    "K8s_Secret": r'(?i)kind:\s*Secret',
    
    # High Entropy / Hardcoded (Generic)
    "AWS_Key": r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
    "Generic_Token": r'(?i)(api_key|access_token|secret)\s*[:=]\s*[\'"][a-zA-Z0-9_\-]{32,}[\'"]',
    "SQL_Key_Insert": r'(?i)INSERT\s+INTO.*VALUES.*\s*[\'"](ssh-rsa|BEGIN\s+PRIVATE\s+KEY)',
}

class PatternScanner:
    def __init__(self, repo_path: str):
        self.repo_path = repo_path


    def scan_file(self, file_path: Path) -> List[Suspect]:
        suspects = []
        try:
            # Avoid OOM for extremely large files
            if file_path.stat().st_size > 5 * 1024 * 1024:
                print(f"Warning: Skipping large file {file_path} (>5MB)")
                return suspects
                
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
                
            for name, pattern in CRYPTO_PATTERNS.items():
                for match in re.finditer(pattern, content):
                    # Calculate line number
                    line_num = content.count('\n', 0, match.start()) + 1
                    snippet = content[match.start():match.end()+50]
                    
                    suspects.append(Suspect(
                        path=str(file_path),
                        line=line_num,
                        content_snippet=snippet,
                        type="code",
                        pattern_matched=name,
                        confidence="medium"
                    ))
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
            
        return suspects

    def scan(self) -> List[Suspect]:
        # Legacy rg-based scan for whole repo (CLI usage)
        suspects = []
        # ... (keep existing rg logic or deprecate, for now keeping for CLI compatibility if needed, 
        # but worker will use scan_file)
        return suspects

if __name__ == "__main__":
    # Test
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    scanner = PatternScanner(path)
    res = scanner.scan()
    print(f"Found {len(res)} suspects")
    for s in res[:5]:
        print(s)
