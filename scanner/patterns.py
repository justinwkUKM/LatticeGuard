"""
LatticeGuard - Post-Quantum Cryptography Assessment Tool
Copyright (c) 2026 Waqas Khalid Obeidy
"""

import os
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
    
    # Nginx / Web Server
    "Nginx_Legacy_Protocol": r'ssl_protocols\s+.*?(SSLv2|SSLv3|TLSv1(?!\.)|TLSv1\.0|TLSv1\.1)',
    "Nginx_Weak_Cipher": r'ssl_ciphers\s+.*?(DES|RC4|MD5|SHA1|AES128-SHA|AES256-SHA)',
}

class PatternScanner:
    def __init__(self, repo_path: str):
        self.repo_path = repo_path


    def scan_file(self, file_path: Path) -> List[Suspect]:
        suspects = []
        chunk_size = 1 * 1024 * 1024  # 1MB chunks
        overlap = 2048  # 2KB overlap to catch patterns at boundaries
        
        try:
            file_size = file_path.stat().st_size
            
            with open(file_path, 'r', errors='ignore') as f:
                offset = 0
                offset_lines = 0  # Track global line offset
                while True:
                    # To handle overlap correctly, we need to seek back by 'overlap' bytes
                    # except for the first chunk.
                    if offset > 0:
                        f.seek(offset - overlap)
                        chunk = f.read(chunk_size + overlap)
                    else:
                        chunk = f.read(chunk_size)
                    
                    if not chunk:
                        break
                    
                    # Track effective start of this chunk relative to the file
                    # If we overlapped, the actual start of specific 'content' is (offset - overlap)
                    actual_start = max(0, offset - overlap)

                    for name, pattern in CRYPTO_PATTERNS.items():
                        for match in re.finditer(pattern, chunk):
                            # Skip matches that are entirely within the overlap zone of the PREVIOUS chunk
                            # to avoid duplicates.
                            # The overlap zone is at the beginning of the current chunk [0:overlap]
                            # match.start() is the index within 'chunk'.
                            if offset > 0 and match.start() < overlap:
                                continue

                            # Calculate global line number (this is slow for huge files, but accurate)
                            # For enterprise usage, we'd pre-calculate line offsets or skip line #s for >100MB
                            # For now, keeping it as requested for consistency.
                            line_num = content_pre_count = 0
                            # To be efficient on line counting, we'd need more logic. 
                            # Let's settle for a simplified approximation or full count if small.
                            # Simple line counting for small files
                            if file_size < 10 * 1024 * 1024:
                                content_pre_count = chunk.count('\n', 0, match.start())
                                line_num = offset_lines + content_pre_count + 1
                            else:
                                line_num = 1
                            
                            suspects.append(Suspect(
                                path=str(file_path),
                                line=line_num,
                                content_snippet=chunk[match.start():match.end()+50],
                                type="code",
                                pattern_matched=name,
                                confidence="medium"
                            ))
                    
                    if len(chunk) < (chunk_size + (overlap if offset > 0 else 0)):
                        break
                    
                    # Update line count for next chunk
                    # This is approximate if we have overlaps, but good enough for static analysis
                    # Ideally we count only the non-overlapped part
                    non_overlapped_len = chunk_size
                    if offset == 0:
                        non_overlapped_chunk = chunk[:chunk_size]
                    else:
                        non_overlapped_chunk = chunk[overlap:overlap+chunk_size]
                        
                    offset_lines += non_overlapped_chunk.count('\n')
                    offset += chunk_size

        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
            
        return suspects

    def scan(self) -> List[Suspect]:
        """Scan the entire repository for patterns."""
        suspects = []
        repo = Path(self.repo_path)
        exclude_dirs = {'.git', 'node_modules', 'venv', 'env', 'dist', 'build', '__pycache__', '.next'}
        
        for dirpath, dirnames, filenames in os.walk(repo):
            dirnames[:] = [d for d in dirnames if not d.startswith('.') and d not in exclude_dirs]
            
            for f in filenames:
                file_path = Path(dirpath) / f
                # Scan all text-based files or suspicious files
                if f.endswith(('.py', '.java', '.cpp', '.cc', '.h', '.hpp', '.rs', '.cs', '.go', '.ts', '.js', '.yaml', '.yml', '.env', '.log', '.txt', '.sql', '.tf', '.tfstate', '.conf', '.nginx')):
                    suspects.extend(self.scan_file(file_path))
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
