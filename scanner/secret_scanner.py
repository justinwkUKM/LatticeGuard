import re
import math
from typing import List
from pathlib import Path
from schemas.models import Suspect

class SecretScanner:
    def __init__(self):
        # Patterns for high-signal secrets
        self.patterns = {
            "AWS_Access_Key": r"AKIA[0-9A-Z]{16}",
            "AWS_Secret_Key": r"secret_key\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]",
            "Google_API_Key": r"AIza[0-9A-Za-z-_]{35}",
            "Generic_B64_Secret": r"['\"][A-Za-z0-9+/=]{40,100}['\"]",
            "Private_Key_Header": r"-----BEGIN [A-Z ]*PRIVATE KEY-----"
        }

    def _calculate_entropy(self, data: str) -> float:
        """Calculates the Shannon entropy of a string."""
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def scan_file(self, file_path: Path) -> List[Suspect]:
        suspects = []
        chunk_size = 1 * 1024 * 1024  # 1MB
        overlap = 2048
        
        try:
            with open(file_path, "r", errors="ignore") as f:
                offset = 0
                while True:
                    if offset > 0:
                        f.seek(offset - overlap)
                        chunk = f.read(chunk_size + overlap)
                    else:
                        chunk = f.read(chunk_size)
                    
                    if not chunk:
                        break

                    # 1. Pattern Matching
                    for name, pattern in self.patterns.items():
                        for match in re.finditer(pattern, chunk):
                            if offset > 0 and match.start() < overlap:
                                continue
                            
                            suspects.append(Suspect(
                                path=str(file_path),
                                line=0,
                                content_snippet=chunk[match.start():match.end()+20],
                                type="code",
                                pattern_matched=name,
                                confidence="high"
                            ))

                    # 2. Entropy Check
                    for match in re.finditer(r"['\"]([A-Za-z0-9]{32,})['\"]", chunk):
                        if offset > 0 and match.start() < overlap:
                            continue
                            
                        val = match.group(1)
                        entropy = self._calculate_entropy(val)
                        if entropy > 4.5:
                            suspects.append(Suspect(
                                path=str(file_path),
                                line=0,
                                content_snippet=f"Entropy: {entropy:.2f} | Snippet: {val[:10]}...",
                                type="code",
                                pattern_matched="High_Entropy_String",
                                confidence="medium"
                            ))
                    
                    if len(chunk) < (chunk_size + (overlap if offset > 0 else 0)):
                        break
                    offset += chunk_size

        except Exception as e:
            print(f"Secret Scanner Error {file_path}: {e}")
            
        return suspects
