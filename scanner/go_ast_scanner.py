import re
from pathlib import Path
from typing import List
from schemas.models import Suspect

class GoScanner:
    def __init__(self):
        self.suspects = []

    def scan_file(self, file_path: Path) -> List[Suspect]:
        self.suspects = []
        try:
            with open(file_path, "r", errors="ignore") as f:
                content = f.read()

            # Patterns for rsa.GenerateKey, ecdsa.GenerateKey, etc.
            patterns = {
                "Go_RSA_Gen": r"rsa\.GenerateKey\s*\(",
                "Go_ECDSA_Gen": r"ecdsa\.GenerateKey\s*\(",
                "Go_Weak_Hash": r"crypto\.(?:MD5|SHA1)\.New\s*\(",
            }

            for name, pattern in patterns.items():
                for match in re.finditer(pattern, content):
                    line_num = content.count('\n', 0, match.start()) + 1
                    self.suspects.append(Suspect(
                        path=str(file_path),
                        line=line_num,
                        content_snippet=content[match.start():match.end()+40],
                        type="code",
                        pattern_matched=name,
                        confidence="high"
                    ))

        except Exception as e:
            # print(f"Go Scan Error {file_path}: {e}")
            pass
            
        return self.suspects
