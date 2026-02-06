import re
from pathlib import Path
from typing import List
from schemas.models import Suspect

class JSScanner:
    def __init__(self):
        self.suspects = []

    def scan_file(self, file_path: Path) -> List[Suspect]:
        self.suspects = []
        try:
            with open(file_path, "r", errors="ignore") as f:
                content = f.read()

            # 1. Look for Node.js Crypto usage
            # Patterns for crypto.createCipheriv, crypto.generateKeyPair, etc.
            patterns = {
                "JS_RSA_Gen": r"generateKeyPair(?:Sync)?\s*\(\s*['\"]rsa['\"]",
                "JS_Weak_Cipher": r"createCipheriv\s*\(\s*['\"](?:des|rc4|seed)['\"]",
                "JS_Static_Key": r"const\s+\w+\s*=\s*['\"]([A-Za-z0-9+/=]{32,})['\"]",
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
            
            # 2. Look for WebCrypto API (Window.crypto.subtle)
            webcrypto_patterns = {
                "WebCrypto_RSA": r"subtle\.generateKey\s*\(\s*{\s*name:\s*['\"]RSASSA-PKCS1-v1_5['\"]",
                "WebCrypto_ECDSA": r"subtle\.generateKey\s*\(\s*{\s*name:\s*['\"]ECDSA['\"]",
            }

            for name, pattern in webcrypto_patterns.items():
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
            # print(f"JS Scan Error {file_path}: {e}")
            pass
            
        return self.suspects
