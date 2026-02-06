import os
from typing import List
from pathlib import Path
from schemas.models import Suspect

class DependencyScanner:
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.vuln_packages = {
            # Python
            "pycrypto": "Legacy crypto library (Unmaintained). Use pycryptodome.",
            "m2crypto": "Unsafe wrappers depending on version.",
            # JS
            "crypto-js": "Legacy JS Crypto. Check for weak algo usage.",
            "node-rsa": "Common RSA impl. Vulnerable to Shor's.",
            # Java
            "bouncycastle": "Check version. Pre-1.78 is often weak vs PQC.",
            # General/Other
            "hazmat": "Low-level crypto primitives. High risk of misuse.",
            # Go
            "crypto/rsa": "Standard Go RSA implementation. Vulnerable to Shor's.",
            "crypto/ecdsa": "Standard Go ECDSA implementation. Vulnerable to Shor's.",
            # Rust
            "rsa": "Pure Rust RSA implementation. Vulnerable to Shor's.",
            "ed25519-dalek": "Standard Ed25519 (ECC). Vulnerable to Shor's.",
            # Java
            "org.bouncycastle": "Universal Java crypto provider. Check for PQC provider usage."
        }

    def scan(self) -> List[Suspect]:
        suspects = []
        # Manifest files to look for
        manifests = ["requirements.txt", "package.json", "pom.xml", "build.gradle", "go.mod", "Cargo.toml"]
        exclude_dirs = {'.git', 'node_modules', 'venv', 'env', 'dist', 'build', '__pycache__', '.next'}
        
        for dirpath, dirnames, filenames in os.walk(self.repo_path):
             # Filter in-place to prevent walking into excluded dirs
            dirnames[:] = [d for d in dirnames if not d.startswith('.') and d not in exclude_dirs]
            
            for f in filenames:
                if f in manifests:
                    file_path = Path(dirpath) / f
                    suspects.extend(self._scan_file(file_path))
        return suspects

    def _scan_file(self, file_path: Path) -> List[Suspect]:
        suspects = []
        try:
            content = ""
            with open(file_path, "r", errors="ignore") as f:
                content = f.read()

            for pkg, msg in self.vuln_packages.items():
                if pkg in content:
                     # Attempt to find line number
                    line_num = 0
                    for i, line in enumerate(content.splitlines()):
                        if pkg in line:
                            line_num = i + 1
                            break
                    
                    suspects.append(Suspect(
                        path=str(file_path),
                        line=line_num,
                        content_snippet=f"Found vulnerable dependency: {pkg}",
                        type="artifact",
                        pattern_matched=pkg,
                        confidence="high"
                    ))

        except Exception as e:
            print(f"SCA Error {file_path}: {e}")
            
        return suspects
