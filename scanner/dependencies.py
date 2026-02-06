from typing import List
from pathlib import Path
from schemas.models import InventoryItem

class DependencyScanner:
    def __init__(self):
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
            "paramiko": "SSHv1/v2 impl. Check for weak KEX usage.",
            "hazmat": "Low-level crypto primitives. High risk of misuse."
        }

    def scan(self, file_path: Path) -> List[InventoryItem]:
        results = []
        try:
            filename = file_path.name
            content = ""
            with open(file_path, "r", errors="ignore") as f:
                content = f.read()

            found_vulns = []
            
            # Simple String Matching for MVP
            # Real SCA would parse the AST/JSON/TOML
            for pkg, msg in self.vuln_packages.items():
                if pkg in content:
                    found_vulns.append((pkg, msg))

            for pkg, msg in found_vulns:
                 results.append(InventoryItem(
                    id=f"{file_path}:{pkg}",
                    path=str(file_path),
                    line=0,
                    name=f"Vulnerable Dependency ({pkg})",
                    category="dependency",
                    algorithm="Classical Crypto Lib",
                    key_size=0,
                    is_pqc_vulnerable=True,
                    description=msg
                ))

        except Exception as e:
            print(f"SCA Error {file_path}: {e}")
            
        return results
