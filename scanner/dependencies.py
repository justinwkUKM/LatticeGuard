import os
import json
from pathlib import Path
from typing import List
from schemas.models import Suspect

CRYPTO_LIBS = [
    # Python
    "cryptography", "pycryptodome", "pycrypto", "m2crypto", "pynacl", "jose", "jwcrypto",
    # JS/Node
    "crypto-js", "bcrypt", "jsonwebtoken", "jose", "node-forge", "tweetnacl",
    # Java (Basic substrings)
    "bouncycastle", "jjwt", "spring-security-crypto"
]

class DependencyScanner:
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)

    def scan(self) -> List[Suspect]:
        suspects = []
        
        for dirpath, _, filenames in os.walk(self.repo_path):
            rel_dir = Path(dirpath).relative_to(self.repo_path)
            
            if "package.json" in filenames:
                suspects.extend(self._scan_package_json(Path(dirpath) / "package.json", rel_dir))
            
            if "requirements.txt" in filenames:
                suspects.extend(self._scan_requirements(Path(dirpath) / "requirements.txt", rel_dir))
                
            if "pom.xml" in filenames:
                suspects.extend(self._scan_pom(Path(dirpath) / "pom.xml", rel_dir))

        return suspects

    def _scan_package_json(self, path: Path, rel_dir: Path) -> List[Suspect]:
        res = []
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                
                for lib in CRYPTO_LIBS:
                    if lib in deps:
                        res.append(Suspect(
                            path=str(rel_dir / "package.json"),
                            line=0,
                            content_snippet=f"{lib}: {deps[lib]}",
                            type="code", # dependency
                            pattern_matched=f"npm:{lib}",
                            confidence="high"
                        ))
        except: pass
        return res

    def _scan_requirements(self, path: Path, rel_dir: Path) -> List[Suspect]:
        res = []
        try:
            with open(path, 'r') as f:
                for idx, line in enumerate(f):
                    line = line.strip().lower()
                    for lib in CRYPTO_LIBS:
                        if line.startswith(lib):
                            res.append(Suspect(
                                path=str(rel_dir / "requirements.txt"),
                                line=idx+1,
                                content_snippet=line,
                                type="code",
                                pattern_matched=f"pip:{lib}",
                                confidence="high"
                            ))
        except: pass
        return res

    def _scan_pom(self, path: Path, rel_dir: Path) -> List[Suspect]:
        # Simple text scan for POM, xml parsing is better but heavy
        res = []
        try:
            with open(path, 'r') as f:
                content = f.read()
                for lib in CRYPTO_LIBS:
                    if lib in content.lower():
                        res.append(Suspect(
                            path=str(rel_dir / "pom.xml"),
                            line=0,
                            content_snippet=f"Detected {lib}",
                            type="code",
                            pattern_matched=f"maven:{lib}",
                            confidence="medium"
                        ))
        except: pass
        return res
