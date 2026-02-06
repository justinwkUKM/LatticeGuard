import os
from typing import List
from pathlib import Path
from schemas.models import Suspect

SUSPICIOUS_EXTENSIONS = {
    ".pem": "PEM Encoded Key/Cert",
    ".der": "DER Encoded Key/Cert",
    ".key": "Private Key",
    ".crt": "Certificate",
    ".cer": "Certificate",
    ".p12": "PKCS#12 Keystore",
    ".pfx": "PKCS#12 Keystore",
    ".jks": "Java Keystore",
    ".jceks": "Java JCEKS Keystore",
    ".ovpn": "OpenVPN Config",
    
    # SCA Manifests
    "requirements.txt": "Python Deps",
    "pyproject.toml": "Python Deps",
    "package.json": "Node Deps",
    "pom.xml": "Java Deps",
    "build.gradle": "Java Deps",
    "go.mod": "Go Deps",
    "Cargo.toml": "Rust Deps",

    ".pub": "Public Key",
    
    # SCA Manifests
    "requirements.txt": "Python Deps",
    "pyproject.toml": "Python Deps",
    "package.json": "Node Deps",
    "pom.xml": "Java Deps",
    "build.gradle": "Java Deps",
    "go.mod": "Go Deps",
    "Cargo.toml": "Rust Deps",

    ".pub": "Public Key",
    ".asc": "PGP Key",
    ".tf": "Terraform Infrastructure",
    
    # Infra & Containers
    "Dockerfile": "Container Build",
    ".yaml": "Kubernetes/Helm Config",
    ".yml": "Kubernetes/Helm Config",
    
    # Data & Config
    ".sql": "SQL Database Dump",
    ".env": "Environment Config",
    ".json": "JSON Config/Data",
    ".xml": "XML Data",
}

class ArtifactScanner:
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)

    def scan(self) -> List[Suspect]:
        """
        Returns list of Suspects for interesting files.
        SECURITY: followlinks=False prevents symlink traversal attacks.
        """
        suspects = []
        exclude_dirs = {'.git', 'node_modules', 'venv', 'env', 'dist', 'build', '__pycache__', '.next', '.idea', '.vscode'}
        
        for dirpath, dirnames, filenames in os.walk(self.repo_path, followlinks=False):
            # Explicitly ignore .git and hidden metadata directories AND noisy build/dep dirs
            dirnames[:] = [d for d in dirnames if not d.startswith('.') and d not in exclude_dirs]
            
            for f in filenames:
                # Basic Binary Exclusion (can be improved)
                if f.endswith(('.pyc', '.o', '.bin', '.exe', '.dll', '.so')):
                    continue
                    
                full_path = Path(dirpath) / f
                try:
                    # rel_path = str(full_path.relative_to(self.repo_path)) # Not needed for Suspect path usually, but keeping full path is safer for open() later
                    
                    # Check if extension is interesting
                    ext = full_path.suffix
                    if ext in SUSPICIOUS_EXTENSIONS:
                         suspects.append(Suspect(
                            path=str(full_path),
                            line=0,
                            content_snippet=f"Found artifact: {SUSPICIOUS_EXTENSIONS[ext]}",
                            type="artifact",
                            pattern_matched=ext,
                            confidence="medium"
                        ))

                except ValueError:
                    continue
        return suspects
