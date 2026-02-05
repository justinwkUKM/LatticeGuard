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

    def scan(self):
        """
        Yields relative file paths to be analyzed.
        """
        for dirpath, _, filenames in os.walk(self.repo_path):
            for f in filenames:
                # Basic Binary Exclusion (can be improved)
                if f.endswith(('.pyc', '.o', '.bin', '.exe', '.dll', '.so')):
                    continue
                    
                full_path = Path(dirpath) / f
                try:
                    rel_path = str(full_path.relative_to(self.repo_path))
                    yield rel_path
                except ValueError:
                    continue
