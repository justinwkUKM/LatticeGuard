"""
LatticeGuard - Post-Quantum Cryptography Assessment Tool
Copyright (c) 2026 Waqas Khalid Obeidy
"""

import os
from collections import Counter
from typing import Dict, List, Set, Any
from pathlib import Path

# Common markers
FRAMEWORK_MARKERS = {
    "spring": ["pom.xml", "build.gradle"],
    "react": ["package.json"],
    "django": ["manage.py"],
    "flask": ["app.py", "wsgi.py"],
    "express": ["package.json"],
    "nextjs": ["next.config.js"],
}

INFRA_MARKERS = {
    "terraform": [".tf"],
    "kubernetes": [".yaml", ".yml"],  # Heuristic, need to check content
    "helm": ["Chart.yaml"],
    "docker": ["Dockerfile", "docker-compose.yml"],
}

SAFE_EXTENSIONS = {'.md', '.txt', '.json', '.xml', '.yaml', '.yml', '.html', '.css', '.csv'}

class RepoFingerprinter:
    def __init__(self, root_path: str):
        self.root = Path(root_path)
        self.languages = Counter()
        self.frameworks = set()
        self.infra = set()
        self.key_files = []

    def fingerprint(self) -> Dict[str, Any]:
        """Scans the repo structure to identify stack details."""
        if not self.root.exists():
            return {"error": f"Path {self.root} does not exist"}

        for dirpath, dirnames, filenames in os.walk(self.root):
            # Skip hidden dirs (git, idea, etc.)
            dirnames[:] = [d for d in dirnames if not d.startswith('.')]
            
            for f in filenames:
                path = Path(dirpath) / f
                ext = path.suffix.lower()
                
                # Languages
                if ext and ext not in SAFE_EXTENSIONS:
                    self.languages[ext] += 1

                # Frameworks (File-based)
                for fw, markers in FRAMEWORK_MARKERS.items():
                    if f in markers:
                        # Simple check: existence. 
                        # Todo: deeper check for package.json dependencies if needed.
                        self.frameworks.add(fw)

                # Infra
                for tool, markers in INFRA_MARKERS.items():
                    if f in markers or (marker.startswith('.') and f.endswith(marker) for marker in markers):
                        if tool == "kubernetes":
                            # Weak heuristic for k8s, skipping content check for speed for now
                            pass 
                        self.infra.add(tool)

        return {
            "languages": dict(self.languages.most_common(5)),
            "frameworks": list(self.frameworks),
            "infra": list(self.infra),
            # "key_files_count": len(self.key_files)
        }

if __name__ == "__main__":
    import sys
    rp = sys.argv[1] if len(sys.argv) > 1 else "."
    print(RepoFingerprinter(rp).fingerprint())
