"""
LatticeGuard - Post-Quantum Cryptography Assessment Tool
Copyright (c) 2026 Waqas Khalid Obeidy
"""

"""
Scan Planner (Smart Orchestration)
Fingerprints the target repository to determine which scanners to activate.
"""

import os
from pathlib import Path
from typing import List, Dict, Any

class ScanPlanner:
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.scanners_to_run = {
            "sast": True,       # Always run SAST (Pattern/AST)
            "sca": False,       # Dependency Scanner
            "infra": False,     # Kubernetes/Terraform
            "binary": False,    # Binary Audit
            "secrets": True     # Always check for secrets
        }
        self.tech_stack = []

    def plan(self) -> Dict[str, Any]:
        """Analyzes the repo and returns a scan plan"""
        if not self.repo_path.exists():
            return {"error": "Path does not exist"}

        print(f"🕵️  Fingerprinting repository: {self.repo_path}")
        
        # 1. Walk the repo to find key indicators
        for root, dirs, files in os.walk(self.repo_path):
            if ".git" in dirs:
                dirs.remove(".git") # Skip git internals
            
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                filename = file.lower()
                
                # Check for Infrastructure
                if ext in [".yaml", ".yml", ".tf", ".json"] and not self.scanners_to_run["infra"]:
                    # Heuristic: Check if contents look like K8s or Terraform? 
                    # For now, just file extension trigger is enough for "smart" selection
                    self.scanners_to_run["infra"] = True
                    self.tech_stack.append("Infrastructure-as-Code")
                
                if ext in [".conf", ".nginx"]:
                     if not self.scanners_to_run["infra"]: # We map this to infra for now to reflect "ops" code
                         self.scanners_to_run["infra"] = True # Though K8s scanner might not pick it up, Pattern scanner will.
                     self.tech_stack.append("Web Server Config")
                
                # Check for Binaries
                if ext in [".so", ".dll", ".exe", ".bin", ".dylib"]:
                    if not self.scanners_to_run["binary"]:
                        self.scanners_to_run["binary"] = True
                        self.tech_stack.append("Compiled Binaries")
                
                # Check for Dependencies (SCA)
                if filename in ["pom.xml", "package.json", "requirements.txt", "go.mod", "cargo.toml"]:
                    if not self.scanners_to_run["sca"]:
                        self.scanners_to_run["sca"] = True
                        self.tech_stack.append("Dependencies Managed")

        return {
            "scanners": self.scanners_to_run,
            "stack": list(set(self.tech_stack))
        }
