import yaml
import fnmatch
from pathlib import Path
from typing import List, Dict, Optional, Set
from schemas.models import Suspect

class SuppressionManager:
    """
    Handles suppression of PQC findings based on .latticeguard.yaml configuration.
    Supports path globbing, algorithm blocking/allowing, and specific finding IDs.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = {}
        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    self.config = yaml.safe_load(f) or {}
            except Exception as e:
                print(f"Warning: Failed to load config at {config_path}: {e}")
        
        self.suppressions = self.config.get('suppressions', {})
        self.path_patterns = self.suppressions.get('paths', [])
        self.ignored_algorithms = set(self.suppressions.get('algorithms', []))
        self.ignored_finding_ids = set(self.suppressions.get('findings', []))
        
        # Also support algorithm allow/block lists from the config root
        self.safe_algorithms = set(self.config.get('quantum_safe_algorithms', []))
        self.blocked_algorithms = set(self.config.get('blocked_algorithms', []))

    def should_suppress(self, suspect: Suspect) -> bool:
        """Determines if a finding should be suppressed."""
        # Check path patterns (glob)
        for pattern in self.path_patterns:
            if fnmatch.fnmatch(suspect.path, pattern):
                return True
        
        # Check algorithm-based suppression
        algo = suspect.pattern_matched if hasattr(suspect, 'pattern_matched') else ""
        if algo in self.ignored_algorithms:
            return True
            
        # Check finding ID suppression
        # ID format: path:line:algorithm
        finding_id = f"{suspect.path}:{suspect.line}:{algo}"
        if finding_id in self.ignored_finding_ids:
            return True
            
        # If it's explicitly quantum-safe, we might still report it but mark it
        # Actually, if it's in quantum_safe_algorithms, we might suppress it if the user wants purely vulnerable ones
        # But usually we flag everything potentially vulnerable.
        
        return False

    def is_blocked(self, algorithm: str) -> bool:
        """Returns True if the algorithm is in the blocked list."""
        return algorithm.upper() in [a.upper() for a in self.blocked_algorithms]

    def is_safe(self, algorithm: str) -> bool:
        """Returns True if the algorithm is in the quantum-safe list."""
        return algorithm.upper() in [a.upper() for a in self.safe_algorithms]
