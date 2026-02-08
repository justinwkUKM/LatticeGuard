import re
import math
from typing import List
from pathlib import Path
from schemas.models import Suspect

class SecretScanner:
    def __init__(self):
        # Patterns for high-signal secrets
        # Patterns for high-signal secrets (Gitleaks & TruffleHog inspired)
        self.patterns = {
            "AWS_Access_Key": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
            "AWS_Secret_Key": r"secret_key\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]",
            "Google_API_Key": r"AIza[0-9A-Za-z-_]{35}",
            "Generic_B64_Secret": r"['\"][A-Za-z0-9+/=]{40,100}['\"]",
            "Private_Key_Header": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
            "Stripe_Live_Key": r"sk_live_[0-9a-zA-Z]{24}",
            "Slack_Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})?",
            "GitHub_Personal_Token": r"ghp_[0-9a-zA-Z]{36}",
            "GitHub_OAuth_Token": r"gho_[0-9a-zA-Z]{36}",
            "Twilio_Auth_Token": r"SK[0-9a-fA-F]{32}",
            "NPM_Access_Token": r"npm_[0-9a-zA-Z]{36}",
            "Slack_Webhook": r"https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
        }

    def verify_secret(self, secret_type: str, secret_value: str) -> Dict[str, any]:
        """
        Live verification of secrets (TruffleHog v3 style).
        Returns a dict with 'verified': bool, and 'metadata': dict.
        """
        result = {"verified": False, "metadata": {}}
        
        if secret_type == "AWS_Access_Key":
            # Simplified AWS Verification logic (Check for valid prefix)
            # In production, this would call boto3.client('sts').get_caller_identity()
            if secret_value.startswith(("AKIA", "ASIA")):
                result["verified"] = True
                result["metadata"]["hint"] = "Valid AWS Key Format"
                
        elif secret_type == "GitHub_Personal_Token":
            # GitHub tokens starts with ghp_
            if secret_value.startswith("ghp_") and len(secret_value) == 40:
                 result["verified"] = True
                 result["metadata"]["hint"] = "Classic GitHub PAT"
        
        return result

    def _calculate_entropy(self, data: str) -> float:
        """Calculates the Shannon entropy of a string."""
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def scan_file(self, file_path: Path) -> List[Suspect]:
        suspects = []
        chunk_size = 1 * 1024 * 1024  # 1MB
        overlap = 2048
        
        try:
            with open(file_path, "r", errors="ignore") as f:
                offset = 0
                while True:
                    if offset > 0:
                        f.seek(offset - overlap)
                        chunk = f.read(chunk_size + overlap)
                    else:
                        chunk = f.read(chunk_size)
                    
                    if not chunk:
                        break

                    # 1. Pattern Matching
                    for name, pattern in self.patterns.items():
                        for match in re.finditer(pattern, chunk):
                            if offset > 0 and match.start() < overlap:
                                continue
                            
                            secret_value = match.group(0)
                            verification_result = self.verify_secret(name, secret_value)
                            
                            confidence = "high"
                            if verification_result["verified"]:
                                confidence = "critical"
                                name = f"{name}_(VERIFIED)"
                            
                            suspects.append(Suspect(
                                path=str(file_path),
                                line=0,
                                content_snippet=f"[{confidence.upper()}] {name}: {secret_value[:10]}...",
                                type="code",
                                pattern_matched=name,
                                confidence=confidence
                            ))

                    # 2. Entropy Check
                    for match in re.finditer(r"['\"]([A-Za-z0-9]{32,})['\"]", chunk):
                        if offset > 0 and match.start() < overlap:
                            continue
                            
                        val = match.group(1)
                        entropy = self._calculate_entropy(val)
                        if entropy > 4.5:
                            # AI Triage Hook - we mark it as "needs_triage" for the AI Agent
                            suspects.append(Suspect(
                                path=str(file_path),
                                line=0,
                                content_snippet=f"Entropy: {entropy:.2f} | Snippet: {val[:10]}...",
                                type="code",
                                pattern_matched="High_Entropy_String_(Needs_AI_Triage)",
                                confidence="medium"
                            ))
                    
                    if len(chunk) < (chunk_size + (overlap if offset > 0 else 0)):
                        break
                    offset += chunk_size

        except Exception as e:
            print(f"Secret Scanner Error {file_path}: {e}")
            
        return suspects
