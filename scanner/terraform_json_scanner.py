"""
LatticeGuard - Post-Quantum Cryptography Assessment Tool
Copyright (c) 2026 Waqas Khalid Obeidy
"""

import json
from pathlib import Path
from typing import List
from schemas.models import Suspect

class TerraformJSONScanner:
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)

    def is_tf_plan(self, content: dict) -> bool:
        """Heuristic to check if JSON is a Terraform plan."""
        return "resource_changes" in content or "planned_values" in content

    def scan_file(self, file_path: Path) -> List[Suspect]:
        suspects = []
        try:
            with open(file_path, "r", errors="ignore") as f:
                content = json.load(f)

            if not self.is_tf_plan(content):
                return suspects

            print(f"  [Terraform] Analyzing resolved plan: {file_path.name}")
            
            # 1. Analyze resource intentional changes/planned values
            root = content.get("planned_values", {}).get("root_module", {})
            resources = self._extract_resources(root)

            for res in resources:
                res_type = res.get("type")
                res_name = res.get("name")
                vals = res.get("values", {})

                # Check for TLS/SSL resources
                if res_type in ["aws_lb_listener", "aws_alb_listener"]:
                    protocol = vals.get("protocol")
                    ssl_policy = vals.get("ssl_policy")
                    if protocol == "HTTPS":
                        suspects.append(Suspect(
                            path=str(file_path),
                            line=0,
                            content_snippet=f"Resource: {res_type}.{res_name} | Protocol: {protocol} | SSL Policy: {ssl_policy}",
                            type="infra",
                            pattern_matched="TF_Resolved_ALB_Listener",
                            confidence="high"
                        ))

                elif res_type == "aws_cloudfront_distribution":
                    cvc = vals.get("viewer_certificate", [{}])[0] if isinstance(vals.get("viewer_certificate"), list) else vals.get("viewer_certificate", {})
                    min_tls = cvc.get("minimum_protocol_version")
                    suspects.append(Suspect(
                        path=str(file_path),
                        line=0,
                        content_snippet=f"Resource: {res_type}.{res_name} | Min TLS: {min_tls}",
                        type="infra",
                        pattern_matched="TF_Resolved_CloudFront",
                        confidence="high"
                    ))

                elif res_type in ["tls_private_key", "aws_kms_key"]:
                    algo = vals.get("algorithm") or vals.get("customer_master_key_spec")
                    suspects.append(Suspect(
                        path=str(file_path),
                        line=0,
                        content_snippet=f"Resource: {res_type}.{res_name} | Algorithm: {algo}",
                        type="infra",
                        pattern_matched="TF_Resolved_Crypto_Key",
                        confidence="high"
                    ))

        except Exception as e:
            print(f"Terraform JSON Scan Error {file_path}: {e}")
            
        return suspects

    def _extract_resources(self, module: dict) -> List[dict]:
        resources = module.get("resources", [])
        # Also check child modules recursively
        for child in module.get("child_modules", []):
            resources.extend(self._extract_resources(child))
        return resources
