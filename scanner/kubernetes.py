"""
Kubernetes Manifest Scanner
Parses Kubernetes YAML manifests to identify PQC-vulnerable cryptographic configurations.
"""
import os
import yaml
from pathlib import Path
from typing import List, Optional, Dict, Any
from schemas.models import Suspect, InventoryItem


class KubernetesScanner:
    """
    Scans Kubernetes manifests for cryptographic configurations:
    - TLS secrets and their key algorithms
    - Ingress TLS configurations
    - cert-manager Certificate resources
    - ConfigMaps with potential crypto configs
    - Service annotations for TLS
    """
    
    # Kubernetes resource types to analyze
    K8S_CRYPTO_RESOURCES = {
        "Secret": "_analyze_secret",
        "Ingress": "_analyze_ingress",
        "Certificate": "_analyze_certificate",  # cert-manager
        "ClusterIssuer": "_analyze_cluster_issuer",  # cert-manager
        "Issuer": "_analyze_issuer",  # cert-manager
        "ConfigMap": "_analyze_configmap",
        "Service": "_analyze_service",
    }
    
    # Deprecated/weak TLS versions
    WEAK_TLS_VERSIONS = {"1.0", "1.1", "TLSv1", "TLSv1.0", "TLSv1.1", "TLS1.0", "TLS1.1"}
    
    # PQC-vulnerable key algorithms
    VULNERABLE_KEY_ALGORITHMS = {
        "rsa": {"risk": "high", "desc": "RSA algorithm - Shor vulnerable"},
        "ecdsa": {"risk": "high", "desc": "ECDSA algorithm - Shor vulnerable"},
        "dsa": {"risk": "high", "desc": "DSA algorithm - Shor vulnerable"},
        "ec": {"risk": "high", "desc": "Elliptic curve - Shor vulnerable"},
    }
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.findings: List[InventoryItem] = []
        self.suspects: List[Suspect] = []
    
    def scan(self) -> List[Suspect]:
        """Scan repository for Kubernetes manifests."""
        exclude_dirs = {'.git', 'node_modules', 'venv', '.terraform', '__pycache__', '.venv'}
        
        for dirpath, dirnames, filenames in os.walk(self.repo_path):
            dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
            
            for filename in filenames:
                if filename.endswith(('.yaml', '.yml')):
                    filepath = Path(dirpath) / filename
                    self._scan_file(filepath)
        
        return self.suspects
    
    def _scan_file(self, filepath: Path) -> None:
        """Scan a single YAML file for Kubernetes resources."""
        try:
            content = filepath.read_text()
            
            # Quick check for Kubernetes markers
            if not self._is_kubernetes(content):
                return
            
            # Parse all YAML documents in the file (multi-doc support)
            documents = list(yaml.safe_load_all(content))
            
            for doc in documents:
                if not isinstance(doc, dict):
                    continue
                
                kind = doc.get("kind", "")
                api_version = doc.get("apiVersion", "")
                
                # Check if this is a K8s resource we care about
                if kind in self.K8S_CRYPTO_RESOURCES:
                    handler = getattr(self, self.K8S_CRYPTO_RESOURCES[kind], None)
                    if handler:
                        handler(filepath, doc, content)
                        
        except yaml.YAMLError:
            pass  # Invalid YAML, skip
        except Exception as e:
            pass  # Silent error handling
    
    def _is_kubernetes(self, content: str) -> bool:
        """Check if content looks like Kubernetes manifest."""
        k8s_markers = [
            "apiVersion:",
            "kind:",
            "kubernetes.io",
            "k8s.io",
            "cert-manager.io",
        ]
        return any(marker in content for marker in k8s_markers)
    
    def _find_line_number(self, content: str, search_term: str) -> int:
        """Find line number containing search term."""
        try:
            for i, line in enumerate(content.splitlines(), 1):
                if search_term in line:
                    return i
        except:
            pass
        return 0
    
    def _analyze_secret(self, filepath: Path, doc: Dict, content: str):
        """Analyze Kubernetes Secret for TLS certificates."""
        metadata = doc.get("metadata", {})
        name = metadata.get("name", "unknown")
        secret_type = doc.get("type", "")
        
        # TLS secrets
        if secret_type == "kubernetes.io/tls":
            line = self._find_line_number(content, name)
            
            self.suspects.append(Suspect(
                path=str(filepath),
                line=line,
                content_snippet=f"TLS Secret '{name}' - certificate key algorithm should be verified",
                type="infra",
                pattern_matched="K8s_TLS_Secret",
                confidence="medium"
            ))
            
            self.findings.append(InventoryItem(
                id=f"{filepath}:{line}:{name}",
                path=str(filepath),
                line=line,
                name=f"K8s TLS Secret ({name})",
                category="certificate",
                is_pqc_vulnerable=True,  # Assume vulnerable until verified
                description="Kubernetes TLS secret. Certificate key algorithm should be verified for PQC readiness.",
                remediation="Verify certificate uses PQC-ready algorithms. Consider hybrid certificates when available.",
                source_type="infra"
            ))
    
    def _analyze_ingress(self, filepath: Path, doc: Dict, content: str):
        """Analyze Ingress TLS configuration."""
        metadata = doc.get("metadata", {})
        name = metadata.get("name", "unknown")
        annotations = metadata.get("annotations", {})
        spec = doc.get("spec", {})
        
        line = self._find_line_number(content, name)
        
        # Check for TLS configuration
        tls_configs = spec.get("tls", [])
        for tls in tls_configs:
            secret_name = tls.get("secretName", "")
            hosts = tls.get("hosts", [])
            
            self.suspects.append(Suspect(
                path=str(filepath),
                line=line,
                content_snippet=f"Ingress '{name}' TLS config using secret '{secret_name}'",
                type="infra",
                pattern_matched="K8s_Ingress_TLS",
                confidence="high"
            ))
            
            self.findings.append(InventoryItem(
                id=f"{filepath}:{line}:{name}:tls",
                path=str(filepath),
                line=line,
                name=f"K8s Ingress TLS ({name})",
                category="network",
                is_pqc_vulnerable=True,
                description=f"Ingress TLS configuration for hosts: {', '.join(hosts)}. Uses secret '{secret_name}'.",
                remediation="Ensure TLS certificates use PQC-ready key algorithms.",
                source_type="infra"
            ))
        
        # Check for SSL/TLS annotations (nginx-ingress, traefik, etc.)
        ssl_annotations = {
            "nginx.ingress.kubernetes.io/ssl-protocols": "SSL protocol versions",
            "nginx.ingress.kubernetes.io/ssl-ciphers": "SSL cipher suites",
            "traefik.ingress.kubernetes.io/frontend-entry-points": "TLS entry points",
        }
        
        for anno_key, desc in ssl_annotations.items():
            if anno_key in annotations:
                anno_value = annotations[anno_key]
                
                # Check for weak TLS versions
                is_weak = any(weak in anno_value for weak in self.WEAK_TLS_VERSIONS)
                
                if is_weak:
                    self.suspects.append(Suspect(
                        path=str(filepath),
                        line=line,
                        content_snippet=f"Ingress '{name}' uses weak TLS: {anno_value}",
                        type="infra",
                        pattern_matched="K8s_Weak_TLS",
                        confidence="high"
                    ))
    
    def _analyze_certificate(self, filepath: Path, doc: Dict, content: str):
        """Analyze cert-manager Certificate resource."""
        metadata = doc.get("metadata", {})
        name = metadata.get("name", "unknown")
        spec = doc.get("spec", {})
        
        line = self._find_line_number(content, name)
        
        # Check key algorithm
        private_key = spec.get("privateKey", {})
        algorithm = private_key.get("algorithm", "RSA")  # Default is RSA
        key_size = private_key.get("size", 2048)
        
        algorithm_lower = algorithm.lower()
        is_vulnerable = any(vuln in algorithm_lower for vuln in self.VULNERABLE_KEY_ALGORITHMS)
        
        self.suspects.append(Suspect(
            path=str(filepath),
            line=line,
            content_snippet=f"cert-manager Certificate '{name}' uses {algorithm}-{key_size}",
            type="infra",
            pattern_matched=f"K8s_CertManager_{algorithm}",
            confidence="high"
        ))
        
        self.findings.append(InventoryItem(
            id=f"{filepath}:{line}:{name}",
            path=str(filepath),
            line=line,
            name=f"cert-manager Certificate ({name})",
            category="certificate",
            algorithm=f"{algorithm}-{key_size}",
            key_size=key_size,
            is_pqc_vulnerable=is_vulnerable,
            description=f"cert-manager managed certificate using {algorithm} with {key_size}-bit key.",
            remediation="Prepare for migration to PQC algorithms when cert-manager supports them.",
            source_type="infra"
        ))
    
    def _analyze_cluster_issuer(self, filepath: Path, doc: Dict, content: str):
        """Analyze cert-manager ClusterIssuer."""
        self._analyze_issuer_common(filepath, doc, content, "ClusterIssuer")
    
    def _analyze_issuer(self, filepath: Path, doc: Dict, content: str):
        """Analyze cert-manager Issuer."""
        self._analyze_issuer_common(filepath, doc, content, "Issuer")
    
    def _analyze_issuer_common(self, filepath: Path, doc: Dict, content: str, kind: str):
        """Common analysis for Issuer/ClusterIssuer resources."""
        metadata = doc.get("metadata", {})
        name = metadata.get("name", "unknown")
        spec = doc.get("spec", {})
        
        line = self._find_line_number(content, name)
        
        # Check if ACME issuer
        acme = spec.get("acme", {})
        if acme:
            server = acme.get("server", "")
            private_key_ref = acme.get("privateKeySecretRef", {}).get("name", "")
            
            self.suspects.append(Suspect(
                path=str(filepath),
                line=line,
                content_snippet=f"{kind} '{name}' ACME issuer - key in secret '{private_key_ref}'",
                type="infra",
                pattern_matched=f"K8s_CertManager_{kind}_ACME",
                confidence="medium"
            ))
    
    def _analyze_configmap(self, filepath: Path, doc: Dict, content: str):
        """Analyze ConfigMap for crypto-related configurations."""
        metadata = doc.get("metadata", {})
        name = metadata.get("name", "unknown")
        data = doc.get("data", {})
        
        # Look for TLS/crypto related keys
        crypto_indicators = ["tls", "ssl", "cert", "key", "cipher", "crypto", "pem", "crt"]
        
        for key, value in data.items():
            key_lower = key.lower()
            if any(indicator in key_lower for indicator in crypto_indicators):
                line = self._find_line_number(content, key)
                
                self.suspects.append(Suspect(
                    path=str(filepath),
                    line=line,
                    content_snippet=f"ConfigMap '{name}' contains crypto config: {key}",
                    type="infra",
                    pattern_matched="K8s_ConfigMap_Crypto",
                    confidence="low"
                ))
    
    def _analyze_service(self, filepath: Path, doc: Dict, content: str):
        """Analyze Service annotations for TLS configuration."""
        metadata = doc.get("metadata", {})
        name = metadata.get("name", "unknown")
        annotations = metadata.get("annotations", {})
        
        # Check for cloud provider TLS annotations
        tls_annotations = [
            "service.beta.kubernetes.io/aws-load-balancer-ssl-cert",
            "service.beta.kubernetes.io/aws-load-balancer-ssl-negotiation-policy",
            "cloud.google.com/backend-config",
        ]
        
        for anno in tls_annotations:
            if anno in annotations:
                line = self._find_line_number(content, anno)
                
                self.suspects.append(Suspect(
                    path=str(filepath),
                    line=line,
                    content_snippet=f"Service '{name}' has TLS annotation: {anno}",
                    type="infra",
                    pattern_matched="K8s_Service_TLS",
                    confidence="medium"
                ))
    
    def get_inventory(self) -> List[InventoryItem]:
        """Return inventory items from scan."""
        return self.findings
