"""
CloudFormation Template Scanner
Parses AWS CloudFormation YAML/JSON templates to identify PQC-vulnerable cryptographic configurations.
"""
import json
import os
from pathlib import Path
from typing import List, Dict, Optional
import re

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from schemas.models import Suspect, InventoryItem


class CloudFormationScanner:
    """
    Scans AWS CloudFormation templates for cryptographic configurations:
    - KMS Key algorithms and key specs
    - ACM Certificate settings
    - ELB/ALB TLS policies
    - RDS encryption
    - S3 bucket encryption
    - Lambda environment encryption
    """
    
    # PQC-vulnerable KMS key specs
    VULNERABLE_KEY_SPECS = {
        "RSA_2048": {"risk": "high", "desc": "RSA-2048 key. Vulnerable to Shor's algorithm."},
        "RSA_3072": {"risk": "high", "desc": "RSA-3072 key. Vulnerable to Shor's algorithm."},
        "RSA_4096": {"risk": "medium", "desc": "RSA-4096 key. Larger key but still Shor-vulnerable."},
        "ECC_NIST_P256": {"risk": "high", "desc": "NIST P-256 curve. Vulnerable to Shor's algorithm."},
        "ECC_NIST_P384": {"risk": "high", "desc": "NIST P-384 curve. Vulnerable to Shor's algorithm."},
        "ECC_NIST_P521": {"risk": "medium", "desc": "NIST P-521 curve. Vulnerable to Shor's algorithm."},
        "ECC_SECG_P256K1": {"risk": "high", "desc": "secp256k1 curve. Vulnerable to Shor's algorithm."},
        "HMAC_224": {"risk": "low", "desc": "HMAC with SHA-224. Symmetric, but weak hash."},
        "HMAC_256": {"risk": "low", "desc": "HMAC with SHA-256. Symmetric, quantum-resistant."},
        "HMAC_384": {"risk": "low", "desc": "HMAC with SHA-384. Symmetric, quantum-resistant."},
        "HMAC_512": {"risk": "low", "desc": "HMAC with SHA-512. Symmetric, quantum-resistant."},
        "SYMMETRIC_DEFAULT": {"risk": "low", "desc": "AES-256-GCM. Symmetric, quantum-resistant."},
    }
    
    # Deprecated TLS policies
    DEPRECATED_TLS_POLICIES = {
        "ELBSecurityPolicy-2016-08": {"risk": "high", "desc": "Legacy policy. Allows TLS 1.0."},
        "ELBSecurityPolicy-TLS-1-0-2015-04": {"risk": "critical", "desc": "TLS 1.0 policy. Deprecated."},
        "ELBSecurityPolicy-TLS-1-1-2017-01": {"risk": "high", "desc": "TLS 1.1 policy. Deprecated."},
        "ELBSecurityPolicy-2015-05": {"risk": "critical", "desc": "Legacy policy. Weak ciphers."},
    }
    
    # Recommended TLS policies (still PQC-vulnerable but current best practice)
    CURRENT_TLS_POLICIES = {
        "ELBSecurityPolicy-TLS13-1-2-2021-06": "TLS 1.3 with 1.2 fallback",
        "ELBSecurityPolicy-TLS13-1-3-2021-06": "TLS 1.3 only",
        "ELBSecurityPolicy-FS-1-2-Res-2020-10": "Forward Secrecy with TLS 1.2",
    }
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.findings: List[InventoryItem] = []
        self.suspects: List[Suspect] = []
    
    def scan(self) -> List[Suspect]:
        """Scan repository for CloudFormation templates"""
        cf_patterns = ["*.yaml", "*.yml", "*.json", "*.template"]
        exclude_dirs = {'.git', 'node_modules', 'venv', '.terraform', '__pycache__'}
        
        for dirpath, dirnames, filenames in os.walk(self.repo_path):
            dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
            
            for filename in filenames:
                filepath = Path(dirpath) / filename
                
                # Check if it's a potential CF template
                if any(filepath.suffix == ext.replace("*", "") for ext in [".yaml", ".yml", ".json", ".template"]):
                    self._scan_file(filepath)
        
        return self.suspects
    
    def _scan_file(self, filepath: Path) -> None:
        """Scan a single file for CloudFormation resources"""
        try:
            content = filepath.read_text()
            
            # Quick check for CloudFormation markers
            if not self._is_cloudformation(content):
                return
            
            # Parse the template
            template = self._parse_template(content, filepath)
            if not template:
                return
            
            # Scan resources
            resources = template.get("Resources", {})
            for resource_name, resource_def in resources.items():
                resource_type = resource_def.get("Type", "")
                properties = resource_def.get("Properties", {})
                
                # KMS Keys
                if resource_type == "AWS::KMS::Key":
                    self._analyze_kms_key(filepath, resource_name, properties)
                
                # ACM Certificates
                elif resource_type == "AWS::CertificateManager::Certificate":
                    self._analyze_acm_cert(filepath, resource_name, properties)
                
                # Application Load Balancer Listeners
                elif resource_type in ["AWS::ElasticLoadBalancingV2::Listener", "AWS::ElasticLoadBalancing::LoadBalancer"]:
                    self._analyze_elb_listener(filepath, resource_name, properties, resource_type)
                
                # RDS Instances
                elif resource_type in ["AWS::RDS::DBInstance", "AWS::RDS::DBCluster"]:
                    self._analyze_rds(filepath, resource_name, properties)
                
                # S3 Buckets
                elif resource_type == "AWS::S3::Bucket":
                    self._analyze_s3_bucket(filepath, resource_name, properties)
                
                # Lambda Functions
                elif resource_type == "AWS::Lambda::Function":
                    self._analyze_lambda(filepath, resource_name, properties)
                    
        except Exception as e:
            print(f"Error scanning {filepath}: {e}")
    
    def _is_cloudformation(self, content: str) -> bool:
        """Check if content looks like CloudFormation"""
        cf_markers = [
            "AWSTemplateFormatVersion",
            "AWS::CloudFormation",
            "AWS::KMS",
            "AWS::Lambda",
            "AWS::S3",
            "AWS::RDS",
            "AWS::EC2",
            '"Resources"',
            "Resources:",
        ]
        return any(marker in content for marker in cf_markers)
    
    def _parse_template(self, content: str, filepath: Path) -> Optional[Dict]:
        """Parse CloudFormation template (YAML or JSON)"""
        # Try JSON first
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass
        
        # Try YAML
        if HAS_YAML:
            try:
                return yaml.safe_load(content)
            except yaml.YAMLError:
                pass
        
        return None
    
    def _find_line_number(self, filepath: Path, search_term: str) -> int:
        """Find line number containing search term"""
        try:
            content = filepath.read_text()
            for i, line in enumerate(content.splitlines(), 1):
                if search_term in line:
                    return i
        except:
            pass
        return 0
    
    def _analyze_kms_key(self, filepath: Path, resource_name: str, properties: Dict):
        """Analyze KMS Key configuration"""
        key_spec = properties.get("KeySpec", "SYMMETRIC_DEFAULT")
        key_usage = properties.get("KeyUsage", "ENCRYPT_DECRYPT")
        
        line = self._find_line_number(filepath, resource_name)
        
        if key_spec in self.VULNERABLE_KEY_SPECS:
            info = self.VULNERABLE_KEY_SPECS[key_spec]
            
            self.suspects.append(Suspect(
                path=str(filepath),
                line=line,
                content_snippet=f"KMS Key '{resource_name}' uses {key_spec}",
                type="infra",
                pattern_matched=key_spec,
                confidence="high"
            ))
            
            self.findings.append(InventoryItem(
                id=f"{filepath}:{line}:{resource_name}",
                path=str(filepath),
                line=line,
                name=f"AWS KMS Key ({resource_name})",
                category="kms",
                algorithm=key_spec,
                key_size=self._extract_key_size(key_spec),
                is_pqc_vulnerable=info["risk"] in ["high", "critical", "medium"],
                description=info["desc"],
                remediation="For signing, prepare for ML-DSA migration. For encryption, SYMMETRIC_DEFAULT (AES-256) is quantum-resistant."
            ))
    
    def _analyze_acm_cert(self, filepath: Path, resource_name: str, properties: Dict):
        """Analyze ACM Certificate configuration"""
        domain = properties.get("DomainName", "unknown")
        key_algorithm = properties.get("KeyAlgorithm", "RSA_2048")
        
        line = self._find_line_number(filepath, resource_name)
        
        # All current ACM algorithms are PQC-vulnerable
        self.suspects.append(Suspect(
            path=str(filepath),
            line=line,
            content_snippet=f"ACM Certificate '{resource_name}' for {domain}",
            type="infra",
            pattern_matched=key_algorithm,
            confidence="high"
        ))
        
        self.findings.append(InventoryItem(
            id=f"{filepath}:{line}:{resource_name}",
            path=str(filepath),
            line=line,
            name=f"ACM Certificate ({domain})",
            category="certificate",
            algorithm=key_algorithm,
            key_size=self._extract_key_size(key_algorithm),
            is_pqc_vulnerable=True,
            description=f"ACM Certificate using {key_algorithm}. All current ACM key algorithms are quantum-vulnerable.",
            remediation="Monitor AWS for PQC certificate support. Plan for hybrid certificate deployment."
        ))
    
    def _analyze_elb_listener(self, filepath: Path, resource_name: str, properties: Dict, resource_type: str):
        """Analyze ELB/ALB TLS policy"""
        ssl_policy = properties.get("SslPolicy", properties.get("SSLCertificateId", ""))
        
        if not ssl_policy:
            return
        
        line = self._find_line_number(filepath, resource_name)
        
        if ssl_policy in self.DEPRECATED_TLS_POLICIES:
            info = self.DEPRECATED_TLS_POLICIES[ssl_policy]
            
            self.suspects.append(Suspect(
                path=str(filepath),
                line=line,
                content_snippet=f"Load Balancer '{resource_name}' uses deprecated TLS policy",
                type="infra",
                pattern_matched=ssl_policy,
                confidence="high"
            ))
            
            self.findings.append(InventoryItem(
                id=f"{filepath}:{line}:{resource_name}",
                path=str(filepath),
                line=line,
                name=f"ELB/ALB TLS Policy ({resource_name})",
                category="network",
                algorithm=ssl_policy,
                is_pqc_vulnerable=True,
                description=info["desc"],
                remediation="Upgrade to ELBSecurityPolicy-TLS13-1-2-2021-06 or newer. Disable TLS 1.0/1.1."
            ))
    
    def _analyze_rds(self, filepath: Path, resource_name: str, properties: Dict):
        """Analyze RDS encryption settings"""
        storage_encrypted = properties.get("StorageEncrypted", False)
        kms_key_id = properties.get("KmsKeyId", "")
        
        line = self._find_line_number(filepath, resource_name)
        
        if not storage_encrypted:
            self.suspects.append(Suspect(
                path=str(filepath),
                line=line,
                content_snippet=f"RDS '{resource_name}' has encryption disabled",
                type="infra",
                pattern_matched="StorageEncrypted=false",
                confidence="high"
            ))
            
            self.findings.append(InventoryItem(
                id=f"{filepath}:{line}:{resource_name}",
                path=str(filepath),
                line=line,
                name=f"RDS Database ({resource_name})",
                category="database",
                algorithm="None",
                is_pqc_vulnerable=True,
                description="RDS instance has storage encryption disabled. Data at rest is unprotected.",
                remediation="Enable StorageEncrypted and specify a KMS key."
            ))
    
    def _analyze_s3_bucket(self, filepath: Path, resource_name: str, properties: Dict):
        """Analyze S3 bucket encryption"""
        encryption_config = properties.get("BucketEncryption", {})
        
        if not encryption_config:
            line = self._find_line_number(filepath, resource_name)
            
            self.suspects.append(Suspect(
                path=str(filepath),
                line=line,
                content_snippet=f"S3 Bucket '{resource_name}' missing encryption config",
                type="infra",
                pattern_matched="BucketEncryption=missing",
                confidence="medium"
            ))
    
    def _analyze_lambda(self, filepath: Path, resource_name: str, properties: Dict):
        """Analyze Lambda KMS encryption"""
        kms_key_arn = properties.get("KmsKeyArn", "")
        
        # If KMS key is specified, it will be analyzed separately
        # Here we just note if environment variables are unencrypted
        environment = properties.get("Environment", {})
        variables = environment.get("Variables", {})
        
        if variables and not kms_key_arn:
            line = self._find_line_number(filepath, resource_name)
            
            self.suspects.append(Suspect(
                path=str(filepath),
                line=line,
                content_snippet=f"Lambda '{resource_name}' has env vars without KMS encryption",
                type="infra",
                pattern_matched="KmsKeyArn=missing",
                confidence="medium"
            ))
    
    def _extract_key_size(self, key_spec: str) -> Optional[int]:
        """Extract key size from key spec string"""
        match = re.search(r'(\d+)', key_spec)
        if match:
            return int(match.group(1))
        return None
    
    def get_inventory(self) -> List[InventoryItem]:
        """Return inventory items from scan"""
        return self.findings
