from typing import List, Optional, Dict, Literal
from pydantic import BaseModel, Field

# --- Phase 1: Scan Plan ---

class ScanBudget(BaseModel):
    max_files: int = 1000
    max_depth: int = 5
    max_file_bytes: int = 200 * 1024  # 200KB

class ScanPlan(BaseModel):
    run_id: str
    target_repo: str
    strategy: Literal["app", "infra", "mixed"]
    budget: ScanBudget
    prioritized_queues: Dict[str, List[str]] = Field(default_factory=dict)
    # e.g. {"hotspots": ["auth/", "crypto/"], "longtail": ["src/"]}

# --- Phase 2: Suspects ---

class Suspect(BaseModel):
    path: str
    line: int
    content_snippet: str
    type: Literal["code", "infra", "artifact", "secret"]
    pattern_matched: str
    confidence: Literal["low", "medium", "high"]

# --- Phase 3: Inventory ---

class InventoryItem(BaseModel):
    id: str  # Unique ID (e.g. file_path:line)
    path: str
    line: int
    name: str  # e.g. "RSASigner" or "tls_config"
    category: str # flexible string to accommodate AI outputs like "secret_management", "cryptographic_library", etc.
    algorithm: Optional[str] = None # e.g. "RSA-2048", "AES-256-GCM"
    key_size: Optional[int] = None
    is_pqc_vulnerable: bool
    description: str
    remediation: Optional[str] = None
    
    # Algorithm Details (Must-Capture)
    cipher_mode: Optional[str] = None  # CBC, GCM, ECB, CTR, etc.
    hash_algorithm: Optional[str] = None  # SHA-256, SHA-1, MD5, etc.
    
    # Key Lifecycle Metadata (Must-Capture)
    key_created_at: Optional[str] = None  # ISO datetime string
    key_expires_at: Optional[str] = None  # ISO datetime string
    rotation_frequency_days: Optional[int] = None  # How often key rotates
    
    # Library Info (Must-Capture)
    library_name: Optional[str] = None  # OpenSSL, BouncyCastle, PyCryptodome, etc.
    library_version: Optional[str] = None  # Version string
    
    # Protocol Details (Must-Capture)
    protocol_version: Optional[str] = None  # TLS 1.2, TLS 1.3, SSH-2, etc.
    has_pfs: Optional[bool] = None  # Perfect Forward Secrecy support
    
    # Ownership (Must-Capture)
    owner_team: Optional[str] = None  # Responsible team
    owner_contact: Optional[str] = None  # Owner email/ID
    
    # HNDL Risk Scoring (Phase 2)
    data_longevity_years: Optional[int] = None  # How long data needs protection
    data_sensitivity: Optional[Literal["public", "internal", "confidential", "secret", "pii", "financial", "health"]] = None
    hndl_score: Optional[float] = None  # Calculated HNDL risk (0-10)
    risk_level: Optional[Literal["critical", "high", "medium", "low", "info"]] = None
    
    # Metadata
    source_type: Optional[Literal["code", "infra", "network", "dependency", "secret"]] = None
    cloud_provider: Optional[Literal["aws", "gcp", "azure", "other"]] = None

class UsageLocation(BaseModel):
    path: str
    line: int
    usage_type: Literal["import", "call", "instantiation", "config"]

class CryptoRelationship(BaseModel):
    source_id: str
    target_id: str
    relation_type: Literal["uses", "configures", "loads_key_for"]

# --- Phase 4: Risk ---

class RiskAssessment(BaseModel):
    item_id: str
    risk_level: Literal["low", "medium", "high", "critical"]
    exposure: Literal["internal", "public", "dmz"]
    crypto_period: Literal["ephemeral", "long-lived", "permanent"]
    remediation_friction: Literal["low", "medium", "high"]
    notes: str

class Report(BaseModel):
    run_id: str
    summary_md: str
    risks: List[RiskAssessment]
