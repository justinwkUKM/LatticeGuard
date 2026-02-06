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
    category: Literal["symmetric", "hashing", "key_exchange", "signing", "pki", "protocol", "dependency", "secret_leak"]
    algorithm: Optional[str] = None # e.g. "RSA-2048", "AES-256-GCM"
    key_size: Optional[int] = None
    is_pqc_vulnerable: bool
    description: str

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
