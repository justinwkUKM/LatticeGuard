"""
External Attack Surface Management (EASM) Module
Discovering shadow IT and legacy protocols that increase HNDL risk.
"""
import socket
import os
import json
from typing import List, Dict, Optional
from schemas.models import InventoryItem

class EASMScanner:
    """
    Scans for external assets and legacy protocols.
    Supports API hooks for Shodan/Censys and active port auditing.
    """
    
    # Legacy protocols with high HNDL (Harvest Now, Decrypt Later) risk
    LEGACY_PROTOCOLS = {
        21: {"name": "FTP", "risk": "critical", "description": "Unencrypted file transfer. Highly vulnerable to interception."},
        23: {"name": "Telnet", "risk": "critical", "description": "Unencrypted remote shell. Credentials sent in cleartext."},
        110: {"name": "POP3", "risk": "high", "description": "Unencrypted email retrieval."},
        143: {"name": "IMAP", "risk": "high", "description": "Unencrypted email access."},
        3389: {"name": "RDP", "risk": "medium", "description": "Remote Desktop. Ensure NLA and strong TLS are enforced."},
        5900: {"name": "VNC", "risk": "high", "description": "Unencrypted remote desktop. Limited crypto agility."},
    }

    def __init__(self, target_cidr: str = "127.0.0.1"):
        self.target = target_cidr
        self.shodan_api_key = os.getenv("SHODAN_API_KEY")
        
    def discover_shadow_it(self) -> List[InventoryItem]:
        """
        Main discovery loop for external assets.
        """
        findings = []
        
        # 1. API-based discovery (if keys present)
        if self.shodan_api_key:
            findings.extend(self._query_shodan())
            
        # 2. Basic active protocol audit for legacy services
        findings.extend(self._active_protocol_audit())
        
        return findings

    def _query_shodan(self) -> List[InventoryItem]:
        """Placeholder for Shodan API integration"""
        # Logic to query Shodan for the target CIDR/Host
        # looking for 'pqc' tags or legacy banners
        print(f"[*] Querying Shodan for {self.target}...")
        return []

    def _active_protocol_audit(self) -> List[InventoryItem]:
        """
        Checks for common legacy ports that are low-agility.
        """
        findings = []
        # For demonstration/safety, we only check a single host or small range
        target_host = self.target.split('/')[0] if '/' in self.target else self.target
        
        print(f"[*] Auditing legacy protocols on {target_host}...")
        
        for port, info in self.LEGACY_PROTOCOLS.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.0)
                    result = s.connect_ex((target_host, port))
                    if result == 0:
                        findings.append(InventoryItem(
                            id=f"easm:{target_host}:{port}",
                            path=f"{target_host}:{port}",
                            line=0,
                            name=f"Shadow IT: {info['name']} Service Detected",
                            category="network",
                            algorithm="None/Legacy",
                            key_size=0,
                            is_pqc_vulnerable=True,
                            description=f"Legacy protocol {info['name']} detected. {info['description']}",
                            remediation=f"Disable {info['name']} and migrate to encrypted alternatives (SFTP, SSH, IMAPS).",
                            source_type="network",
                            risk_level=info["risk"],
                            hndl_score=90.0
                        ))
            except Exception:
                continue
                
        return findings
