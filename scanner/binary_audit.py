"""
LatticeGuard - Post-Quantum Cryptography Assessment Tool
Copyright (c) 2026 Waqas Khalid Obeidy
"""

"""
Binary SCA (Software Composition Analysis)
Audits compiled binaries (ELF, Mach-O, PE) for embedded cryptographic signatures.
"""

import os
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class BinaryFinding:
    path: str
    algorithm: str
    signature: str
    description: str
    severity: str

class BinaryAuditScanner:
    def __init__(self):
        # Known cryptographic OIDs and magic constants (hex strings)
        self.signatures = {
            "RSA": {
                "oid": "2a864886f70d010101", # 1.2.840.113549.1.1.1
                "desc": "RSA Encryption OID found in binary sections"
            },
            "SHA-1": {
                "oid": "2a864886f70d010105", # sha1WithRSAEncryption
                "desc": "Legacy SHA-1 hashing signature found"
            },
            "ECDSA": {
                "oid": "2a8648ce3d0401", # ecdsa-with-SHA1 (legacy)
                "desc": "ECDSA signature found, likely using legacy curve/hash"
            },
            "AES_SBOX": {
                "hex": "637c777bf26b6fc53001672bfed7ab76", # First 16 bytes of AES S-Box
                "desc": "AES implementation detected via S-Box lookup table"
            }
        }

    def scan_file(self, file_path: str) -> List[BinaryFinding]:
        """Scans a single binary file for crypto signatures"""
        findings = []
        
        # Only scan binary-like extensions
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in [".so", ".a", ".o", ".dll", ".exe", ".bin", ".dylib", ""]:
            return []

        try:
            # Check if it's actually a binary file (look for ELF/Mach-O/PE headers)
            with open(file_path, "rb") as f:
                header = f.read(4)
                if not any(header.startswith(h) for h in [b"\x7fELF", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"MZ"]):
                    # Not a common binary format, but search anyway if it's a known extension
                    if ext not in [".so", ".dll", ".exe"]:
                        return []
                
                f.seek(0)
                content = f.read()
                content_hex = content.hex()

                for alg, sig_info in self.signatures.items():
                    sig = sig_info.get("oid") or sig_info.get("hex")
                    if sig and sig in content_hex:
                        findings.append(BinaryFinding(
                            path=file_path,
                            algorithm=alg,
                            signature=sig,
                            description=sig_info["desc"],
                            severity="HIGH" if alg in ["RSA", "SHA-1"] else "MEDIUM"
                        ))
        except Exception as e:
            # Skip files we can't read
            pass

        return findings

    def scan_directory(self, directory: str) -> List[BinaryFinding]:
        """Recursively scans a directory for binary findings"""
        all_findings = []
        for root, _, files in os.walk(directory):
            for file in files:
                path = os.path.join(root, file)
                all_findings.extend(self.scan_file(path))
        return all_findings
