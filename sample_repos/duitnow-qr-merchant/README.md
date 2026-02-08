# DuitNow QR Merchant Payment System

This module handles merchant-side QR code generation for DuitNow instant payments.

## Risk Context
- **Data Sensitivity**: Financial / PII (Transaction amounts, Merchant IDs)
- **Data Longevity**: 7 years (Bank Negara Malaysia regulatory requirement)
- **Crypto Algorithm**: ECDSA P-256 (SHA256withECDSA)

## PQC Risk Assessment
The ECDSA algorithm used for QR signature validation is **Shor-vulnerable**. A cryptographically-relevant quantum computer (CRQC) could forge payment signatures, allowing attackers to:
1. Create fake merchant QR codes
2. Redirect funds to attacker-controlled accounts
3. Forge transaction receipts

## Remediation
Migrate to **ML-DSA (Dilithium)** or a hybrid ECDSA+ML-DSA scheme when BouncyCastle/JCE PQC providers are production-ready.
