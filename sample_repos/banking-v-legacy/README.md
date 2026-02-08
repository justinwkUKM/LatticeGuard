# Legacy Banking System - PQC Assessment Demo

This sample represents a typical **Malaysian banking legacy system** using vulnerable cryptographic algorithms.

## Business Context
- **System Type**: Core Banking / Payment Gateway
- **Data Sensitivity**: Financial (HNDL High-Risk)
- **Data Retention**: 7 years (BNM requirement for financial records)
- **Regulatory**: Bank Negara Malaysia, PCI-DSS

## Vulnerabilities Demonstrated

### 1. RSA-1024 Key Generation (Java)
```java
KeyPairGenerator.getInstance("RSA");
kpg.initialize(1024); // Shor-vulnerable
```
**Risk**: Core banking certificates using weak RSA can be forged by CRQC.

### 2. RSA/ECB/PKCS1Padding (Java)
```java
Cipher.getInstance("RSA/ECB/PKCS1Padding");
```
**Risk**: Padding oracle attacks + quantum vulnerability.

### 3. OpenSSL RSA_generate_key (C++)
```cpp
RSA_generate_key(1024, RSA_F4, NULL, NULL);
```
**Risk**: Payment gateway using deprecated, quantum-vulnerable API.

## Remediation Path
1. **Short-term**: Upgrade to RSA-3072 or ECDSA P-384.
2. **Medium-term**: Implement cryptographic agility layer.
3. **Long-term**: Migrate to ML-KEM + ML-DSA (NIST PQC standards).
