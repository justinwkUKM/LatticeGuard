# Banking Legacy System

This module handles sensitive customer financial data, including transaction history and account balances.

## Risk Context
- **Data Sensitivity**: Confidential / Financial
- **Data Longevity**: 10 years (Regulatory requirement for audit trails)

LatticeGuard will identify that the RSA-1024 keys used here are vulnerable to harvest-now-decrypt-later (HNDL) attacks because the data must remain secret for a decade, while quantum computers are expected to break RSA within that timeframe.
