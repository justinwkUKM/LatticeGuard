# LatticeGuard PQC Assessment Roadmap

This document outlines the planned improvements for the LatticeGuard PQC Assessment tool to reach Enterprise-Grade maturity.

## Phase 1: Deep Analysis & Coverage (Short Term)
- **AST-Based Scanning**: Move beyond pattern matching. Use Abstract Syntax Trees (AST) to identify exactly how cryptographic libraries (like `cryptography` in Python or `WebCrypto` in JS) are being invoked.
- **Secret Scanning Integration**: Integrate with `trufflehog` or `gitleaks` to automatically identify hardcoded keys during the Fast Scan phase.
- **Support for more Manifests**: Add support for Go (`go.mod`), Rust (`Cargo.toml`), and Java (`pom.xml`).

## Phase 2: DevOps & Automation (Medium Term)
- **CI/CD Plugins**: Create GitHub Actions and GitLab CI components to run PQC scans on every Pull Request.
- **GitHub PR Comments**: Automatically comment on PRs when new PQC-vulnerable code is introduced, including the AI reasoning.
- **Centralized Dashboard**: A web-based UI (using the existing SQLite DB) to visualize PQC risk trends across multiple repositories.

## Phase 3: Automated Remediation (Long Term)
- **Remediation Agent**: A specialized AI agent that not only identifies vulnerabilities but also generates a "Fix Branch" with the necessary code changes (e.g., swapping RSA for ML-KEM).
- **Compliance Mapping**: Map all findings directly to NIST SP 800-208 and CNSA 2.0 requirements for regulatory reporting.
- **Binary Scanning**: Ability to scan compiled artifacts (binaries/containers) for linked cryptographic libraries.
