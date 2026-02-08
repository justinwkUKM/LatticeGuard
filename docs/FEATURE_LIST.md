# LatticeGuard Enterprise Feature List

## Current Capabilities

### ✅ Implemented

| Feature | Module | Description |
|---------|--------|-------------|
| Python SAST | `ast_scanner.py` | AST-based crypto call detection |
| Go SAST | `go_ast_scanner.py` | Go crypto package analysis |
| JavaScript SAST | `js_scanner.py` | Node.js crypto detection |
| Java SAST | `treesitter_scanner.py` | Tree-sitter AST detection for Java |
| C++ SAST | `treesitter_scanner.py` | Tree-sitter AST detection for C++ |
| Terraform IaC | `terraform_json_scanner.py` | KMS, TLS config parsing |
| CloudFormation IaC| `cloudformation.py` | AWS crypto resource analysis |
| Kubernetes IaC | `scanner/kubernetes.py` | K8s manifest & secret analysis |
| Suppression Rules | `scanner/suppression.py` | Glob-based findings filtering |
| Cloud Discovery | `scanner/cloud_discovery.py`| Multi-cloud (AWS/GCP/Azure) asset scan |
| Inventory Sync | `cli/cicd_scanner.py` | Auto-sync scan results to DB |
| CBOM Export | `schemas/cbom.py` | CycloneDX 1.6 Cryptographic BOM |
| TLS Fingerprinting| `network.py` | TLS version & cipher suite detection |
| Cert Extraction | `network.py` | X.509 certificate chain analysis |
| HNDL Scoring | `cli/cicd_scanner.py` | Harvest Now, Decrypt Later risk scoring |
| Blast Radius | `/blast-radius` | D3.js dependency visualization |
| Crypto Agility | `/agility` | Algorithm registry & tracking |
| CI/CD Pipeline | `action.yml` | GitHub Actions & CLI integration |
| PDF Reports | `reporting/pdf_generator.py`| Comprehensive compliance PDF export |
| Dependency SCA | `dependencies.py` | Transitive resolution for Go/Python |
| Git History | `git_scanner.py` | Secret/key commit history |
| AI Secret Triage| `secret_scanner.py` | Gemini-based credential filtering |
| Live Verification| `secret_scanner.py` | AWS/GitHub API key validation |
| Protocol Auditor| `network.py` | Active PQC handshake simulation |
| EASM | `scanner/easm.py` | Shadow IT & legacy protocol discovery |
| Resilience Score| `network.py` | 0-100 Quantum readiness metric |
| AI Remediation | Worker + Gemini | PQC migration guidance |

### ⚠️ Partial

| Feature | Gap |
|---------|-----|
| Multi-Cloud Discovery | GCP/Azure support in development |

### ❌ Missing

| Feature | Priority |
|---------|----------|
| Cryptographic Inventory (Auto-sync) | High |
| Multi-Cloud Asset Discovery | Medium |

---

## Implementation Roadmap

## Implementation Roadmap

### Phase 1: Foundation ✅ COMPLETED
- CBOM Schema (CycloneDX 1.6)
- Certificate Chain Extraction
- TLS Version Fingerprinting

### Phase 2: Enterprise Core ✅ COMPLETED
- CI/CD CLI with exit codes
- GitHub Actions integration
- HNDL Risk Scoring with data longevity

### Phase 3: Intelligence Layer ⬅️ CURRENT
- [x] Blast Radius visualization (D3.js)
- [x] Cryptographic Agility tracking
- [ ] Suppression rules & ignore lists (Logic integration)

### Phase 4: Advanced
- [x] Kubernetes manifest parsing
- [x] PDF compliance reports
- [ ] Multi-cloud asset auto-discovery

---

## Quick Reference

```bash
# Start full stack
docker compose up -d

# Trigger scan
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_path": "/path/to/repo"}'

# Export report
curl http://localhost:8000/reports/export/{run_id}?format=json
```
