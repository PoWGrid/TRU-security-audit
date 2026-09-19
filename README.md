# TRU Core 0.05 Security Audit Framework

[![Scope](https://img.shields.io/badge/Target-TRU%20Core%20v0.05%2B-blue.svg)](https://github.com/TokenizedRealUtility/TRU-Core)
[![Mode](https://img.shields.io/badge/Mode-Analyze%20%26%20Defend-green.svg)]()
[![Tracks](https://img.shields.io/badge/Audit%20Tracks-15%20Verified%20Vectors-orange.svg)]()

Comprehensive security analysis, vulnerability discovery, consensus invariant auditing, and defensive patch engineering for **Tokenized Real Utility (TRU)** Core C++ codebase.

---

## 🧭 Repository Structure

```
TRU-security-audit/
├── README.md                              # Audit framework overview & guidelines
└── round_1/                               # Round 1: Core 0.05 Comprehensive Vulnerability Sweep
    ├── AUDIT_PLAN_15_TRACKS.md            # Detailed scope & attack surface allocation
    ├── sandbox/                           # Isolated testnet / regtest harness (ports 21842/21843)
    ├── findings/
    │   ├── active_mainnet/                # 8 High-priority tracks directly affecting mainnet (Tracks 01-08)
    │   └── for_review/                    # 7 Architectural & deep hardening tracks (Tracks 09-15)
    ├── verify_active_tracks.py            # Automated vulnerability detector & regression verifier
    └── TRU_CORE_005_SECURITY_AUDIT_REPORT.md # Master executive vulnerability & remediation report
```

---

## 🛡️ Responsible Disclosure & Safety Policy

This audit strictly operates under the **Analyze & Defend** methodology:
- **Zero Weaponization:** No functional exploit payloads, attack scripts, or weaponized attack tools are developed or distributed.
- **Defensive Engineering:** Every identified weakness or vulnerability is documented with:
  1. Exact C++ source location and root cause analysis.
  2. Severity classification (CWE & estimated CVSS v3 score).
  3. Potential protocol impact (DoS, consensus divergence, state corruption, funds loss).
  4. Production-grade defensive C++ patch for TRU Core developers.
  5. Non-destructive regression verification tests.

---

## 🚀 Developer Quickstart: 15-Track Invariant & Vulnerability Verifier

To allow TRU Core developers to independently audit their codebase and verify hotfixes across all audit vectors without running offensive exploits, Round 1 includes an automated **Invariant & Vulnerability Detector** (`verify_active_tracks.py`).

### Running the Verifier

```bash
# Navigate to the Round 1 audit directory
cd round_1

# Run the comprehensive 15-track vulnerability inspector
python3 verify_active_tracks.py
```

### Understanding Output Sections

The verifier executes across both audit divisions:
1. **Section 1: Active Mainnet Tracks (Tracks 01 to 08):** Immediate vulnerabilities directly affecting consensus, serialization, tokens, mempool, RPC, and cryptographic malleability.
2. **Section 2: Architectural Hardening Tracks (Tracks 09 to 15):** Network timeouts, atomic reorg rollbacks, living token queue isolation, HTLC safety margin, RPC token bounding, wallet mlock/zeroing, and log injection guards.

| Status Indicator | Interpretation | Action Required |
|---|---|---|
| `[FAIL ❌ VULNERABLE]` | The vulnerability signature or architectural defect is present in the C++ source. | Apply the recommended defensive patch specified in the track finding. |
| `[PASS ✅ FIXED]` | The defensive guard or invariant correction is detected in the source. | Codebase is protected against this regression vector. |

### Exit Codes for CI/CD Integration

- **`0`**: All 15 verified tracks are compliant and patched.
- **`1`**: One or more vulnerabilities remain unpatched in the codebase.
