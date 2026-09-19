# TRU Core v0.05 Security Audit — Round 1 Master Report

> **Audit Campaign:** Round 1 Comprehensive Source Code Audit  
> **Target Version:** TRU Core v0.05 (`commit 3d1d7bc`)  
> **Verification Methodology:** 15-Track Deep Analysis & Dual-Phase AST/Source Invariant Validation  
> **Scope:** `projects/tru/nodes/core/src/`  
> **Date:** September 2026  
> **Outcome Summary:** 15 Verified Security Findings (8 Active Mainnet + 7 Architectural Hardening)  

---

## Executive Summary

A comprehensive 15-track security audit was performed across the C++ codebase of TRU Core v0.05. Every finding has been verified against the active source repository with exact line references and concrete impact scenarios.

The 15 verified findings are organized into two operational priorities:

1. **Active Mainnet Impact (Tracks 01 to 08):** Immediate vulnerabilities affecting transaction deserialization, token balances, consensus difficulty drift, mempool dust flood, opcode execution, and RPC null pointer crash safety.
2. **Architectural Hardening & Deep Edge Cases (Tracks 09 to 15):** Defensive gaps requiring specific network socket anomalies, multi-block chain reorganizations, physical process memory dumps, or unbounded input headers.

---

## Part 1: Active Mainnet Vulnerabilities (Immediate Action Required)

| Track | Subsystem | Vulnerability Summary | Severity | CWE | Status |
|---|---|---|---|---|---|
| **[Track 01](findings/active_mainnet/TRACK_01_BINARY_SERIALIZATION_VARINT.md)** | Serialization | **VarInt Double-Increment Cursor Desync:** `readVarInt()` executes double `pos` increments on 0xFE/0xFF prefixes, corrupting transactions $\ge 64$ KB. | **CRITICAL** (9.1) | CWE-193 / CWE-125 | Unpatched (0/1) |
| **[Track 02](findings/active_mainnet/TRACK_02_TOKEN_SUPPLY_ARITHMETIC_OVERFLOW.md)** | Tokens & SFT | **Token Supply Inflation via Self-Transfer:** Self-transfers (`from == to`) overwrite balance subtractions in LevelDB batches, allowing unlimited token doubling. | **CRITICAL** (9.3) | CWE-840 / CWE-670 | Unpatched (0/1) |
| **[Track 03](findings/active_mainnet/TRACK_03_POW_DIFFICULTY_RETARGETING.md)** | Consensus & PoW | **PoW Retarget Off-By-One Drift:** 59 intervals measured against 60-block timespan, artificially inflating difficulty by 1.67% every retarget period. | **HIGH** (7.1) | CWE-682 / CWE-193 | Unpatched (0/1) |
| **[Track 04](findings/active_mainnet/TRACK_04_MEMPOOL_DUST_EVICTION_DOS.md)** | Mempool & UTXO | **Mempool Dust Absence:** Lack of output dust filter allows zero/sub-sat spam to permanently bloat the LevelDB UTXO database. | **HIGH** (7.5) | CWE-400 / CWE-770 | Unpatched (0/1) |
| **[Track 05](findings/active_mainnet/TRACK_05_CLTV_CSV_TIMELOCK_SAFETY.md)** | VM & Script | **Missing `OP_CHECKSEQUENCEVERIFY` Execution:** Opcode `0xb2` mapped in lexer but missing in `EvaluateScript()`, failing closed on relative timelocks. | **HIGH** (7.4) | CWE-439 / CWE-670 | Unpatched (0/1) |
| **[Track 06](findings/active_mainnet/TRACK_06_RPC_JSON_INPUT_NULL_DEREF.md)** | RPC Interface | **Storage Null Pointer Dereference:** Unguarded `chain.getStorage()->` dereferences trigger remote `SIGSEGV` node crashes on malformed requests. | **HIGH** (7.5) | CWE-476 / CWE-20 | Unpatched (0/1) |
| **[Track 07](findings/active_mainnet/TRACK_07_P2P_PROTOBUF_DESERIALIZATION.md)** | Network & P2P | **P2P Slow-Drip Frame Accumulation:** Incomplete frames lack read-timeout deadlines, allowing socket stalling and memory allocation pinning. | **MEDIUM** (5.3) | CWE-400 / CWE-20 | Unpatched (0/1) |
| **[Track 08](findings/active_mainnet/TRACK_08_CRYPTO_SIGNATURE_DER_MALLEABILITY.md)** | Cryptography | **ECDSA secp256k1 Signature Malleability:** Absence of strict BIP-62 Low-S enforcement enables txid malleability in the P2P mempool. | **MEDIUM** (6.5) | CWE-347 / CWE-327 | Unpatched (0/1) |

---

## Part 2: Confirmed Architectural Hardening & Deep Edge Cases (7 Tracks)

The following 7 tracks represent structural, resource-bounding, and memory-defense improvements in TRU Core v0.05:

| Track | Subsystem | Description & Vulnerability Vector | Severity | CWE | Status |
|---|---|---|---|---|---|
| **[Track 09](findings/for_review/TRACK_09_PEER_STATE_MACHINE_RECOVERY.md)** | Network & P2P | **Outbound Peer Handshake Timeout:** Outbound redial sockets lack application-layer handshake completion deadlines, pinning reconnection slots. | **MEDIUM** (5.9) | CWE-400 | Unpatched (0/1) |
| **[Track 10](findings/for_review/TRACK_10_UTXO_DOUBLE_SPEND_REORG_ROLLBACK.md)** | UTXO Engine | **Atomic Multi-Block Reorg Rollback:** Deep reorgs commit LevelDB WriteBatches per block. Interruption leaves split state requiring full `--reindex`. | **HIGH** (7.8) | CWE-662 / CWE-670 | Unpatched (0/1) |
| **[Track 11](findings/for_review/TRACK_11_LIVING_TOKEN_EVOLUTION_SPLIT_BRAIN.md)** | Tokens / AI | **Living Token Anchor Queue Saturation:** Global `anchor_queue` cap of 256 items allows a single token spammer to freeze evolution triggers for all tokens. | **HIGH** (8.2) | CWE-400 / CWE-770 | Unpatched (0/1) |
| **[Track 12](findings/for_review/TRACK_12_HTLC_ATOMIC_SWAP_REORG_RACE.md)** | Cross-Chain | **HTLC Timelock Reorg Race Margin:** Absence of mandatory locktime delta between claim and refund leaves cross-chain swaps vulnerable during shallow reorgs. | **MEDIUM** (6.8) | CWE-362 | Unpatched (0/1) |
| **[Track 13](findings/for_review/TRACK_13_RPC_AUTHENTICATION_TIMING_LEAKS.md)** | RPC Interface | **RPC Token Length Bounding:** `constantTimeEqual` loops over `max(lenA, lenB)` without input length ceiling, allowing CPU exhaustion via oversized headers. | **MEDIUM** (6.5) | CWE-400 / CWE-208 | Unpatched (0/1) |
| **[Track 14](findings/for_review/TRACK_14_WALLET_ENCRYPTION_SECRET_SESSION.md)** | Wallet | **In-Memory Secret Zeroing & mlock:** Wallet holds raw private key buffers in unpinned heap `std::string` without memory wiping (`sodium_memzero`) on lock. | **HIGH** (7.4) | CWE-316 / CWE-226 | Unpatched (0/1) |
| **[Track 15](findings/for_review/TRACK_15_BOUNDED_LOGGING_INJECTION_IO.md)** | Logging | **CWE-117 Log Injection Sanitization:** `Logger::formatLineLocked` prints unescaped strings, allowing malicious peer user-agents to forge authentic log lines. | **LOW** (5.3) | CWE-117 | Unpatched (0/1) |


---

## Action Plan for Developers

### Phase 1: Immediate Mainnet Hotfix (v0.05.1 — Soft Fork / Node Upgrade)
- **Track 01:** Remove double increments in `src/tx.cpp:957-966`.
- **Track 02:** Guard self-transfers in `src/tokens.cpp:310-335` (`if (fromAddress == toAddress) return true;`).
- **Track 04:** Enforce minimum output dust limit (546 atoms) in `src/mempool.cpp:1465`.
- **Track 06:** Add `nullptr` checks on `chain.getStorage()` in `src/rpc_server.cpp:2066, 3638`.
- **Track 07:** Add read deadline for incomplete P2P frame buffers in `src/peer_connection.cpp:620`.

### Phase 2: Planned Consensus Upgrade (v0.06 — Hard Fork)
- **Track 03:** Eliminate PoW retarget off-by-one drift in `src/blockchain.cpp:2944, 2997`.
- **Track 05:** Implement `OP_CHECKSEQUENCEVERIFY` in `src/script_interpreter.cpp:2475`.
- **Track 08:** Enforce strict BIP-62 Low-S in base `ECDSAKey::verify()` in `src/crypto_ecdsa.cpp:548`.

### Phase 3: Architectural Hardening Sprint (v0.07+)
- Implement the 7 architectural defense improvements documented in `findings/for_review/` (Tracks 09 to 15).

---

## Automated Regression Verification

The audit suite provides an automated Python verification script to audit local C++ source files against all 15 confirmed defect patterns:

```bash
python3 verify_active_tracks.py
```

- Returns exit code `0` when all 15 defects have been properly mitigated.
- Returns exit code `1` if any unpatched vulnerability pattern is detected.
