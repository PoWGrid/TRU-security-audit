# TRU Core 0.05 Security Audit — Round 1 Specification (15 Audit Tracks)

> **Target Version:** TRU Core v0.05 (`commit 3d1d7bc`)  
> **Source Directory:** `projects/tru/nodes/core/src/`  
> **Methodology:** Static code review, execution path tracing, boundary fuzzing hypothesis, and defensive patch engineering.  

---

## 🎯 The 15 Security Audit Tracks

### Section 1: Active Mainnet Vulnerability Tracks (Immediate Priority)

* **Track 01: Binary Serialization & VarInt Truncation**
  * *Files:* `tx.cpp`, `tx.h`, `utils.cpp`
  * *Focus:* `readVarInt`/`writeVarInt` cursor synchronization, integer overflow in payload lengths, buffer over-read on truncated inputs.
* **Track 02: Token Issuance, Supply Caps & Balance Arithmetic**
  * *Files:* `tokens.cpp`, `tokens.h`, `token_burn_v1.h`
  * *Focus:* Integer overflow in token transfers, self-transfer balance overwrite duplication, unauthorized minting, supply cap circumvention.
* **Track 03: Proof-of-Work Verification & Difficulty Retargeting**
  * *Files:* `pow.cpp`, `blockchain.cpp`, `consensus.cpp`
  * *Focus:* Retarget window boundary off-by-one errors (59 vs 60 block intervals), upward difficulty drift, timewarp attacks.
* **Track 04: Mempool Admission, Dust Boundaries & Eviction DoS**
  * *Files:* `mempool.cpp`, `mempool.h`, `tx_relay_queue_v1.h`
  * *Focus:* Minimum output dust boundary absence, zero/sub-sat spam state bloat in LevelDB UTXO database, orphan eviction.
* **Track 05: CLTV & CSV Timelock Evaluation Safety**
  * *Files:* `script_interpreter.cpp`, `tx.cpp`
  * *Focus:* Missing opcode implementations (`OP_CHECKSEQUENCEVERIFY`), sequence lock relative timelock bypasses, Median Time Past (MTP) arithmetic.
* **Track 06: RPC JSON Input Sanitization & Null Pointer Dereferences**
  * *Files:* `rpc_server.cpp`, `rpc_utils.cpp`
  * *Focus:* Missing null checks on storage pointers (`chain.getStorage()`), remote `SIGSEGV` crash vectors via invalid or uninitialized RPC calls.
* **Track 07: P2P Protobuf Deserialization & Memory Safety**
  * *Files:* `peer_connection.cpp`, `message_handler.cpp`, `p2p.cpp`
  * *Focus:* Read-timeout deadlines on partial frames, slow-drip memory accumulation attacks, socket starvation.
* **Track 08: Cryptographic Signature Enforcement & Malleability**
  * *Files:* `crypto_ecdsa.cpp`, `utils.cpp`
  * *Focus:* Strict DER parsing, BIP-62 Low-S enforcement in core signature verification, transaction ID malleability prevention.

### Section 2: Architectural Hardening & Deep Edge Cases (Secondary Priority)

* **Track 09: Peer State Machine & Auto-Recovery (`[PEER-REDIAL-01]`)**
  * *Files:* `peer_connection.cpp`, `peer_manager.cpp`, `p2p.cpp`
  * *Focus:* Outbound socket handshake deadlines, redial table slot exhaustion, backoff timer integrity.
* **Track 10: UTXO Double-Spend Prevention & Deep Chain Reorganizations**
  * *Files:* `utxo.cpp`, `utxo.h`, `blockchain.cpp`
  * *Focus:* Multi-block reorganization rollback atomicity, dirty-state UTXO caches, split-state recovery without `--reindex`.
* **Track 11: Living Token Evolution (SFT/NCFT) Global Queue Cap**
  * *Files:* `token_evolution.cpp`, `token_evolution.h`, `token_evolution_cli.cpp`
  * *Focus:* Global `anchor_queue` saturation (256 items), cross-token denial of service, fair scheduling per token identifier.
* **Track 12: Cross-Chain HTLC Atomic Swaps & Reorg Race Protection**
  * *Files:* `rpc_server.cpp`, `smart_contract.cpp`, `tru_swap_*.h`
  * *Focus:* Mandatory timelock safety delta between claim and refund, reorg race conditions during cross-chain exit.
* **Track 13: RPC Authentication & Cookie Token Enforcement**
  * *Files:* `rpc_server.cpp`, `rpc_utils.h`
  * *Focus:* Unbounded HTTP header input lengths in `constantTimeEqual`, CPU exhaustion via oversized authentication headers.
* **Track 14: Wallet Keystore In-Memory Secret Retention & Memory Locking**
  * *Files:* `wallet.h`, `wallet.cpp`, `wallet_encryption_v1.cpp`
  * *Focus:* In-memory plaintext key retention in unpinned heap strings, lack of `sodium_memzero` / `sodium_mlock` on wallet lock.
* **Track 15: Disk I/O, Bounded Logging & Log Injection Flaws**
  * *Files:* `logging.cpp`, `logging.h`, `logger.cpp`
  * *Focus:* Control character escaping (CWE-117 log injection), newline sanitization, log rotation concurrency.
