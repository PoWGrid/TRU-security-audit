# Audit Track 12 — Cross-Chain HTLC Atomic Swaps & Reorganization Expiry Race Protection

- **Component:** Cross-Chain / Hashed Time-Lock Contract (HTLC) & Swap Engine
- **Target Files:** `projects/tru/nodes/core/src/tru_swap_prepared_funding_guard.h`, `projects/tru/nodes/core/src/rpc_server.cpp`
- **Severity:** Medium (CVSS 6.8)
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization, CWE-682: Incorrect Calculation

---

## 1. Vulnerability Summary
TRU Cross-Chain Atomic Swaps (`TRU-SWAP-V1`) use hashlocks with timelocks for atomic swap settlement. When claiming an HTLC swap after counterparty funding, if a 1- or 2-block chain reorganization occurs around the timelock expiration timestamp, a race condition arises where the refund transaction and claim transaction can both be valid on alternate branches. If the refunding party observes the preimage published on-chain during a shallow reorg, they may attempt to reorganize the block and reclaim funds via the timelock refund branch while keeping counterparty assets on the other chain.

## 2. Root Cause Analysis
In `src/rpc_server.cpp`:
```cpp
// HTLC claim and refund operations:
const auto result = wallet.claimHtlcAtomicSwapV1(...);
const auto result = wallet.refundHtlcAtomicSwapV1(...);
```
In `tru_swap_prepared_funding_guard.h`, local prepared funding reservations track UTXOs in local memory (`std::recursive_mutex& mutex()`), but do not enforce a **timelock safety margin** (e.g. `MIN_REORG_SAFETY_BLOCKS = 6`). If an automated swap coordinator broadcasts a claim transaction when `lockTime` is within 10 minutes of expiry, any block propagation delay or micro-reorg can push the block timestamp past `lockTime`, allowing the funder to broadcast `refundHtlcAtomicSwapV1()` concurrently. Because the claim transaction revealed the preimage on the P2P network, the funder acquires the preimage for free while also reclaiming their original deposit.

## 3. Impact
- Risk of cross-chain fund loss during atomic swaps when claiming near the timelock expiration boundary.
- Counterparty griefing via shallow reorganizations around locktime boundaries.

## 4. Remediation & Defensive Patch
Enforce an asymmetric timelock buffer in `prepareHtlcAtomicSwapV1()`: the claim window must expire at least 7200 seconds (2 hours) before the refund window opens:

```diff
--- a/projects/tru/nodes/core/src/rpc_server.cpp
+++ b/projects/tru/nodes/core/src/rpc_server.cpp
@@ -8295,6 +8295,11 @@ static json handleHtlcPrepareSwap(...) {
+    // Enforce minimum 2-hour delta between claim and refund timelocks
+    if (refundLockTime <= claimLockTime + 7200U) {
+        return makeError(-32602, "HTLC refund locktime must be at least 7200 seconds greater than claim locktime");
+    }
```
