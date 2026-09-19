# Audit Track 04 — Mempool Admission Dust Boundaries & State Bloat DoS

- **Component:** Mempool / Transaction Admission Engine
- **Target Files:** `projects/tru/nodes/core/src/mempool.cpp`
- **Severity:** High (CVSS 7.5)
- **CWE:** CWE-400: Uncontrolled Resource Consumption, CWE-770: Allocation of Resources Without Limits or Throttling

---

## 1. Vulnerability Summary
While TRU RPC and wallet code define a standard dust limit (546 atoms), `Mempool::validateTransaction()` contains **zero consensus or admission-level dust checks** for transaction outputs. An attacker can broadcast transactions with hundreds or thousands of 1-atom or 0-atom outputs that consume tiny transaction fees, yet force the mempool and subsequent mining nodes to permanently expand LevelDB UTXO storage.

## 2. Root Cause Analysis
In `src/mempool.cpp`, the output loop validates only that the sum of outputs does not exceed `MAX_MONEY`:
```cpp
1080: for (size_t outIdx = 0; outIdx < tx.vout.size(); ++outIdx) {
1081:     const auto& out = tx.vout[outIdx];
1082:     if (out.amount > MAX_MONEY) return false;
1083:     totalOutput += out.amount;
1084: }
```
There is no minimum threshold check for `out.amount` (e.g. `out.amount < DUST_THRESHOLD`). Furthermore, 0-value outputs for standard P2PKH scripts are accepted without restriction.
Because UTXOs are indexed as `utxo:<txid>:<vout>` and `address:<addr>:utxo` in LevelDB, creating 10,000 outputs of 1 atom each costs only 10,000 atoms (0.0001 TRU) plus the minimal relay fee, but forces the node to allocate tens of megabytes of persistent disk state. Once confirmed into blocks, these dust UTXOs remain in the UTXO set forever because the fee required to spend them exceeds their value.

## 3. Impact
- Rapid, low-cost exhaustion of node storage (UTXO set explosion).
- Increased memory requirements for nodes during UTXO cache loading and chain reorgs.
- Eviction of higher-value economic transactions from mempool memory pools.

## 4. Remediation & Defensive Patch
Enforce an explicit standard dust threshold (e.g. 546 atoms) for all non-OP_RETURN transaction outputs at mempool admission:

```diff
--- a/projects/tru/nodes/core/src/mempool.cpp
+++ b/projects/tru/nodes/core/src/mempool.cpp
@@ -1082,6 +1082,10 @@
         if (out.amount > MAX_MONEY) return false;
+        // Enforce dust threshold for spending outputs (OP_RETURN exempted)
+        if (!out.isOpReturn() && out.amount < 546ULL) {
+            Logger::log("[Mempool] Output " + std::to_string(outIdx) + " below dust limit (546 atoms): " + tx.txid);
+            return false;
+        }
         totalOutput += out.amount;
```
