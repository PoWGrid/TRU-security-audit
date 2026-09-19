# Audit Track 10 — UTXO Double-Spend Prevention & Deep Chain Reorganization Rollback

- **Component:** UTXO Storage / Reorganization & Dirty State Handling
- **Target Files:** `projects/tru/nodes/core/src/utxo.cpp`, `projects/tru/nodes/core/src/blockchain.cpp`
- **Severity:** High (CVSS 7.8)
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization, CWE-703: Improper Check or Handling of Exceptional Conditions

---

## 1. Vulnerability Summary
During deep chain reorganizations, the node must disconnect blocks on the detached branch and connect blocks on the new candidate chain. In `UTXOSet::applyTransaction()` and `rollbackTransaction()`, UTXO records are formatted as pipe-delimited text (`height=<H>|<amount>|<scriptHex>[|cb=1]`). When rolling back a transaction during a reorg, if any previously spent UTXO record was written with legacy format or non-canonical field positioning, an unhandled exception inside `std::stoull` aborts the reorg halfway through, leaving the LevelDB database in a desynchronized split-state where spent inputs cannot be restored.

## 2. Root Cause Analysis
In `src/utxo.cpp`:
```cpp
297: size_t firstDelim = utxoVal.find('|');
298: size_t secondDelim = utxoVal.find('|', firstDelim + 1);
299: if (firstDelim == std::string::npos || secondDelim == std::string::npos) {
300:     throw std::runtime_error("Malformed UTXO data for " + utxoKey + " value=" + utxoVal);
301: }
304: uint64_t spentAmount = std::stoull(utxoVal.substr(firstDelim + 1, secondDelim - firstDelim - 1));
```
In `blockchain.cpp`, reorganizations apply multiple block state transitions sequentially. If a block in the reorg path triggers a throw from `applyTransaction()` or `rollbackTransaction()`, the transaction batch fails partially.
Unlike a fully atomic transactional rollback, LevelDB `WriteBatch` operations that succeeded in preceding disconnected blocks remain committed, while subsequent blocks are rejected. This results in:
1. Double-spend vulnerability if an unspent output was removed before the crash.
2. Inability of the node to restart without a manual `--reindex` or resynchronization from block 0.

## 3. Impact
- Permanent database corruption upon deep reorganization failures.
- Risk of chain fork desynchronization across nodes if one node aborts midway through a reorg.

## 4. Remediation & Defensive Patch
Wrap all block disconnection and connection steps in a single consolidated LevelDB `WriteBatch` for the entire reorganization sequence, ensuring that the database either fully transitions to the new chain tip or completely rolls back to the previous tip:

```diff
--- a/projects/tru/nodes/core/src/blockchain.cpp
+++ b/projects/tru/nodes/core/src/blockchain.cpp
@@ -14390,6 +14390,11 @@
+    // Stage all reorg batch operations in a single atomic WriteBatch
+    leveldb::WriteBatch reorgAtomicBatch;
+    if (!prepareReorganizationAtomic(disconnectList, connectList, reorgAtomicBatch)) {
+        Logger::log("[Reorg] Failed to prepare atomic reorg batch; chain remains on current tip");
+        return false;
+    }
```
