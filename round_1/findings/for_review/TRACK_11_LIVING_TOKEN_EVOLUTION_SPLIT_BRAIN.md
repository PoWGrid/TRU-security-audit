# Audit Track 11 — Living Token Evolution (SFT/NCFT) Global Queue Cap & Race Condition DoS

- **Component:** AI Living Tokens / Token Evolution Engine
- **Target Files:** `projects/tru/nodes/core/src/token_evolution.cpp`, `projects/tru/nodes/core/src/token_evolution.h`
- **Severity:** High (CVSS 8.2)
- **CWE:** CWE-400: Uncontrolled Resource Consumption, CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization

---

## 1. Vulnerability Summary
The Living Token evolution system persists token epochs using a global queue stored under the single key `{"TOKEN_EVOLUTION", "anchor_queue"}`. This queue has a hardcoded capacity ceiling of `TOKEN_EVOLUTION_MAX_ANCHOR_QUEUE_ITEMS = 256U`. If 256 unanchored evolution items accumulate across the entire node/network, `persistPreview()` returns `false`, **permanently blocking all evolution progress for every other token on the blockchain**. Furthermore, concurrent evolution calls on different tokens suffer from read-modify-write race conditions that overwrite each other's pending queue items.

## 2. Root Cause Analysis
In `src/token_evolution.cpp`:
```cpp
21: constexpr std::size_t TOKEN_EVOLUTION_MAX_ANCHOR_QUEUE_ITEMS = 256U;
...
937: if (!alreadyQueued) {
938:     if (compactQueue.size() >= TOKEN_EVOLUTION_MAX_ANCHOR_QUEUE_ITEMS) {
939:         Logger::log(
940:             "[TokenEvolution] Anchor queue full; refusing unqueued epoch"
941:         );
942:         return false;
943:     }
944:     compactQueue.push_back(queueItem);
945: }
961: {"TOKEN_EVOLUTION", "anchor_queue", queueSerialized}
```
1. **Global Denial of Service:** A malicious user or script can create and evolve multiple tokens without anchoring them on-chain. Once 256 items are queued in `anchor_queue`, no living token on the network can be evolved until anchors are mined.
2. **Atomic Inconsistency / Race Condition:** `persistPreview()` loads `anchor_queue`, parses it into a JSON array, modifies it in RAM, and writes it back as part of a batch. If two tokens evolve simultaneously across separate threads or RPC calls, the second write completely stomps the first write's updates to `anchor_queue`.

## 3. Impact
- Global suspension of AI living token evolution across the network.
- Silent loss of queued anchor receipts due to race conditions during parallel evolution requests.

## 4. Remediation & Defensive Patch
Isolate anchor queues per token ID (or per contract namespace) rather than sharing a single global key, and synchronize queue access with a dedicated mutex:

```diff
--- a/projects/tru/nodes/core/src/token_evolution.cpp
+++ b/projects/tru/nodes/core/src/token_evolution.cpp
@@ -958,7 +958,7 @@ bool TokenEvolutionEngine::persistPreview(const nlohmann::json& record) {
     const std::vector<ContractStorage::BatchWrite> writes = {
         {"TOKEN_EVOLUTION", epochKey, serialized},
         {"TOKEN_EVOLUTION", latestKey, serialized},
-        {"TOKEN_EVOLUTION", "anchor_queue", queueSerialized}
+        {"TOKEN_EVOLUTION", "anchor_queue:" + tokenID, queueSerialized}
     };
```
