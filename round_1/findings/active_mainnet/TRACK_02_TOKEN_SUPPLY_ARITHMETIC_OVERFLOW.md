# Audit Track 02 — Token Balance Inflation Vulnerability via Self-Transfer Logic Flaw

- **Component:** Tokens Subsystem / Token Ownership State Engine
- **Target Files:** `projects/tru/nodes/core/src/tokens.cpp`
- **Severity:** Critical (CVSS 9.3)
- **CWE:** CWE-840: Business Logic Errors, CWE-670: Always-Incorrect Control Flow Implementation

---

## 1. Vulnerability Summary
A critical business logic vulnerability in `updateTokenOwnership()` in `src/tokens.cpp` allows any token holder to **arbitrarily inflate their token balance by transferring tokens to themselves**. When `fromAddress == toAddress`, the function calculates the remaining balance `rem = have - quantity` and queues a write or deletion for `fromKey`. It then computes `newTo = quantity + current_balance` for `toKey`. Because `fromKey` and `toKey` refer to the identical LevelDB key, the second `Put(toKey, ...)` in the batch overwrites the subtraction, committing a balance of `have + quantity`. By repeatedly executing self-transfers, an attacker can double their token holdings indefinitely, subverting all supply caps.

## 2. Root Cause Analysis
In `src/tokens.cpp`:
```cpp
290: const std::string fromKey = "tokenOwnership:" + fromAddress + ":" + tid;
291: const std::string toKey = "tokenOwnership:" + toAddress + ":" + tid;
292: 
293: std::string rawFrom;
294: if (!storage->getWithDataChecksum(fromKey, rawFrom)) {
...
304: uint64_t have = jf.value("amount", 0ULL);
305: if (have < quantity) return false;
308: 
310: leveldb::WriteBatch batch;
311: uint64_t rem = have - quantity;
312: if (rem > 0) {
313:     jf["amount"] = rem;
314:     batch.Put(fromKey, jf.dump());
315: } else {
316:     batch.Delete(fromKey);
317: }
318: 
319: uint64_t newTo = quantity;
320: std::string rawTo;
321: if (storage->getWithDataChecksum(toKey, rawTo)) {
322:     try {
323:         auto jt = nlohmann::json::parse(rawTo);
324:         newTo += jt.value("amount", 0ULL); // <--- Reads original 'have'!
325:     } catch (...) { ... }
326: }
329: nlohmann::json jt = {{"amount", newTo}, {"txid", jf["txid"]}};
330: batch.Put(toKey, jt.dump()); // <--- OVERWRITES fromKey WITH have + quantity!
```

### Execution Trace when `fromAddress == toAddress`:
Suppose Alice owns 1,000 tokens of `tid`:
1. `fromKey` and `toKey` are identical: `"tokenOwnership:ALICE:tid"`.
2. Alice submits a transaction transferring 1,000 tokens to Alice (`quantity = 1000`).
3. `have = 1000`, `quantity = 1000`.
4. `rem = 1000 - 1000 = 0`. `batch.Delete(fromKey)` is queued.
5. `storage->getWithDataChecksum(toKey, rawTo)` reads the current state in database (1,000 tokens).
6. `newTo = quantity + 1000 = 2000`.
7. `batch.Put(toKey, jt.dump())` (where `toKey == fromKey`) writes 2,000 tokens to the batch.
8. When `batch` executes in LevelDB, the second write overrides the delete.
9. Alice now owns **2,000 tokens**.
10. Repeating this transfer produces 4,000, 8,000, 16,000... infinitely inflating the token supply.

## 3. Impact
- Unrestricted token counterfeiting by any address possessing even 1 token.
- Total collapse of token economics and unauthorized bypass of token max supply caps.

## 4. Remediation & Defensive Patch
Check for self-transfer at the entry of `updateTokenOwnership()` and treat it as a no-op (or handle in-memory subtraction before accumulation):

```diff
--- a/projects/tru/nodes/core/src/tokens.cpp
+++ b/projects/tru/nodes/core/src/tokens.cpp
@@ -290,6 +290,11 @@ bool updateTokenOwnership(
     const std::string fromKey = "tokenOwnership:" + fromAddress + ":" + tid;
     const std::string toKey = "tokenOwnership:" + toAddress + ":" + tid;
 
+    if (fromAddress == toAddress) {
+        Logger::log("[updateTokenOwnership] Self-transfer is a no-op: " + fromAddress);
+        return true; // Balance unchanged
+    }
+
     std::string rawFrom;
     if (!storage->getWithDataChecksum(fromKey, rawFrom)) {
```
