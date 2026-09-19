# Audit Track 06 — RPC JSON Input Validation & Storage Null Pointer Dereference Vulnerabilities

- **Component:** RPC Server / Request Processing & Input Deserialization
- **Target Files:** `projects/tru/nodes/core/src/rpc_server.cpp`
- **Severity:** High (CVSS 7.5)
- **CWE:** CWE-476: NULL Pointer Dereference, CWE-20: Improper Input Validation

---

## 1. Vulnerability Summary
Multiple RPC handler functions in `rpc_server.cpp` access nested JSON fields via operator `[]` without prior `.contains()` and type checks, or directly dereference pointer methods such as `chain.getStorage()->...` without verifying that the storage engine pointer is non-null. In particular, passing unexpected types (e.g. integer where string is expected) or invoking storage-backed RPC methods before the database initialization completes can trigger unhandled `std::exception` throws or fatal `SIGSEGV` segmentation faults that crash the entire TRU node process.

## 2. Root Cause Analysis
In `src/rpc_server.cpp`:
```cpp
2061: std::string txid = params["txid"].get<std::string>();
2064: std::string metaKey = "tokenMetadata:" + txid;
2065: std::string metaValue;
2066: if (!chain.getStorage()->getWithDataChecksum(metaKey, metaValue)) { ... }
```
1. **Unchecked JSON indexing:** If `params` is empty, an array, or missing `"txid"`, `params["txid"]` returns a null JSON node. Calling `.get<std::string>()` throws `nlohmann::json::type_error`. While enclosed in a local `try/catch`, it returns generic error messages instead of standard JSON-RPC 2.0 error codes.
2. **Null Pointer Dereference:** In testnet startup, reindexing mode, or headless verification instances, `chain.getStorage()` can be `nullptr`. Invoking `chain.getStorage()->getWithDataChecksum(...)` immediately triggers a `SIGSEGV` crash.
3. Similar unguarded dereferences exist in lines 3638, 3789, 3961, 4139, 4145, 4156, and 4178.

## 3. Impact
- Remote denial of service (node process termination via SIGSEGV) on malformed RPC payloads or during node startup transitions.
- Lack of standard JSON-RPC -32602 (Invalid params) error signaling.

## 4. Remediation & Defensive Patch
Add null storage checks and safe parameter extraction helpers:

```diff
--- a/projects/tru/nodes/core/src/rpc_server.cpp
+++ b/projects/tru/nodes/core/src/rpc_server.cpp
@@ -2060,6 +2060,14 @@ static json handleGetTRUScript(...) {
     try {
+        if (!params.contains("txid") || !params["txid"].is_string()) {
+            return makeError(-32602, "Missing or invalid 'txid' parameter");
+        }
+        LevelDBStorage* storage = chain.getStorage();
+        if (!storage) {
+            return makeError(-32000, "Node storage engine is not ready");
+        }
         std::string txid = params["txid"].get<std::string>();
```
