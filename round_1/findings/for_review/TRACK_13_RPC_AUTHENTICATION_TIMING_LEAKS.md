# Audit Track 13 — RPC Authentication Timing Analysis & Resource Exhaustion in `constantTimeEqual`

- **Component:** Node Management / RPC Transport Authentication
- **Target Files:** `projects/tru/nodes/core/src/rpc_utils.h`, `projects/tru/nodes/core/src/rpc_server.cpp`
- **Severity:** Medium (CVSS 6.5)
- **CWE:** CWE-208: Observable Timing Discrepancy, CWE-400: Uncontrolled Resource Consumption

---

## 1. Vulnerability Summary
The constant-time string comparison function `tru_rpc::constantTimeEqual()` is used to authenticate HTTP RPC headers (`Authorization: Bearer <token>`) and swap tokens. While designed to prevent timing attacks by avoiding early exits, its iteration count is bound to $\max(\text{size}_A, \text{size}_B)$. Because HTTP request bodies and header values can be large (governed only by `set_payload_max_length`), an unauthenticated remote client can supply an arbitrary 10 MB Authorization header, forcing the node worker thread to execute 10 million byte comparisons for a single authorization check. Furthermore, measuring execution time across varying input lengths leaks whether the supplied token length is greater than the secret token length.

## 2. Root Cause Analysis
In `src/rpc_utils.h`:
```cpp
33: inline bool constantTimeEqual(const std::string& a, const std::string& b) {
34:     const std::size_t maxLen = a.size() > b.size() ? a.size() : b.size();
35:     unsigned int diff = static_cast<unsigned int>(a.size() ^ b.size());
36:     for (std::size_t i = 0; i < maxLen; ++i) {
37:         const unsigned char av = i < a.size() ? static_cast<unsigned char>(a[i]) : 0U;
38:         const unsigned char bv = i < b.size() ? static_cast<unsigned char>(b[i]) : 0U;
39:         diff |= static_cast<unsigned int>(av ^ bv);
40:     }
41:     return diff == 0U;
42: }
```
1. **CPU Exhaustion:** An unauthenticated attacker sending high-frequency HTTP requests with 4 MiB header values forces all worker threads (`g_rpcServer.new_task_queue`) into high CPU utilization, blocking legitimate mining templates or wallet commands.
2. **Length Leakage:** When $a.\text{size}() \gg b.\text{size}()$, the elapsed time scales linearly with $a.\text{size}()$. When $a.\text{size}() \le b.\text{size}()$, elapsed time is constant (bound by $b.\text{size}()$). This creates an observable inflection point at the exact length of the server secret.

## 3. Impact
- Unauthenticated RPC thread starvation and denial of service.
- Minor information leak regarding secret token byte length.

## 4. Remediation & Defensive Patch
Enforce an immediate length ceiling (e.g. maximum 128 bytes) and use OpenSSL's `CRYPTO_memcmp()` after bounding sizes:

```diff
--- a/projects/tru/nodes/core/src/rpc_utils.h
+++ b/projects/tru/nodes/core/src/rpc_utils.h
@@ -33,6 +33,10 @@ inline std::string trim(const std::string& in) {
 inline bool constantTimeEqual(const std::string& a, const std::string& b) {
+    // Bound maximum token length to prevent CPU exhaustion
+    if (a.size() > 256U || b.size() > 256U) {
+        return false;
+    }
     const std::size_t maxLen = a.size() > b.size() ? a.size() : b.size();
     unsigned int diff = static_cast<unsigned int>(a.size() ^ b.size());
```
