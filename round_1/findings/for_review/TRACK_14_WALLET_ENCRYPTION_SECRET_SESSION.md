# Audit Track 14 — Wallet Keystore In-Memory Plaintext Key Retention & Page Swapping Risks

- **Component:** Wallet / Keystore Encryption & Key Management
- **Target Files:** `projects/tru/nodes/core/src/wallet.cpp`, `projects/tru/nodes/core/src/wallet_encryption_v1.cpp`
- **Severity:** High (CVSS 7.4)
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory, CWE-226: Sensitive Information Uncleared Before Release

---

## 1. Vulnerability Summary
While `wallet_encryption_v1.cpp` uses libsodium's `crypto_pwhash` (Argon2id) and `crypto_aead_xchacha20poly1305_ietf` with `sodium_memzero` for the encryption key, the decrypted private keys are stored in `Wallet::privateKeys` as standard C++ `std::unordered_map<std::string, std::string>`. Unmanaged heap `std::string` allocations are never pinned with `mlock()` and are not zeroed out when the wallet is locked or when keys are deleted. The plaintext PEM private keys can be swapped to disk in swapfiles or recovered from process core dumps.

## 2. Root Cause Analysis
In `src/wallet.cpp`:
```cpp
627: privateKeys[address] = privateKeyPEM;
...
3122: privateKeys.clear();
```
When `privateKeys.clear()` is called:
1. `std::string` destructors simply release heap memory blocks to glibc's `ptmalloc` without scrubbing the byte buffers (`memset` / `sodium_memzero`).
2. Operating systems may page heap memory to unencrypted swap partitions on disk.
3. If an attacker gains unprivileged local read access to memory (e.g. via `/proc/<pid>/mem`, debugging utilities, or core dumps), the wallet owner's active private keys can be extracted in plaintext long after the wallet has supposedly been locked.

## 3. Impact
- Residual private key exposure in physical memory or system swap space.
- Compromise of funds if the host machine experiences unauthorized memory inspection or memory-dump analysis.

## 4. Remediation & Defensive Patch
Introduce a secure allocator (such as `sodium_malloc` or a custom zeroing allocator `SecureString`) that calls `sodium_mlock()` to prevent swapping and invokes `sodium_memzero()` upon deallocation:

```diff
--- a/projects/tru/nodes/core/src/wallet.h
+++ b/projects/tru/nodes/core/src/wallet.h
@@ -45,7 +45,8 @@
-    std::unordered_map<std::string, std::string> privateKeys;
+    // Secure string allocator with sodium_memzero on destruction
+    std::unordered_map<std::string, SecureString> privateKeys;
```
