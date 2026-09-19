# Audit Track 08 — Cryptographic Signature Enforcement & Malleability Resistance

- **Component:** Cryptography / ECDSA secp256k1 Signature Verification
- **Target Files:** `projects/tru/nodes/core/src/crypto_ecdsa.cpp`, `projects/tru/nodes/core/src/utils.cpp`
- **Severity:** Medium (CVSS 6.5)
- **CWE:** CWE-347: Improper Verification of Cryptographic Signature, CWE-327: Use of a Broken or Risky Cryptographic Algorithm

---

## 1. Vulnerability Summary
ECDSA signatures over elliptic curves have inherent symmetry: for any valid signature $(r, s)$, the pair $(r, -s \pmod n)$ is also a mathematically valid signature for the same message and public key. Standard Bitcoin-derived cryptocurrencies enforce **BIP-62 (Low-S)** rules to ensure non-malleability, preventing third parties or intermediaries from altering a transaction's signature (and thus its `txid`) while in the mempool without invalidating the cryptographic proof. In TRU Core, while OpenSSL verifies signature validity, strict Low-S canonical enforcement is not explicitly checked prior to transaction hashing.

## 2. Root Cause Analysis
In `src/crypto_ecdsa.cpp`:
```cpp
// ECDSA verification calls OpenSSL d2i_ECDSA_SIG and ECDSA_do_verify:
ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &pSig, sigLen);
int res = ECDSA_do_verify(digest, digestLen, sig, ecKey);
```
OpenSSL accepts any valid signature where $0 < s < n$. If $s > n/2$, the signature is mathematically valid according to the secp256k1 curve parameters, but is non-canonical according to BIP-62.
An attacker observing a valid transaction in the mempool can flip $s$ to $s' = n - s$, re-encode the signature into DER format, and re-broadcast the transaction with a modified `txid`. If miners include the altered transaction first:
1. The sender's unconfirmed child transactions (chained by the original `txid`) become invalid orphans.
2. Tracking systems, web wallets, and exchanges waiting for confirmation of the original `txid` fail to observe confirmation, potentially triggering double-credit or support issues.

## 3. Impact
- Transaction malleability in the mempool prior to block inclusion.
- Disruption of unconfirmed transaction chains and automated withdrawal reconciliation engines.

## 4. Remediation & Defensive Patch
Enforce strict Low-S validation on all ECDSA signatures before accepting transactions into the mempool or blocks:

```diff
--- a/projects/tru/nodes/core/src/crypto_ecdsa.cpp
+++ b/projects/tru/nodes/core/src/crypto_ecdsa.cpp
@@ -120,6 +120,15 @@
+    // Enforce BIP-62: S must be <= order / 2
+    const BIGNUM* s_bn = nullptr;
+    ECDSA_SIG_get0(sig, nullptr, &s_bn);
+    BIGNUM* half_order = BN_new();
+    BN_rshift1(half_order, EC_GROUP_get0_order(group));
+    if (BN_cmp(s_bn, half_order) > 0) {
+        BN_free(half_order);
+        ECDSA_SIG_free(sig);
+        return false; // Reject high-S malleable signature
+    }
+    BN_free(half_order);
```
