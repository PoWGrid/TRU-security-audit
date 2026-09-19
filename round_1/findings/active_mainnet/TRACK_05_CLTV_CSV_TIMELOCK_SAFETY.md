# Audit Track 05 — CLTV & CSV Timelock Evaluation Safety & Missing CSV Opcode

- **Component:** Script VM / Timelock Verification (`OP_CHECKLOCKTIMEVERIFY` & `OP_CHECKSEQUENCEVERIFY`)
- **Target Files:** `projects/tru/nodes/core/src/script_interpreter.cpp`, `projects/tru/nodes/core/src/opcodes.h`
- **Severity:** High (CVSS 7.4)
- **CWE:** CWE-439: Behavioral Change in New Version, CWE-670: Always-Incorrect Control Flow Implementation

---

## 1. Vulnerability Summary
`OP_CHECKSEQUENCEVERIFY` (`0xb2`, CSV) is defined in `opcodes.h` and mapped in `compileTextScript()`, but **has no corresponding `case` statement in `EvaluateScript()`**. Any smart contract, swap script, or stateful channel relying on relative timelocks via `OP_CHECKSEQUENCEVERIFY` triggers the `default:` case during execution, causing immediate script failure. Furthermore, for `OP_CHECKLOCKTIMEVERIFY` (CLTV), while MTP clock discipline is enforced, height-domain locktimes are hard-disabled, preventing blocks-based timelocks.

## 2. Root Cause Analysis
In `src/opcodes.h`:
```cpp
126: OP_CHECKSEQUENCEVERIFY = 0xb2,
```
In `src/script_interpreter.cpp`:
```cpp
2632: {"OP_CHECKSEQUENCEVERIFY", OP_CHECKSEQUENCEVERIFY},
```
However, in `EvaluateScript()` switch statement:
There is no `case OP_CHECKSEQUENCEVERIFY:`.
When a transaction containing opcode `0xb2` is evaluated, it falls through to:
```cpp
2475: default:
2476: {
2481:     Logger::log("[EvaluateScript] ERROR: unsupported opcode byte=" +
2482:                 std::to_string(static_cast<unsigned int>(opcode)));
2483:     return false;
2484: }
```
Developers or smart contract authors deploying relative sequence lock contracts will find their transactions permanently invalid, resulting in potential funds lockup if an off-chain protocol assumes BIP-112 CSV semantics are active.

Regarding `OP_CHECKLOCKTIMEVERIFY`:
```cpp
1339: static constexpr uint32_t TRU_CLTV_TIMESTAMP_THRESHOLD = 500000000U;
1340: if (locktimeValue < TRU_CLTV_TIMESTAMP_THRESHOLD) {
1341:     Logger::log("[EvaluateScript] ERROR: OP_CHECKLOCKTIMEVERIFY height-domain value is unsupported: " +
1342:                 std::to_string(locktimeValue));
1343:     return false;
1344: }
```
Locktime values below 500 million represent block heights in standard Bitcoin/UTXO protocols. TRU rejects all height-domain values as unsupported, which restricts contracts strictly to Unix epoch timestamps.

## 3. Impact
- Permanent fund freezing if a user attempts to execute contracts compiled with `OP_CHECKSEQUENCEVERIFY`.
- Incapacity to implement relative-timelock payment channels (e.g. Lightning Network-style HTLC channels) without protocol upgrades.

## 4. Remediation & Defensive Patch
Implement the BIP-112 relative sequence lock verification logic inside `EvaluateScript()` for `OP_CHECKSEQUENCEVERIFY`:

```diff
--- a/projects/tru/nodes/core/src/script_interpreter.cpp
+++ b/projects/tru/nodes/core/src/script_interpreter.cpp
@@ -1380,6 +1380,24 @@
                         if (!consumeGas(ctx, static_cast<uint64_t>(10))) return false;
                         break;
                     }
+                    case OP_CHECKSEQUENCEVERIFY: // 0xb2
+                    {
+                        if (stack.empty()) return false;
+                        if (!ctx.tx || ctx.inputIndex >= ctx.tx->vin.size()) return false;
+                        const auto& seqBytes = stack.back();
+                        if (seqBytes.size() != 4) return false;
+                        uint32_t nSequence = (uint32_t)seqBytes[0] | ((uint32_t)seqBytes[1] << 8) |
+                                             ((uint32_t)seqBytes[2] << 16) | ((uint32_t)seqBytes[3] << 24);
+                        if (nSequence & (1U << 31)) { // Sequence lock disabled flag
+                            if (!consumeGas(ctx, 10)) return false;
+                            break;
+                        }
+                        uint32_t txSequence = ctx.tx->vin[ctx.inputIndex].sequence;
+                        if (txSequence & (1U << 31)) return false;
+                        if (txSequence < nSequence) return false;
+                        if (!consumeGas(ctx, 10)) return false;
+                        break;
+                    }
```
