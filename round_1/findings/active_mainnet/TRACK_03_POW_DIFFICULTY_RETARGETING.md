# Audit Track 03 — Proof-of-Work Difficulty Retargeting Off-By-One Drift

- **Component:** Consensus / Proof-of-Work & Retargeting Engine
- **Target Files:** `projects/tru/nodes/core/src/blockchain.cpp`
- **Severity:** High (CVSS 7.1)
- **CWE:** CWE-682: Incorrect Calculation, CWE-193: Off-by-one Error

---

## 1. Vulnerability Summary
TRU Core calculates difficulty adjustments every `DIFFICULTY_RETARGET_INTERVAL = 60` blocks. When computing the actual timespan elapsed during the preceding period, the algorithm steps backwards 59 ancestors from `parent`, calculating the time difference between block $H-1$ and block $H-60$. This encompasses exactly 59 block intervals, but compares them against `DESIRED_TIMESPAN = 60 * DIFFICULTY_TARGET_SPACING`. As a result, even if every block arrives with mathematical perfection at 60-second intervals, the network mistakenly calculates the mining speed as 1.67% too fast, causing persistent upward difficulty bias and consensus target drift.

## 2. Root Cause Analysis
In `src/blockchain.cpp`:
```cpp
2943: static constexpr uint64_t DESIRED_TIMESPAN =
2944:     static_cast<uint64_t>(DIFFICULTY_RETARGET_INTERVAL) *
2945:     DIFFICULTY_TARGET_SPACING; // 60 * 60 = 3600 seconds
...
2996: const BlockIndexEntry* startEntry = parent;
2997: for (int depth = 0; depth < DIFFICULTY_RETARGET_INTERVAL - 1; ++depth) {
...
3018:     startEntry = ancestor;
3019: }
3021: const int64_t signedSpan =
3022:     static_cast<int64_t>(parent->block.header.timestamp) -
3023:     static_cast<int64_t>(startEntry->block.header.timestamp);
...
3033: boost::multiprecision::uint512_t scaled =
3034:     boost::multiprecision::uint512_t(parentTarget) * actualTime;
3035: scaled /= DESIRED_TIMESPAN;
```
### Mathematical Proof of Error:
- At retarget height $H = 120$:
  - `parent` is at height 119.
  - The loop iterates `DIFFICULTY_RETARGET_INTERVAL - 1 = 59` times.
  - `startEntry` reaches height $119 - 59 = 60$.
  - Number of elapsed blocks measured: $119 - 60 = 59$ blocks.
  - Expected time for 59 blocks at 60s per block: $59 \times 60 = 3540$ seconds.
  - `DESIRED_TIMESPAN`: $60 \times 60 = 3600$ seconds.
  - Retarget scale: $\frac{3540}{3600} = \frac{59}{60} \approx 0.9833$.
  - The new target is multiplied by $\frac{59}{60}$, decreasing the target and **increasing mining difficulty by ~1.69%** every retarget window without any increase in actual hashrate!

This is the historic Satoshi Bitcoin off-by-one retargeting bug inherited directly into TRU's retarget implementation.

## 3. Impact
- Gradual, unearned difficulty escalation on stable-hashrate networks.
- Block intervals drift from nominal 60 seconds to ~61.02 seconds unless miners compensate.
- Any hard-fork fix would require coordinated protocol activation height.

## 4. Remediation & Defensive Patch
For future consensus hard-fork or testnet activation: either measure over 60 intervals (by traversing back `DIFFICULTY_RETARGET_INTERVAL` steps to block $H-61$ or using candidate height), or define `DESIRED_TIMESPAN` based on 59 intervals:

```diff
--- a/projects/tru/nodes/core/src/blockchain.cpp
+++ b/projects/tru/nodes/core/src/blockchain.cpp
@@ -2943,7 +2943,7 @@
     static constexpr uint64_t DESIRED_TIMESPAN =
-        static_cast<uint64_t>(DIFFICULTY_RETARGET_INTERVAL) *
+        static_cast<uint64_t>(DIFFICULTY_RETARGET_INTERVAL - 1) *
         DIFFICULTY_TARGET_SPACING;
```
