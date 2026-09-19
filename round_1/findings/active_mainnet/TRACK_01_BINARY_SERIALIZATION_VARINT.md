# Audit Track 01 — Binary Serialization VarInt Cursor Double-Increment Deserialization Corruption

- **Component:** Core / Binary Wire Serialization & Transaction Deserialization
- **Target Files:** `projects/tru/nodes/core/src/tx.cpp`
- **Severity:** Critical (CVSS 9.1)
- **CWE:** CWE-193: Off-by-one Error, CWE-125: Out-of-bounds Read, CWE-440: Expected Behavior Violation

---

## 1. Vulnerability Summary
A critical synchronization bug was discovered in `readVarInt()` in `src/tx.cpp`. When parsing variable-length integers prefixed with `0xFE` (indicating a 32-bit integer) or `0xFF` (indicating a 64-bit integer), `readVarInt()` calls helper functions `read32LE(raw, pos)` and `read64LE(raw, pos)` which advance the position reference `pos` by 4 and 8 bytes respectively. However, `readVarInt()` **subsequently increments `pos` a second time** (`pos += 4` and `pos += 8`). This double increment causes the stream parser to skip 4 or 8 bytes of legitimate payload data, desynchronizing the binary stream and corrupting the deserialization of large scripts, token metadata, or multi-input transactions.

## 2. Root Cause Analysis
In `src/tx.cpp`:
```cpp
921: static uint32_t read32LE(const std::vector<unsigned char> &raw, size_t &pos)
922: {
923:     if(pos+4>raw.size()) throw std::runtime_error("read32LE out of range");
924:     uint32_t val = (uint32_t)raw[pos] 
925:                  | ((uint32_t)raw[pos+1]<<8)
926:                  | ((uint32_t)raw[pos+2]<<16)
927:                  | ((uint32_t)raw[pos+3]<<24);
928:     pos+=4; // <--- pos IS INCREMENTED HERE!
929:     return val;
930: }
...
934: static uint64_t read64LE(const std::vector<unsigned char> &raw, size_t &pos)
935: {
936:     if(pos+8>raw.size()) throw std::runtime_error("read64LE out of range");
...
941:     pos+=8; // <--- pos IS INCREMENTED HERE!
942:     return val;
943: }
...
947: static uint64_t readVarInt(const std::vector<unsigned char> &raw, size_t &pos) {
948:     if (pos >= raw.size()) throw std::runtime_error("readVarInt: out of range");
949:     unsigned char c = raw[pos++];
950:     if (c < 0xFD) {
951:         return c;
952:     } else if (c == 0xFD) {
953:         if (pos + 2 > raw.size()) throw std::runtime_error("readVarInt[0xFD]: out of range");
954:         uint16_t val = (uint16_t)raw[pos] | ((uint16_t)raw[pos + 1] << 8);
955:         pos += 2; // Correct: advances pos once
956:         return val;
957:     } else if (c == 0xFE) {
958:         if (pos + 4 > raw.size()) throw std::runtime_error("readVarInt[0xFE]: out of range");
959:         uint32_t val = read32LE(raw, pos); // <--- read32LE ADVANCES pos BY 4
960:         pos += 4; // <--- CRITICAL BUG: ADVANCES pos BY 4 A SECOND TIME!
961:         return val;
962:     } else if (c == 0xFF) {
963:         if (pos + 8 > raw.size()) throw std::runtime_error("readVarInt[0xFF]: out of range");
964:         uint64_t val = read64LE(raw, pos); // <--- read64LE ADVANCES pos BY 8
965:         pos += 8; // <--- CRITICAL BUG: ADVANCES pos BY 8 A SECOND TIME!
966:         return val;
967:     }
968:     throw std::runtime_error("Invalid varint prefix");
969: }
```

### Consequences:
1. When a transaction contains a script, metadata field, or input array with length $\ge 65,536$ bytes (`0xFE` prefix), `readVarInt` consumes 1 byte for prefix, 4 bytes for value in `read32LE`, and then skips an additional 4 bytes of the actual script data.
2. The subsequent script read copies bytes from offset `pos + 4` instead of `pos`, slicing into the middle of bytecode or outpoints.
3. If the transaction buffer is near capacity, `pos += 4` causes the stream to overshoot `raw.size()`, throwing a false `"readVarInt[0xFE]: out of range"` or `"out of range"` exception.
4. Large transactions validly serialized by other clients fail deserialization on TRU nodes, creating consensus splits or block rejection.

## 3. Impact
- High-volume contract deployment or inscription transactions over 64 KiB become unparseable or corrupted.
- Deserialization crashes nodes or permanently forks mining nodes from valid blocks containing 0xFE/0xFF varints.

## 4. Remediation & Defensive Patch
Remove the redundant secondary increments in `readVarInt()`:

```diff
--- a/projects/tru/nodes/core/src/tx.cpp
+++ b/projects/tru/nodes/core/src/tx.cpp
@@ -957,11 +957,9 @@ static uint64_t readVarInt(const std::vector<unsigned char> &raw, size_t &pos)
     } else if (c == 0xFE) {
         if (pos + 4 > raw.size()) throw std::runtime_error("readVarInt[0xFE]: out of range");
         uint32_t val = read32LE(raw, pos);
-        pos += 4;
         return val;
     } else if (c == 0xFF) {
         if (pos + 8 > raw.size()) throw std::runtime_error("readVarInt[0xFF]: out of range");
         uint64_t val = read64LE(raw, pos);
-        pos += 8;
         return val;
     }
```
