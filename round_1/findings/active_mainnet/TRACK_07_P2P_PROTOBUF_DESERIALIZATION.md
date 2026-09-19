# Audit Track 07 — P2P Protobuf Deserialization & Buffer Boundary Safety

- **Component:** Network / P2P Transport Framing
- **Target Files:** `projects/tru/nodes/core/src/message_handler.cpp`, `projects/tru/nodes/core/src/peer_connection.cpp`
- **Severity:** Medium (CVSS 5.3)
- **CWE:** CWE-400: Uncontrolled Resource Consumption, CWE-20: Improper Input Validation

---

## 1. Vulnerability Summary
During P2P message frame ingestion in `MessageHandler::deserializeMessage()`, incoming TCP payload streams are framed with a 4-byte magic, 4-byte type, 4-byte length, and 32-byte SHA256 checksum. While `maxFramePayloadForType()` enforces a ceiling on declared frame length, several parsing edge cases exist where malformed or partial frames cause unbounded buffer growth before a connection reset, or throw uncaught exceptions during Protobuf field parsing under hostile socket fragmentation.

## 2. Root Cause Analysis
In `src/message_handler.cpp`:
```cpp
188: if (data.size() < headerSize + static_cast<size_t>(length)) {
189:     return 0; // incomplete but size-valid frame
190: }
```
When `data.size()` is less than the required frame size, `0` is returned to indicate an incomplete frame, which causes `PeerConnection::readLoop` to continue accumulating bytes in `buffer_`. If a peer announces a maximum allowed payload (e.g. 4 MiB for a block) but streams bytes at 1 byte per second or stalls, `buffer_` retains allocated heap memory up to `MAX_P2P_RECEIVE_BUFFER_BYTES` (8 MiB) per peer. Across 128 active peer sockets, this allows an unauthenticated remote attacker to pin hundreds of megabytes of process memory without completing valid protocol handshakes.

Furthermore, `ParseFromString` does not catch internal Protobuf recursion limits:
```cpp
213: if (!msg.ParseFromString(payload)) { ... }
```
Deeply nested or corrupted protobuf structures can exceed default protobuf recursion depth limits, triggering silent parse failures rather than explicit peer ban scores.

## 3. Impact
- Memory amplification and denial of service across peer connection threads.
- Inbound connection starvation where attacker-held slow-drip sockets exhaust available node worker threads.

## 4. Remediation & Defensive Patch
Enforce an explicit per-frame read timeout deadline on incomplete frames, and enforce a strict sub-header accumulation limit:

```diff
--- a/projects/tru/nodes/core/src/peer_connection.cpp
+++ b/projects/tru/nodes/core/src/peer_connection.cpp
@@ -620,6 +620,12 @@
                 } else if (consumed == 0) {
+                    if (incompleteFrameStartTime_ == TimePoint{}) {
+                        incompleteFrameStartTime_ = Clock::now();
+                    } else if (Clock::now() - incompleteFrameStartTime_ > std::chrono::seconds(15)) {
+                        Logger::log("[PeerConnection] Dropping slow-drip peer stalling frame: " + ip_);
+                        running_ = false;
+                        break;
+                    }
                     break; // Incomplete but size-valid frame; wait for more data
                 }
+                incompleteFrameStartTime_ = TimePoint{};
```
