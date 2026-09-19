# Audit Track 09 — Peer State Machine & Auto-Recovery (`[PEER-REDIAL-01]`)

- **Component:** Network / Peer Manager & Reconnect Subsystem
- **Target Files:** `projects/tru/nodes/core/src/peer_manager.cpp`, `projects/tru/nodes/core/src/p2p.cpp`
- **Severity:** Medium (CVSS 5.9)
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)

---

## 1. Vulnerability Summary
Core 0.05 introduced `[PEER-REDIAL-01]` to maintain transport connectivity by automatically redialing verified peers with exponential backoff (5s to 60s). However, peer candidate leasing in `claimReconnectCandidates()` uses an 8-second static window (`state.nextAttempt = now + std::chrono::seconds(8);`). If a peer connects via TCP but the connection hangs or the peer sends slow data without concluding a VERSION handshake, the peer remains marked as leased until disconnection occurs. Under network partition or ungraceful socket drop, state maps in `reconnect_` retain dangling records without a cleanup cap.

## 2. Root Cause Analysis
In `src/peer_manager.cpp`:
```cpp
377: // Attempt lease: longer than the 5s redial connect timeout. If TCP
378: // succeeds but VERSION never validates, releaseConnectionSlot() will
379: // schedule the next exponentially-backed-off attempt.
380: state.nextAttempt = now + std::chrono::seconds(8);
381: result.push_back(peer);
```
If an outbound redial TCP connection is established (`connectToPeer() == true`), but the target remote node drops packets during the TLS/Protobuf handshake, the socket can remain in a half-open state until system TCP keepalive timeouts expire (often 2 hours by default on Linux if `SO_KEEPALIVE` parameters are unconfigured). Consequently:
1. The peer slot is blocked in `activeConnections_`.
2. The backoff scheduler does not count this as a failure until a hard error surfaces.
3. If an attacker controls multiple IP addresses registered in the peer table, they can accept TCP SYN packets without sending any bytes, locking up outbound reconnect workers.

## 3. Impact
- Exhaustion of outbound reconnection slots.
- Node isolation from legitimate peer networks during intermittent internet disruptions.

## 4. Remediation & Defensive Patch
Introduce an application-level handshake deadline (e.g. 10 seconds) for newly established outbound connections. If the handshake is not finalized within this deadline, forcibly terminate the socket and trigger `noteReconnectFailure()`:

```diff
--- a/projects/tru/nodes/core/src/p2p.cpp
+++ b/projects/tru/nodes/core/src/p2p.cpp
@@ -109,6 +109,8 @@
                     "[PEER-REDIAL-01] TCP redial established to " + peer.ip + ":" +
                     std::to_string(peer.port) + "; awaiting verified VERSION");
+                // Set socket receive timeout for handshake completion
+                setSocketTimeout(newPeerSocket, 10);
             }
```
