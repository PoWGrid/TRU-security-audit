# Audit Track 15 — Bounded Logging, Log Injection Flaws (CWE-117) & File Rotation Concurrency

- **Component:** Logging Subsystem / Log Formatting & Rotation
- **Target Files:** `projects/tru/nodes/core/src/logging.cpp`, `projects/tru/nodes/core/src/logging.h`
- **Severity:** Low/Medium (CVSS 5.3)
- **CWE:** CWE-117: Improper Output Handling for Logs (Log Injection)

---

## 1. Vulnerability Summary
While TRU Core 0.05 successfully bounded log file growth to 32 MiB with 4 rolling archives (160 MiB total), `Logger::formatLineLocked()` in `src/logging.cpp` does not sanitize incoming message strings for newline (`\n`, `\r`) or ANSI escape sequences. An external attacker can inject crafted useragent strings, transaction metadata, or malformed RPC method names containing carriage returns and forged log timestamps (e.g. `\n[2026-09-20 12:00:00] [INFO] Block successfully validated...`), deceiving node administrators and automated log auditing systems.

## 2. Root Cause Analysis
In `src/logging.cpp`:
```cpp
72: std::string Logger::formatLineLocked(Level level, const std::string& message) {
73:     return "[" + timestampNow() + "] [" + levelName(level) + "] " + message + "\n";
74: }
```
When P2P peers connect or send invalid messages:
```cpp
Logger::log("[PeerConnection] Peer " + peerUserAgent_ + " connected");
```
If a peer provides a useragent containing embedded newlines and false severity tags:
```
TRU-Client/1.0\n[2026-09-20 00:00:00] [ERROR] Critical storage failure, database unrecoverable\n[INFO] Peer resumed
```
The resulting log output creates authentic-looking log entries on new lines, corrupting log integrity. In environments where monitoring daemons parse `Tru_debug.log` to trigger automated failover or alerting, an attacker can manipulate operational dashboards or mask real security events.

## 3. Impact
- Log forgery and injection (CWE-117).
- False alerts or masking of malicious activities in operational SIEM systems.

## 4. Remediation & Defensive Patch
Sanitize control characters (`\r`, `\n`, escape codes) in `Logger::formatLineLocked()` before writing to disk:

```diff
--- a/projects/tru/nodes/core/src/logging.cpp
+++ b/projects/tru/nodes/core/src/logging.cpp
@@ -72,7 +72,14 @@ bool Logger::shouldLogLocked(Level level) {
 std::string Logger::formatLineLocked(Level level, const std::string& message) {
-    return "[" + timestampNow() + "] [" + levelName(level) + "] " + message + "\n";
+    std::string sanitized = message;
+    for (char& c : sanitized) {
+        if (c == '\r' || c == '\n') {
+            c = ' ';
+        }
+    }
+    return "[" + timestampNow() + "] [" + levelName(level) + "] " + sanitized + "\n";
 }
```
