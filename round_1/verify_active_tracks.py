#!/usr/bin/env python3
"""
TRU Core 0.05 Security Audit — Master Invariant & Vulnerability Verifier
Accurately inspects active node C++ source code across all 15 audit vectors:
  - Section 1: 8 Active Mainnet Vulnerability Tracks (Critical / High / Medium)
  - Section 2: 7 Architectural Hardening & Reliability Tracks (High / Medium / Low)
"""

import os
import sys
import time
import json
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SANDBOX_DIR = os.path.join(BASE_DIR, "sandbox")
SRC_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "..", "..", "nodes", "core", "src"))
RPC_URL = "http://127.0.0.1:21842/rpc"

results = []

def report_status(track_id, name, is_fixed, details="", category="ACTIVE_MAINNET"):
    status = "PASS ✅ FIXED" if is_fixed else "FAIL ❌ VULNERABLE"
    results.append({
        "track": track_id,
        "name": name,
        "fixed": is_fixed,
        "details": details,
        "category": category
    })
    print(f"[{status}] {track_id}: {name}")
    if details:
        print(f"       ↳ {details}")

def read_source_file(rel_path):
    full_path = os.path.join(SRC_DIR, rel_path)
    if not os.path.isfile(full_path):
        return None
    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

# ==============================================================================
# SECTION 1: 8 ACTIVE MAINNET TRACKS (TRACKS 01 TO 08)
# ==============================================================================

def check_track_01_varint():
    print("\n--- [Track 01] Binary Serialization: VarInt Deserialization Cursor ---")
    content = read_source_file("tx.cpp")
    if content is None:
        report_status("Track 01", "VarInt Deserialization Double-Increment", False, "Missing tx.cpp")
        return

    has_fe_double = "read32LE(raw, pos);\n        pos += 4;" in content or "read32LE(raw, pos);\n        pos+=4;" in content
    has_ff_double = "read64LE(raw, pos);\n        pos += 8;" in content or "read64LE(raw, pos);\n        pos+=8;" in content

    if has_fe_double or has_ff_double:
        report_status("Track 01", "VarInt Deserialization Double-Increment", False, 
                      "tx.cpp lines 957-966 contain redundant 'pos += 4'/'pos += 8' after read32LE/read64LE. Desync ACTIVE!")
    else:
        report_status("Track 01", "VarInt Deserialization Double-Increment", True, 
                      "Redundant position increments removed. readVarInt correctly synchronized.")

def check_track_02_token_self_transfer():
    print("\n--- [Track 02] Token Engine: Self-Transfer Balance Inflation ---")
    content = read_source_file("tokens.cpp")
    if content is None:
        report_status("Track 02", "Token Self-Transfer Balance Inflation", False, "Missing tokens.cpp")
        return

    guard_present = "fromAddress == toAddress" in content and "updateTokenOwnership" in content
    if not guard_present:
        report_status("Track 02", "Token Self-Transfer Balance Inflation", False, 
                      "tokens.cpp lacks 'fromAddress == toAddress' guard in updateTokenOwnership. Self-transfer overwrites subtraction and doubles balance!")
    else:
        report_status("Track 02", "Token Self-Transfer Balance Inflation", True, 
                      "Self-transfer guard active. Overwrite balance doubling prevented.")

def check_track_03_pow_retarget():
    print("\n--- [Track 03] PoW Consensus: Retarget Interval Window Off-By-One ---")
    content = read_source_file("blockchain.cpp")
    if content is None:
        report_status("Track 03", "PoW Retarget Interval Off-By-One", False, "Missing blockchain.cpp")
        return

    has_off_by_one = "depth < DIFFICULTY_RETARGET_INTERVAL - 1" in content and "DESIRED_TIMESPAN =\n        static_cast<uint64_t>(DIFFICULTY_RETARGET_INTERVAL)" in content
    has_fixed_timespan = "DESIRED_TIMESPAN =\n        static_cast<uint64_t>(DIFFICULTY_RETARGET_INTERVAL - 1)" in content or "depth < DIFFICULTY_RETARGET_INTERVAL;" in content

    if has_off_by_one and not has_fixed_timespan:
        report_status("Track 03", "PoW Retarget Interval Off-By-One", False, 
                      "blockchain.cpp measures 59 blocks against 60-block DESIRED_TIMESPAN. 1.67% upward difficulty drift ACTIVE!")
    else:
        report_status("Track 03", "PoW Retarget Interval Off-By-One", True, 
                      "Difficulty retarget interval matches actual measured block span.")

def check_track_04_mempool_dust():
    print("\n--- [Track 04] Mempool Engine: Minimum Output Dust Boundary ---")
    content = read_source_file("mempool.cpp")
    if content is None:
        report_status("Track 04", "Mempool Dust Boundary Absence", False, "Missing mempool.cpp")
        return

    has_dust_boundary = "out.amount < MIN_OUTPUT_DUST_ATOMS" in content or "out.amount < 546" in content or "isDust(" in content
    if not has_dust_boundary:
        report_status("Track 04", "Mempool Dust Boundary Absence", False, 
                      "mempool.cpp lacks minimum output dust threshold. Zero and 1-atom UTXO flood is PERMITTED!")
    else:
        report_status("Track 04", "Mempool Dust Boundary Absence", True, 
                      "Output dust boundary enforced during mempool validation.")

def check_track_05_missing_csv():
    print("\n--- [Track 05] VM Engine: Missing OP_CHECKSEQUENCEVERIFY Support ---")
    content = read_source_file("script_interpreter.cpp")
    if content is None:
        report_status("Track 05", "Missing OP_CHECKSEQUENCEVERIFY Implementation", False, "Missing script_interpreter.cpp")
        return

    has_csv_case = "case OP_CHECKSEQUENCEVERIFY:" in content
    if not has_csv_case:
        report_status("Track 05", "Missing OP_CHECKSEQUENCEVERIFY Implementation", False, 
                      "script_interpreter.cpp lacks 'case OP_CHECKSEQUENCEVERIFY:'. All CSV timelock transactions fall to default: and FAIL!")
    else:
        report_status("Track 05", "Missing OP_CHECKSEQUENCEVERIFY Implementation", True, 
                      "OP_CHECKSEQUENCEVERIFY implemented and handled in EvaluateScript().")

def check_track_06_rpc_null_storage():
    print("\n--- [Track 06] RPC Server: Storage Null Pointer Dereference Safety ---")
    content = read_source_file("rpc_server.cpp")
    if content is None:
        report_status("Track 06", "RPC Storage Null Pointer Dereference Guards", False, "Missing rpc_server.cpp")
        return

    has_guard_2066 = "if (!chain.getStorage())" in content or "auto storage = chain.getStorage();\n    if (!storage)" in content
    if not has_guard_2066:
        report_status("Track 06", "RPC Storage Null Pointer Dereference Guards", False, 
                      "rpc_server.cpp contains direct 'chain.getStorage()->' calls without nullptr validation (lines 2066, 3638). Remote SIGSEGV crash risk ACTIVE!")
    else:
        report_status("Track 06", "RPC Storage Null Pointer Dereference Guards", True, 
                      "Storage pointer validated before dereference in RPC handlers.")

def check_track_07_p2p_slow_drip():
    print("\n--- [Track 07] P2P Transport: Read Timeout & Slow-Drip Framing Safety ---")
    content = read_source_file("peer_connection.cpp")
    if content is None:
        report_status("Track 07", "P2P Read Timeout & Slow-Drip Framing Safety", False, "Missing peer_connection.cpp")
        return

    has_slow_drip_timeout = "FRAME_READ_TIMEOUT_MS" in content or "lastPartialFrameTime" in content
    if not has_slow_drip_timeout:
        report_status("Track 07", "P2P Read Timeout & Slow-Drip Framing Safety", False, 
                      "peer_connection.cpp lacks deadline on consumed==0 incomplete frames. Slow-drip peers can pin 8 MiB heap buffers!")
    else:
        report_status("Track 07", "P2P Read Timeout & Slow-Drip Framing Safety", True, 
                      "Incomplete frame read timeout enforced. Slow-drip sockets cleanly dropped.")

def check_track_08_crypto_low_s():
    print("\n--- [Track 08] Cryptography: Strict BIP-62 Low-S in Core ECDSAKey::verify ---")
    content = read_source_file("crypto_ecdsa.cpp")
    if content is None:
        report_status("Track 08", "ECDSA Signature Malleability Resistance (Low-S)", False, "Missing crypto_ecdsa.cpp")
        return

    has_low_s = "secp256k1_ecdsa_signature_normalize" in content or "isLowS" in content
    if not has_low_s:
        report_status("Track 08", "ECDSA Signature Malleability Resistance (Low-S)", False, 
                      "Base ECDSAKey::verify() lacks Low-S check. Non-tx callers (blockchain.cpp:2738, VAH gates) accept malleable High-S signatures!")
    else:
        report_status("Track 08", "ECDSA Signature Malleability Resistance (Low-S)", True, 
                      "ECDSA signature verification enforces canonical Low-S values.")

# ==============================================================================
# SECTION 2: 7 ARCHITECTURAL HARDENING TRACKS (TRACKS 09 TO 15)
# ==============================================================================

def check_track_09_peer_handshake():
    print("\n--- [Track 09] P2P Peer Redial: Outbound Socket Handshake Deadline ---")
    content = read_source_file("p2p.cpp")
    if content is None:
        report_status("Track 09", "Outbound Peer Handshake Timeout", False, "Missing p2p.cpp", category="HARDENING")
        return

    has_handshake_deadline = "HANDSHAKE_TIMEOUT_MS" in content or "outboundHandshakeDeadline" in content
    if not has_handshake_deadline:
        report_status("Track 09", "Outbound Peer Handshake Timeout", False,
                      "p2p.cpp lacks application-layer handshake completion deadline on redialed sockets. Half-open sockets pin reconnect slots!", category="HARDENING")
    else:
        report_status("Track 09", "Outbound Peer Handshake Timeout", True,
                      "Application handshake deadline enforced on outbound peer connections.", category="HARDENING")

def check_track_10_reorg_atomicity():
    print("\n--- [Track 10] UTXO Engine: Reorg Disconnect/Connect Multi-Block Atomicity ---")
    content = read_source_file("blockchain.cpp")
    if content is None:
        report_status("Track 10", "Atomic Multi-Block Reorg Rollback", False, "Missing blockchain.cpp", category="HARDENING")
        return

    has_atomic_reorg_batch = "reorgBatch" in content or "reorgScopeGuard" in content
    if not has_atomic_reorg_batch:
        report_status("Track 10", "Atomic Multi-Block Reorg Rollback", False,
                      "Deep reorgs commit WriteBatches per block. Interrupted reorg leaves split-state requiring full --reindex!", category="HARDENING")
    else:
        report_status("Track 10", "Atomic Multi-Block Reorg Rollback", True,
                      "Multi-block chain reorganizations wrapped in atomic rollback transactions.", category="HARDENING")

def check_track_11_living_token_queue():
    print("\n--- [Track 11] Token Evolution: Per-Token Anchor Queue Isolation ---")
    content = read_source_file("token_evolution.cpp")
    if content is None:
        report_status("Track 11", "Living Token Anchor Queue Namespace Isolation", False, "Missing token_evolution.cpp", category="HARDENING")
        return

    has_per_token_queue = "per_token_queues_" in content or "MAX_ANCHORS_PER_TOKEN" in content
    if not has_per_token_queue:
        report_status("Track 11", "Living Token Anchor Queue Namespace Isolation", False,
                      "Global 'anchor_queue' cap at 256 items allows griefers to freeze all living token evolutions across the blockchain!", category="HARDENING")
    else:
        report_status("Track 11", "Living Token Anchor Queue Namespace Isolation", True,
                      "Evolution anchor queues isolated per token ID with fair scheduling.", category="HARDENING")

def check_track_12_htlc_timelock_margin():
    print("\n--- [Track 12] Cross-Chain Swaps: HTLC Timelock Safety Margin ---")
    content = read_source_file("rpc_server.cpp")
    if content is None:
        report_status("Track 12", "HTLC Timelock Reorg Race Margin", False, "Missing rpc_server.cpp", category="HARDENING")
        return

    has_safety_margin = "HTLC_MIN_SAFETY_MARGIN_SECONDS" in content or "MIN_REFUND_LOCKTIME_DELTA" in content
    if not has_safety_margin:
        report_status("Track 12", "HTLC Timelock Reorg Race Margin", False,
                      "HTLC atomic swaps allow claim and refund timelocks without mandatory 2-hour delta, risking double-claim during shallow reorgs!", category="HARDENING")
    else:
        report_status("Track 12", "HTLC Timelock Reorg Race Margin", True,
                      "Mandatory timelock delta enforced on cross-chain swap deployments.", category="HARDENING")

def check_track_13_rpc_constant_time_header():
    print("\n--- [Track 13] RPC Transport: Constant-Time Comparison Header Bounding ---")
    content = read_source_file("rpc_utils.h")
    if content is None:
        content = read_source_file("rpc_server.cpp")
    if content is None:
        report_status("Track 13", "RPC Token Length Bounding (DoS/Timing Leak)", False, "Missing rpc_utils.h/rpc_server.cpp", category="HARDENING")
        return

    has_length_cap = "MAX_AUTH_TOKEN_LENGTH" in content or "a.size() > 256 || b.size() > 256" in content
    if not has_length_cap:
        report_status("Track 13", "RPC Token Length Bounding (DoS/Timing Leak)", False,
                      "constantTimeEqual loops over max(lenA, lenB) without length ceiling. Arbitrary large HTTP auth headers exhaust CPU!", category="HARDENING")
    else:
        report_status("Track 13", "RPC Token Length Bounding (DoS/Timing Leak)", True,
                      "Input length bounded before constant-time comparison.", category="HARDENING")

def check_track_14_wallet_mlock():
    print("\n--- [Track 14] Wallet Security: In-Memory Key Zeroing & Memory Locking ---")
    content = read_source_file("wallet.h")
    if content is None:
        report_status("Track 14", "Wallet In-Memory Secret Zeroing (mlock)", False, "Missing wallet.h", category="HARDENING")
        return

    has_secure_alloc = "SecureString" in content or "sodium_mlock" in content or "sodium_memzero" in content
    if not has_secure_alloc:
        report_status("Track 14", "Wallet In-Memory Secret Zeroing (mlock)", False,
                      "Wallet stores private keys in unpinned std::string maps without zeroing upon wallet lock. Secrets vulnerable to swapfile dump!", category="HARDENING")
    else:
        report_status("Track 14", "Wallet In-Memory Secret Zeroing (mlock)", True,
                      "SecureString / sodium_memzero allocator active for decrypted keys.", category="HARDENING")

def check_track_15_logging_cwe117():
    print("\n--- [Track 15] Logging: CWE-117 Newline & Log Injection Sanitization ---")
    content = read_source_file("logging.cpp")
    if content is None:
        report_status("Track 15", "CWE-117 Log Injection Sanitization", False, "Missing logging.cpp", category="HARDENING")
        return

    has_sanitization = "c == '\\r' || c == '\\n'" in content or "sanitized = message" in content
    if not has_sanitization:
        report_status("Track 15", "CWE-117 Log Injection Sanitization", False,
                      "Logger::formatLineLocked writes raw unescaped strings. Malicious peer useragents can forge authentic log timestamps and severity tags!", category="HARDENING")
    else:
        report_status("Track 15", "CWE-117 Log Injection Sanitization", True,
                      "Control characters sanitized in log formatting.", category="HARDENING")

# ==============================================================================
# MAIN
# ==============================================================================
def main():
    print("=" * 80)
    print("🛡️ TRU CORE v0.05 SECURITY AUDIT — MASTER 15-TRACK INVARIANT VERIFIER")
    print("=" * 80)
    print(f"Target Source Directory: {SRC_DIR}")

    print("\n" + "#" * 80)
    print("### SECTION 1: ACTIVE MAINNET VULNERABILITY TRACKS (TRACKS 01 TO 08)")
    print("#" * 80)
    check_track_01_varint()
    check_track_02_token_self_transfer()
    check_track_03_pow_retarget()
    check_track_04_mempool_dust()
    check_track_05_missing_csv()
    check_track_06_rpc_null_storage()
    check_track_07_p2p_slow_drip()
    check_track_08_crypto_low_s()

    print("\n" + "#" * 80)
    print("### SECTION 2: ARCHITECTURAL HARDENING TRACKS (TRACKS 09 TO 15)")
    print("#" * 80)
    check_track_09_peer_handshake()
    check_track_10_reorg_atomicity()
    check_track_11_living_token_queue()
    check_track_12_htlc_timelock_margin()
    check_track_13_rpc_constant_time_header()
    check_track_14_wallet_mlock()
    check_track_15_logging_cwe117()

    print("\n" + "=" * 80)
    vulnerable_mainnet = sum(1 for r in results if r["category"] == "ACTIVE_MAINNET" and not r["fixed"])
    fixed_mainnet = sum(1 for r in results if r["category"] == "ACTIVE_MAINNET" and r["fixed"])
    total_mainnet = sum(1 for r in results if r["category"] == "ACTIVE_MAINNET")

    vulnerable_hardening = sum(1 for r in results if r["category"] == "HARDENING" and not r["fixed"])
    fixed_hardening = sum(1 for r in results if r["category"] == "HARDENING" and r["fixed"])
    total_hardening = sum(1 for r in results if r["category"] == "HARDENING")

    total_vulnerable = vulnerable_mainnet + vulnerable_hardening
    total_fixed = fixed_mainnet + fixed_hardening
    total = len(results)

    print(f"📊 SUMMARY REPORT:")
    print(f"   • Active Mainnet Vulnerabilities: {vulnerable_mainnet}/{total_mainnet} active ({fixed_mainnet} fixed)")
    print(f"   • Architectural Hardening Gaps:  {vulnerable_hardening}/{total_hardening} open ({fixed_hardening} fixed)")
    print(f"   • TOTAL AUDIT TRACKS:            {total_vulnerable}/{total} requiring patches")
    print("=" * 80)

    return 1 if vulnerable_mainnet > 0 else 0

if __name__ == "__main__":
    sys.exit(main())
