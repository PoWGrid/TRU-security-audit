#!/usr/bin/env python3
"""
TRU Security Audit Sandbox Controller
Manages an isolated, local testnet sandbox instance of TRU Core on dedicated ports
(RPC: 21842, P2P disabled, seed nodes disabled) with a disposable data directory.
Handles encrypted wallet passphrase via pseudo-terminal (pty).
"""

import os
import sys
import time
import subprocess
import signal
import urllib.request
import json
import pty
import select

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
LOG_DIR = os.path.join(BASE_DIR, "logs")
CONF_FILE = os.path.join(BASE_DIR, "tru.conf")
PID_FILE = os.path.join(BASE_DIR, "sandbox_node.pid")
RUNNER_PID_FILE = os.path.join(BASE_DIR, "sandbox_runner.pid")
LOG_OUT = os.path.join(LOG_DIR, "sandbox_stdout.log")

BIN_CANDIDATES = [
    os.path.abspath(os.path.join(BASE_DIR, "..", "..", "..", "..", "nodes", "core", "build-native", "bin", "tru_advanced")),
    os.path.abspath(os.path.join(BASE_DIR, "..", "..", "..", "workspace", "build-native", "bin", "tru_advanced")),
]

LIB_CANDIDATES = [
    os.path.abspath(os.path.join(BASE_DIR, "..", "..", "..", "workspace", "build-native", "bin", "lib")),
    os.path.abspath(os.path.join(BASE_DIR, "..", "..", "..", "..", "nodes", "core", "build-native", "bin", "lib")),
]

WALLET_SOURCE_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "..", "..", "workspace", "docker-node"))

PASS = b"12345678\n"

def get_node_bin():
    for b in BIN_CANDIDATES:
        if os.path.isfile(b) and os.access(b, os.X_OK):
            return b
    raise FileNotFoundError(f"Could not locate compiled tru_advanced binary. Checked: {BIN_CANDIDATES}")

def get_ld_library_path():
    paths = [p for p in LIB_CANDIDATES if os.path.isdir(p)]
    existing = os.environ.get("LD_LIBRARY_PATH", "")
    if existing:
        paths.append(existing)
    return ":".join(paths)

def ensure_wallet_files():
    wallet_files = ["tru.dat.enc", "tru.dat.public", "wallet_seed.dat.enc"]
    for wf in wallet_files:
        dst = os.path.join(BASE_DIR, wf)
        if not os.path.exists(dst):
            src = os.path.join(WALLET_SOURCE_DIR, wf)
            if os.path.exists(src):
                import shutil
                shutil.copy2(src, dst)

def get_sandbox_rpc_token():
    paths = [
        os.path.join(DATA_DIR, ".rpc-cookie-21842"),
        os.path.join(BASE_DIR, ".rpc-cookie-21842"),
        os.path.expanduser("~/.tru/rpc-cookie-21842")
    ]
    for p in paths:
        if os.path.exists(p):
            try:
                with open(p, "r") as f:
                    t = f.read().strip()
                    if t: return t
            except Exception:
                pass
    return ""

def start_sandbox():
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, "r") as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            print(f"[!] Sandbox node is already running (PID: {pid}).")
            return
        except Exception:
            os.remove(PID_FILE)

    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    ensure_wallet_files()

    node_bin = get_node_bin()
    ld_path = get_ld_library_path()

    env = os.environ.copy()
    if ld_path:
        env["LD_LIBRARY_PATH"] = ld_path

    cmd = [
        node_bin,
        "--datadir", DATA_DIR,
        "--logdir", LOG_DIR,
        "--conf", CONF_FILE,
        "--rpcport", "21842",
        "--rpcbind", "127.0.0.1",
        "--no-seeds",
        "--no-p2p",
        "--loglevel", "DEBUG"
    ]

    print(f"[*] Launching isolated sandbox node on RPC port 21842 with pty wrapper...")
    print(f"    Binary: {node_bin}")
    print(f"    Data:   {DATA_DIR}")

    # Launch daemon in background via fork + pty
    daemon_pid = os.fork()
    if daemon_pid == 0:
        # Grandchild process: runner with pty
        os.setsid()
        master, slave = pty.openpty()
        sub_pid = os.fork()

        if sub_pid == 0:
            os.close(master)
            os.dup2(slave, 0)
            os.dup2(slave, 1)
            os.dup2(slave, 2)
            os.close(slave)
            os.execve(node_bin, cmd, env)
        else:
            os.close(slave)
            with open(PID_FILE, "w") as f:
                f.write(str(sub_pid))
            
            log_f = open(LOG_OUT, "wb")
            fed = False
            while True:
                r, _, _ = select.select([master], [], [], 1.0)
                if master in r:
                    try:
                        data = os.read(master, 1024)
                    except OSError:
                        break
                    if not data:
                        break
                    log_f.write(data)
                    log_f.flush()
                    if not fed and b"passphrase" in data.lower():
                        time.sleep(0.3)
                        os.write(master, PASS)
                        fed = True
            log_f.close()
            os._exit(0)
    else:
        # Parent: write runner pid and wait for RPC readiness
        with open(RUNNER_PID_FILE, "w") as f:
            f.write(str(daemon_pid))

        for _ in range(25):
            time.sleep(0.5)
            try:
                token = get_sandbox_rpc_token()
                headers = {"Content-Type": "application/json"}
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                req = urllib.request.Request(
                    "http://127.0.0.1:21842/rpc",
                    data=json.dumps({"jsonrpc": "2.0", "method": "getblockcount", "params": {}, "id": 1}).encode(),
                    headers=headers
                )
                with urllib.request.urlopen(req, timeout=1) as resp:
                    if resp.status == 200:
                        print(f"✅ Sandbox node successfully started and ready on port 21842!")
                        return
            except urllib.error.HTTPError as e:
                if e.code in (200, 401):
                    print(f"✅ Sandbox node successfully started and responding on port 21842!")
                    return
            except Exception:
                pass

        print(f"[*] Sandbox process launched. Run `python3 sandbox_ctl.py status` to check progress.")

def stop_sandbox():
    stopped_any = False
    for pf in [PID_FILE, RUNNER_PID_FILE]:
        if os.path.exists(pf):
            try:
                with open(pf, "r") as f:
                    pid = int(f.read().strip())
                os.killpg(os.getpgid(pid), signal.SIGTERM)
                stopped_any = True
            except Exception:
                pass
            finally:
                if os.path.exists(pf):
                    os.remove(pf)

    if stopped_any:
        print("[*] Terminated sandbox node.")
    else:
        print("[*] Sandbox node is not running.")

def status_sandbox():
    if not os.path.exists(PID_FILE):
        print("Sandbox Status: STOPPED")
        return False
    try:
        with open(PID_FILE, "r") as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
        print(f"Sandbox Status: RUNNING (PID: {pid}) on http://127.0.0.1:21842/rpc")
        return True
    except Exception:
        print("Sandbox Status: STALE PID (Process not active)")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sandbox_ctl.py [start|stop|status|restart]")
        sys.exit(1)

    cmd = sys.argv[1].lower()
    if cmd == "start":
        start_sandbox()
    elif cmd == "stop":
        stop_sandbox()
    elif cmd == "restart":
        stop_sandbox()
        time.sleep(1)
        start_sandbox()
    elif cmd == "status":
        status_sandbox()
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
