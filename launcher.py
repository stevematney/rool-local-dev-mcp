#!/usr/bin/env python3
"""
launcher.py — clean process supervision for the rool-fs dev stack.

Spawns the MCP server and ngrok in their own process groups, forwards
SIGINT/SIGTERM to them, and guarantees they are torn down on exit
(no orphans after Ctrl+C).

Usage:  python3 launcher.py          (from the repo directory)
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PORT = int(os.environ.get("PORT", "8000"))
NGROK_URL = os.environ.get("NGROK_URL", "https://your-subdomain.ngrok-free.dev")

SERVER_CMD = [sys.executable, str(ROOT / "mcp_fs_server.py")]
NGROK_CMD = ["ngrok", "http", str(PORT), "--url", NGROK_URL]


def make_group(cmd: list[str]):
    # start in a new session/process group so we can signal the whole tree
    return subprocess.Popen(
        cmd,
        start_new_session=True,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )


def main() -> None:
    server = make_group(SERVER_CMD)
    print(f"[launcher] server pid={server.pid}")

    # wait for /health
    import urllib.request

    up = False
    for _ in range(50):
        if server.poll() is not None:
            print("[launcher] server exited early", file=sys.stderr)
            sys.exit(1)
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=1):
                up = True
                break
        except Exception:
            time.sleep(0.2)
    if not up:
        print("[launcher] server never came up", file=sys.stderr)
        server.terminate()
        sys.exit(1)
    print("[launcher] server up.")

    ngrok = make_group(NGROK_CMD)
    print(f"[launcher] ngrok pid={ngrok.pid}")

    def shutdown(*_):
        print("[launcher] shutting down…")
        for p in (ngrok, server):
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        # escalate after a grace period
        deadline = time.time() + 3
        while time.time() < deadline:
            if ngrok.poll() is not None and server.poll() is not None:
                break
            time.sleep(0.1)
        for p in (ngrok, server):
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # keep running until interrupted
    try:
        while True:
            time.sleep(1)
            for p in (ngrok, server):
                if p.poll() is not None:
                    print(f"[launcher] child exited ({p.pid})", file=sys.stderr)
                    shutdown()
    except KeyboardInterrupt:
        shutdown()


if __name__ == "__main__":
    main()
