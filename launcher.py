#!/usr/bin/env python3
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PORT = int(os.environ.get("PORT", "8000"))
NGROK_URL = os.environ.get("NGROK_URL", "https://gumming-jersey-rewash.ngrok-free.dev")

SERVER_CMD = [sys.executable, str(ROOT / "mcp_fs_server.py")]
NGROK_CMD = ["ngrok", "http", str(PORT), "--url", NGROK_URL]


def spawn_process_group(cmd: list[str]) -> subprocess.Popen:
    return subprocess.Popen(
        cmd,
        start_new_session=True,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )


def wait_for_health(port: int, attempts: int = 50, delay: float = 0.2) -> bool:
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1):
                return True
        except Exception:
            time.sleep(delay)
    return False


def kill_process_group(proc: subprocess.Popen, sig: signal.Signals) -> None:
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            pass


def terminate_processes(processes: list[subprocess.Popen], grace_period: float = 3.0) -> None:
    for proc in processes:
        kill_process_group(proc, signal.SIGTERM)

    deadline = time.time() + grace_period
    while time.time() < deadline:
        if all(proc.poll() is not None for proc in processes):
            return
        time.sleep(0.1)

    for proc in processes:
        kill_process_group(proc, signal.SIGKILL)


def main() -> None:
    server = spawn_process_group(SERVER_CMD)
    print(f"[launcher] server pid={server.pid}")

    if not wait_for_health(PORT):
        print("[launcher] server failed health check", file=sys.stderr)
        terminate_processes([server])
        sys.exit(1)

    print("[launcher] server up.")

    ngrok = spawn_process_group(NGROK_CMD)
    print(f"[launcher] ngrok pid={ngrok.pid}")

    tracked_processes = [ngrok, server]

    def shutdown(*_args) -> None:
        print("[launcher] shutting down...")
        terminate_processes(tracked_processes)
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        while True:
            time.sleep(1)
            for proc in tracked_processes:
                if proc.poll() is not None:
                    print(f"[launcher] child exited ({proc.pid})", file=sys.stderr)
                    shutdown()
    except KeyboardInterrupt:
        shutdown()


if __name__ == "__main__":
    main()
