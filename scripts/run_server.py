#!/usr/bin/env python3
"""Start FastAPI server for CyberSentinel Evolver (dev or E2E).

If EVOLVER_DB env var is unset and --test-db flag is passed (or running under
Playwright), uses a temp DB file so E2E tests don't clobber production data.

Usage:
    python scripts/run_server.py [--host 127.0.0.1] [--port 8080] [--test-db]
"""
from __future__ import annotations

import argparse
import os
import socket
import sys
import tempfile
from pathlib import Path


def find_free_port(start: int = 8080, attempts: int = 20) -> int:
    """Find a free TCP port near `start`."""
    for port in range(start, start + attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    raise RuntimeError(f"No free port found in range {start}..{start + attempts - 1}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run FastAPI server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0, help="0 = auto-find")
    parser.add_argument("--test-db", action="store_true", help="Use a temp DB file")
    args = parser.parse_args()

    # Set test DB path if requested
    if args.test_db and "EVOLVER_DB" not in os.environ:
        tmp_path = Path(tempfile.mkdtemp()) / "e2e_test.db"
        os.environ["EVOLVER_DB"] = str(tmp_path)
        print(f"[run_server] Test DB: {tmp_path}", file=sys.stderr)

    # Auto-find port if 0 (prevents collisions with dev server)
    port = args.port if args.port else find_free_port()
    host = args.host

    # Import after env is set so server.py picks up EVOLVER_DB
    import uvicorn

    from cybersentinel_evolver.server import app

    print(f"[run_server] Starting on {host}:{port}", file=sys.stderr)
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
