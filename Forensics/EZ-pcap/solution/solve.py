#!/usr/bin/env python3
"""
EZ-pcap solver
"""

from __future__ import annotations

import argparse
import base64
import re
import sys
from pathlib import Path
from typing import Iterable, Optional

# Scapy is the most portable way to parse PCAP in Python for CTF tooling.
# Install (Arch): sudo pacman -S python-scapy OR sudo apt install python3-scapy (debian/ubuntu) OR pip: pip install scapy
# Or pip: pip install scapy
try:
    from scapy.all import rdpcap, TCP, Raw  # type: ignore
except Exception as e:
    print("[!] Missing dependency: scapy", file=sys.stderr)
    print("    Install with: pip install scapy  (or your distro package: python-scapy)", file=sys.stderr)
    raise

FLAG_RE = re.compile(r"GRIZZ\{[^}]+\}")
B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{16,}={0,2})")


def iter_tcp_payloads(pcap_path: Path) -> Iterable[bytes]:
    """
    Yield TCP Raw payload bytes from a PCAP.
    We don't fully reassemble TCP streams because for this challenge it isn't necessary:
    the base64 flag response typically appears as a contiguous ASCII blob in a single segment.
    """
    pkts = rdpcap(str(pcap_path))
    for p in pkts:
        if p.haslayer(TCP) and p.haslayer(Raw):
            yield bytes(p[Raw].load)


def try_decode_flag_from_blob(blob: bytes) -> Optional[str]:
    """
    Search for:
      - direct GRIZZ{...}
      - OR base64 that decodes into GRIZZ{...}
    """
    # Direct
    m = FLAG_RE.search(blob.decode(errors="ignore"))
    if m:
        return m.group(0)

    # Look for base64 chunks and attempt decode
    s = blob.decode(errors="ignore")
    for b64txt in B64_RE.findall(s):
        # Ignore very short matches, and avoid obvious false positives
        if len(b64txt) < 24:
            continue
        # base64 decoding requires proper padding
        padded = b64txt + ("=" * ((4 - (len(b64txt) % 4)) % 4))
        try:
            dec = base64.b64decode(padded, validate=False)
        except Exception:
            continue
        m2 = FLAG_RE.search(dec.decode(errors="ignore"))
        if m2:
            return m2.group(0)

    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Solve EZ-pcap and extract GRIZZ{...} flag.")
    ap.add_argument("pcap", help="Path to PCAP handout (e.g., handout/capture_victim.pcap)")
    args = ap.parse_args()

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        print(f"[-] PCAP not found: {pcap_path}", file=sys.stderr)
        return 2

    for payload in iter_tcp_payloads(pcap_path):
        flag = try_decode_flag_from_blob(payload)
        if flag:
            print(flag)
            return 0

    print("[-] Flag not found. Try opening in Wireshark and Follow TCP Stream on HTTP flows.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())