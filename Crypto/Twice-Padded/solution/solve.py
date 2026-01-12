#!/usr/bin/env python3
import re
from pathlib import Path
from pwn import xor
# can use pwnlib's xor function instead of defining our own
'''
def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))
'''
def parse_output(path="output.txt"):
    text = Path(path).read_text().strip().splitlines()
    kv = {}
    for line in text:
        if "=" in line:
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()
    if "c1" not in kv or "c2" not in kv:
        raise ValueError("output.txt must contain lines like c1=<hex> and c2=<hex>")
    return bytes.fromhex(kv["c1"]), bytes.fromhex(kv["c2"])

def solve():
    c1, c2 = parse_output("output.txt")

    # MUST match chal.py exactly
    msg1 = (
        b"From: admin@company.internal\n"
        b"To: ops@company.internal\n"
        b"Subject: deployment status\n\n"
        b"All services are online. No action required at this time.\n"
    )

    key_prefix = xor(c1, msg1)    
    msg2_prefix = xor(c2, key_prefix)
    print("[+] Decrypted msg2 prefix:\n")
    print(msg2_prefix.decode(errors="replace"))
    m = re.search(rb"(GRIZZ\{[A-Za-z]+\})", msg2_prefix)
    if m:
        print("\n[+] FLAG:", m.group(1).decode())
        return
if __name__ == "__main__":
    solve()
