#!/usr/bin/env python3
import os
from pathlib import Path

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def otp_key(n: int) -> bytes:
    return os.urandom(n) 

def main():
    flag_path = Path("flag.txt")
    if not flag_path.exists():
        raise FileNotFoundError("You done goofed! flag.txt not found.")

    flag = flag_path.read_text().strip().encode("utf-8")

    msg1 = (
        b"From: admin@company.internal\n"
        b"To: ops@company.internal\n"
        b"Subject: deployment status\n\n"
        b"All services are online. No action required at this time.\n"
    )

    msg2 = (
        b"From: ops@company.internal\n"
        b"To: admin@company.internal\n"
        b"Subject: re: deployment status\n\n"
        b"Audit reference: " + flag + b"\n"
    )
    key = otp_key(len(msg2))
    c1 = xor(msg1, key)
    c2 = xor(msg2, key)
    
    with open("output.txt", "w", encoding="utf-8") as f:
        f.write("c1=" + c1.hex() + "\n")
        f.write("c2=" + c2.hex() + "\n")

    print("[+] Wrote output.txt")
    print(f"[i] len(msg1)={len(msg1)} len(msg2)={len(msg2)} key_len={len(key)}")

if __name__ == "__main__":
    main()
