#!/usr/bin/env python3
"""
Generate 100 RSA CTF instances for the known-high-bits factor attack.

Each instance contains:
- a fresh 2048-bit RSA modulus N = p*q
- e = 65537
- one unique plaintext message
- ciphertext c
- leaked high bits of q via q_prefix = q >> unknown_bits

Outputs:
- batch_challenges.json

Notes:
- This is a creator-side generator.
- It does NOT guarantee solver success by itself.
- Use benchmark_solver.py to measure empirical success rates.
"""

from __future__ import annotations

import json
import random
import secrets
from pathlib import Path
from typing import Dict, List

from Crypto.Util.number import getPrime, bytes_to_long, inverse

OUTFILE = Path("batch_challenges.json")

NUM_INSTANCES = 50
RSA_BITS = 2048
PRIME_BITS = RSA_BITS // 2
E = 65537

# For practical reliability testing, 200 is safer than 240.
# Increase once your solver benchmark is consistently healthy.
UNKNOWN_BITS = 184

THEME_NAME = "Ashes of the Mint"

MESSAGE_PREFIXES = [
    "The crown survived the fire",
    "The royal mint remembers",
    "Only the upper carving remained",
    "The sacred divisor lost its feet",
    "The archivist restored the seal",
    "The burden divided cleanly",
    "The war ledger was scorched",
    "The decree slept behind the lock",
    "The fragment belonged to the mint",
    "The king trusted twin divisors",
]


def build_plaintext(i: int) -> bytes:
    """
    Generate unique plaintext messages.
    """
    phrase = MESSAGE_PREFIXES[i % len(MESSAGE_PREFIXES)]
    nonce = secrets.token_hex(8)
    msg = f"GRIZZ{{batch_{i:03d}_{phrase.lower().replace(' ', '_')}_{nonce}}}"
    return msg.encode()


def gen_instance(i: int) -> Dict:
    while True:
        p = getPrime(PRIME_BITS)
        q = getPrime(PRIME_BITS)
        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)

        if phi % E == 0:
            continue

        d = inverse(E, phi)
        if d is None:
            continue

        pt = build_plaintext(i)
        m = bytes_to_long(pt)
        if m >= n:
            continue

        c = pow(m, E, n)

        q_prefix = q >> UNKNOWN_BITS
        q_bar = q_prefix << UNKNOWN_BITS
        x = q - q_bar

        if not (0 <= x < (1 << UNKNOWN_BITS)):
            continue

        return {
            "instance_id": i,
            "theme": THEME_NAME,
            "n": str(n),
            "e": E,
            "c": str(c),
            "prime_bits": PRIME_BITS,
            "unknown_bits": UNKNOWN_BITS,
            "q_prefix": str(q_prefix),
            # private verification material
            "_private": {
                "p": str(p),
                "q": str(q),
                "d": str(d),
                "x": str(x),
                "q_bar": str(q_bar),
                "plaintext": pt.decode(),
            },
        }


def main() -> None:
    print(f"[*] Generating {NUM_INSTANCES} challenge instances...")
    dataset: List[Dict] = []
    ctx = 0
    for i in range(NUM_INSTANCES):
        ctx += 5
        inst = gen_instance(i)
        dataset.append(inst)
        print(
            f"[+] Instance {i:03d}: "
            f"N_bits={int(inst['n']).bit_length()} "
            f"q_prefix_bits={int(inst['q_prefix']).bit_length()} "
            f"unknown_bits={inst['unknown_bits']}"
        )
        if ctx % 5 == 0:
            i+=1
    
    

    OUTFILE.write_text(json.dumps({"instances": dataset}, indent=2), encoding="utf-8")
    print(f"[+] Wrote {OUTFILE}")


if __name__ == "__main__":
    main()
