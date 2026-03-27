#!/usr/bin/env python3
"""
Ashes of the Mint - challenge generator

Theme:
    A royal mint ledger partially burned. The top of one prime survived,
    but the lower digits were lost to the fire. Recover the missing tail,
    factor the modulus, and decrypt the royal dispatch.

Challenge model:
    - 2048-bit RSA modulus N = p*q
    - e = 65537
    - The high bits of q are known
    - The low UNKNOWN_BITS of q are missing
    - This is intended to be solved with a known-high-bits factoring attack
      using Coppersmith/Howgrave-Graham on:
            f(x) = qbar + x
      where q = qbar + x and |x| < X

Outputs:
    - challenge.txt
    - challenge.json
"""

from __future__ import annotations

import json
from pathlib import Path
from Crypto.Util.number import getPrime, bytes_to_long, inverse
import os
# ---------------------- configuration ----------------------

OUTDIR = Path(".")
CHALLENGE_JSON = OUTDIR / "challenge.json"
CHALLENGE_TXT = OUTDIR / "challenge.txt"

FLAG = b"GRIZZ{ashes_of_the_mint_the_crown_survived_the_tail_did_not}"
RSA_BITS = 2048
PRIME_BITS = RSA_BITS // 2
E = 65537

# Hidden low bits of q.
# For a 2048-bit modulus with the known-high-bits factor attack,
# keeping this comfortably below the asymptotic N^(1/4) zone is a good idea.
# 220-280 is a reasonable practical zone for a CTF depending on solver quality.
UNKNOWN_BITS = 240

# ---------------------- helpers ----------------------

def long_to_hex_blocks(x: int, block: int = 8) -> str:
    s = f"{x:x}"
    if len(s) % block:
        s = "0" * (block - (len(s) % block)) + s
    return " ".join(s[i:i+block] for i in range(0, len(s), block))

def format_burned_fragment(q_prefix: int, unknown_bits: int, total_bits: int) -> str:
    """
    Present the known prefix of q in-story.
    We reveal q >> unknown_bits, i.e. the crown/high bits.
    """
    prefix_hex = f"{q_prefix:x}"
    grouped = " ".join(prefix_hex[i:i+4] for i in range(0, len(prefix_hex), 4))
    return (
        "Recovered ledger fragment (upper carving survives):\n"
        f"  {grouped}\n\n"
        f"Archivist's note:\n"
        f"  The lower {unknown_bits} bits were burned away.\n"
        f"  Only the crown of the divisor remains.\n"
        f"  The full divisor was {total_bits} bits long.\n"
    )

# ---------------------- key generation ----------------------

def main() -> None:
    print("[*] Generating 2048-bit RSA challenge...")

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

        m = bytes_to_long(FLAG)
        if m >= n:
            raise ValueError("Flag too large for modulus.")

        c = pow(m, E, n)

        # Known-high-bits leak:
        # q = (q_prefix << UNKNOWN_BITS) + x
        # where x is the missing low-bit tail.
        q_prefix = q >> UNKNOWN_BITS
        q_bar = q_prefix << UNKNOWN_BITS
        x = q - q_bar

        # Sanity: x must fit the chosen bound.
        if 0 <= x < (1 << UNKNOWN_BITS):
            break

    crown_fragment = format_burned_fragment(q_prefix, UNKNOWN_BITS, PRIME_BITS)

    handout = f"""\
Ashes of the Mint
=================

The royal mint sealed a wartime dispatch under a public lock.

A fire swept through the archive. Most ledgers were lost.
One page survived only in part: the top of a sacred divisor remained legible,
but its lower digits were charred away.

The Archivist insists this fragment came from one of the two great divisors
used to forge the public lock.

"I am whole, but you know only my crown.
My feet are missing, though they were never many.
I divide the king's burden exactly,
and once restored, I reveal his hidden decree."

Public lock:
n = {n}

e = {E}

Sealed dispatch:
c = {c}

{crown_fragment}

Task:
Recover the missing tail of the divisor, factor the lock, and reveal the dispatch.
"""

    challenge_json = {
        "name": "Ashes of the Mint",
        "description": "Known high bits of one RSA prime factor are leaked; recover the missing low bits via a small-root attack and decrypt the ciphertext.",
        "n": str(n),
        "e": E,
        "c": str(c),
        "prime_bits": PRIME_BITS,
        "unknown_bits": UNKNOWN_BITS,
        "q_prefix": str(q_prefix),
        # The following are generator-side/private; remove for release if desired.
        "_private": {
            "p": str(p),
            "q": str(q),
            "d": str(d),
            "x": str(x),
            "q_bar": str(q_bar),
            "flag": FLAG.decode(),
        },
    }

    CHALLENGE_TXT.write_text(handout, encoding="utf-8")
    CHALLENGE_JSON.write_text(json.dumps(challenge_json, indent=2), encoding="utf-8")

    print(f"[+] Wrote {CHALLENGE_TXT}")
    print(f"[+] Wrote {CHALLENGE_JSON}")
    print("[+] Done.")
    print()
    print("[Creator sanity]")
    print(f"    q has {q.bit_length()} bits")
    print(f"    q_prefix has {q_prefix.bit_length()} bits")
    print(f"    missing tail x has {x.bit_length()} bits")
    print(f"    x < 2^{UNKNOWN_BITS}: {x < (1 << UNKNOWN_BITS)}")

def rndstr(n):
    import strings, random
    return ''.join(random.choice(strings.printable) for i in n)

def generate_tests():
    ctx = 0
    for i in range(0, 101):
        ctx +=1
        pt = rndstr(ctx)
        with open(f"challenge_{i}.json", "w") as f:
            json.dump({
                "pt": pt,
                "ct": pt[::-1],
            }, f, indent=2)

# display matrix picture with 0 and X
def matrix_overview(BB, bound):
    for ii in range(BB.dimensions()[0]):
        a = ('%02d ' % ii)
        for jj in range(BB.dimensions()[1]):
            a += '0' if BB[ii,jj] == 0 else 'X'
            a += ' '
        if BB[ii, ii] >= bound:
            a += '~'
        print(a)
    
if __name__ == "__main__":
    main()
