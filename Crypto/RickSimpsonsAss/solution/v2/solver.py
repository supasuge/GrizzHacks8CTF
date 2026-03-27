#!/usr/bin/env python3
"""
Solver for:
    Tropic Like It's Hot

Intended attack:
- Rebuild the public templates C_A and C_B by calling the same public template
  function with secret=0.
- Precompute:
      M = C_A ⊙ X ⊙ C_B
      U = C_A ⊙ C_A
      V = C_B ⊙ C_B
      W = U ⊙ X ⊙ V
- Recover:
      s = Ka[0][0] - M[0][0]   = a1 + b1
      t = Kb[0][0] - M[0][0]   = a2 + b2
      S = s + t
- Reconstruct:
      K = S + W
- Derive the keystream from K and decrypt the flag.

This solver is deterministic and should work every time for challenges generated
by src/chal.py.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import List

CHALLENGE_FILE = Path("batch_challenge.jsonn")

Matrix = List[List[int]]

# ---------------------- max-plus helpers ----------------------

def maxplus_add_scalar(s: int, A: Matrix) -> Matrix:
    return [[s + x for x in row] for row in A]

def maxplus_mul(A: Matrix, B: Matrix) -> Matrix:
    n = len(A)
    out = [[-(10**30)] * n for _ in range(n)]
    for i in range(n):
        Ai = A[i]
        for k in range(n):
            aik = Ai[k]
            Bk = B[k]
            for j in range(n):
                cand = aik + Bk[j]
                if cand > out[i][j]:
                    out[i][j] = cand
    return out

def matrix_to_bytes(A: Matrix) -> bytes:
    return ("\n".join(",".join(str(x) for x in row) for row in A)).encode()

def expand_keystream(seed: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# ---------------------- public template reconstruction ----------------------

def build_public_template(
    m: int,
    alpha: int,
    w: int,
    twist: int,
    zig: int,
    lime: int,
) -> Matrix:
    A = [[0] * m for _ in range(m)]
    for i in range(m):
        for j in range(m):
            offset = (j - i) % m

            base = alpha - offset * w
            if offset != 0:
                base += twist

            row_term = ((i * zig) % lime) - (lime // 2)
            col_term = ((j * (zig + 3)) % (lime + 7)) - ((lime + 7) // 2)
            orbit_term = ((i * 7 + j * 13 + offset * 5) % 19) - 9

            A[i][j] = base + row_term + col_term + orbit_term
    return A

# ---------------------- optional consistency checks ----------------------

def verify_shift_structure(Kmsg: Matrix, M: Matrix, sample_step: int = 7) -> int:
    """
    Check that Kmsg - M is a constant scalar shift across sampled entries.
    Return that scalar if consistent.
    """
    n = len(Kmsg)
    ref = Kmsg[0][0] - M[0][0]

    for i in range(0, n, sample_step):
        for j in range(0, n, sample_step):
            delta = Kmsg[i][j] - M[i][j]
            if delta != ref:
                raise ValueError(
                    f"shift structure failed at ({i}, {j}): got {delta}, expected {ref}"
                )
    return ref

# ---------------------- main solve ----------------------

def main() -> None:
    data = json.loads(CHALLENGE_FILE.read_text(encoding="utf-8"))
    pub = data["public"]

    m = pub["m"]
    alpha = pub["alpha"]
    w = pub["w"]
    v = pub["v"]
    c = pub["c"]
    zig_a = pub["zig_a"]
    zig_b = pub["zig_b"]
    lime_a = pub["lime_a"]
    lime_b = pub["lime_b"]
    X = pub["X"]
    Ka = pub["Ka"]
    Kb = pub["Kb"]
    flag_enc = bytes.fromhex(pub["flag_enc"])

    print("[*] rebuilding public templates...")
    C_A = build_public_template(m, alpha, w, v, zig_a, lime_a)
    C_B = build_public_template(m, alpha, w, c, zig_b, lime_b)

    print("[*] precomputing M, U, V, W...")
    Mmat = maxplus_mul(maxplus_mul(C_A, X), C_B)
    U = maxplus_mul(C_A, C_A)
    V = maxplus_mul(C_B, C_B)
    Wmat = maxplus_mul(maxplus_mul(U, X), V)

    print("[*] recovering scalar shifts from intercepted messages...")
    s = verify_shift_structure(Ka, Mmat)
    t = verify_shift_structure(Kb, Mmat)
    S = s + t

    print(f"[+] recovered s = a1 + b1 = {s}")
    print(f"[+] recovered t = a2 + b2 = {t}")
    print(f"[+] recovered S = a1 + a2 + b1 + b2 = {S}")

    print("[*] reconstructing shared key matrix...")
    K = maxplus_add_scalar(S, Wmat)

    print("[*] deriving keystream and decrypting flag...")
    seed = hashlib.sha256(matrix_to_bytes(K)).digest()
    keystream = expand_keystream(seed, len(flag_enc))
    flag = xor_bytes(flag_enc, keystream)

    try:
        decoded = flag.decode()
    except UnicodeDecodeError:
        decoded = repr(flag)

    print("[+] flag:")
    print(decoded)


if __name__ == "__main__":
    main()
