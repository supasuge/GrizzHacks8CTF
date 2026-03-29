<<<<<<< HEAD
#!/usr/bin/python3


#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  TROPIKOS IoT Key Exchange — Challenge Script                    ║
║  GrizzHacks 8 CTF — Crypto / 450pts                             ║
║                                                                  ║
║  An industrial IoT gateway uses the "DuoCirculant™" key          ║
║  exchange protocol (based on α-v-w-duo circulant matrices over   ║
║  the max-plus tropical semiring) to negotiate session keys.      ║
║                                                                  ║
║  You intercepted one session. Can you recover the key?           ║
╚══════════════════════════════════════════════════════════════════╝

Ref: Amutha & Perumal, "Two party key exchange protocol based on duo
     circulant matrices for the IoT environment", Int J Inf Technol, 2024.

     Chavhan & Chaudhari, "Structural Collapse of the Amutha–Perumal
     Scheme Based on Duo Circulant Matrices", ePrint 2026/354.
"""

import json
import os
import hashlib
import random
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# ──────────────────────────────────────────────────────────────────
# Max-plus (tropical) semiring operations
# We represent -∞ as None (the additive identity).
# ──────────────────────────────────────────────────────────────────

NEG_INF = float("-inf")


def trop_add(a: float, b: float) -> float:
    """Tropical addition: max(a, b)."""
    return max(a, b)


def trop_mul(a: float, b: float) -> float:
    """Tropical multiplication: a + b (ordinary addition)."""
    if a == NEG_INF or b == NEG_INF:
        return NEG_INF
    return a + b


def trop_mat_mul(A: np.ndarray, B: np.ndarray) -> np.ndarray:
    """
    Tropical matrix multiplication over the max-plus semiring.

    (A ⊙ B)_{ij} = max_k { A_{ik} + B_{kj} }

    We use -∞ (NEG_INF) as the zero element.
    """
    m = A.shape[0]
    n = B.shape[1]
    p = A.shape[1]
    C = np.full((m, n), NEG_INF)
    for i in range(m):
        for j in range(n):
            for k in range(p):
                val = trop_mul(A[i, k], B[k, j])
                C[i, j] = trop_add(C[i, j], val)
    return C


# ──────────────────────────────────────────────────────────────────
# α-v-w-duo circulant matrix construction
#
# Given public params (α, v, w) and a first-row parameter p1,
# the row entries r_1, r_2, ..., r_m satisfy the recurrence:
#
#   r_1 = p1
#   r_i = α ⊙ r_{i-1}  ⊕  v     for i = 2, ..., m
#       = max(α + r_{i-1}, v)
#
# The matrix is then a w-circulant: each subsequent row is obtained
# by cyclically shifting the previous row right, with the wrap-around
# element increased by w.
# ──────────────────────────────────────────────────────────────────

def build_row(p1: int, alpha: int, v: int, m: int) -> list:
    """Build the first row [r_1, ..., r_m] of a duo circulant matrix."""
    row = [0] * m
    row[0] = p1
    for i in range(1, m):
        row[i] = max(alpha + row[i - 1], v)
    return row


def build_duo_circulant(p1: int, alpha: int, v_or_c: int, w: int, m: int) -> np.ndarray:
    """
    Construct an m×m α-v-w-duo circulant matrix (or α-c-w variant)
    from a first-row parameter p1.

    The w-circulant structure means:
        M[i][j] = first_row[(j - i) mod m]           if j >= i
        M[i][j] = first_row[(j - i) mod m] + w * 1   (wrap-around adds w)

    More precisely, for a w-circulant, when the shift wraps around,
    each wrapped element gets w added.
    """
    first_row = build_row(p1, alpha, v_or_c, m)
    M = np.full((m, m), NEG_INF)
    for i in range(m):
        for j in range(m):
            shift = (j - i) % m
            # Number of times the element has "wrapped around"
            wraps = 1 if j < i else 0
            M[i][j] = first_row[shift] + w * wraps
    return M.astype(float)


# ──────────────────────────────────────────────────────────────────
# Key Exchange Protocol (Amutha-Perumal, 2024)
#
# Public parameters: m, α, w, v, c, and a public matrix X ∈ Z^{m×m}
#
# Device 1 (Alice):
#   - Picks secret a1, b1
#   - Builds A1 ∈ A_v  (using p1 = a1, family param = v)
#   - Builds B1 ∈ B_c  (using p1 = b1, family param = c)
#   - Computes Ka = A1 ⊙ X ⊙ B1    (public message)
#
# Device 2 (Bob):
#   - Picks secret a2, b2
#   - Builds A2 ∈ A_v  (using p1 = a2, family param = v)
#   - Builds B2 ∈ B_c  (using p1 = b2, family param = c)
#   - Computes Kb = A2 ⊙ X ⊙ B2    (public message)
#
# Shared key (due to commutativity of A_v and B_c):
#   K = A1 ⊙ A2 ⊙ X ⊙ B1 ⊙ B2
#     = A2 ⊙ A1 ⊙ X ⊙ B2 ⊙ B1   (same thing)
#
# Alice computes:  K = A1 ⊙ Kb ⊙ B1
# Bob computes:    K = A2 ⊙ Ka ⊙ B2
# ──────────────────────────────────────────────────────────────────

ALICE = None 
BOB = None
ATTACKER_LISTENING=None
def main():
    # ── Read flag ──
    flag_path = os.path.join(os.path.dirname(__file__), "flag.txt")
    with open(flag_path, "r") as f:
        flag = f.read().strip()

    # ── Public parameters ──
    m = 24                     # matrix dimension
    alpha = random.randint(50, 200)
    w = random.randint(5, 30)
    v = random.randint(-500, -50)
    c = random.randint(-500, -50)

    # Public matrix X (random integer entries)
    X = np.array(
        [[random.randint(-1000, 1000) for _ in range(m)] for _ in range(m)],
        dtype=float,
    )

    # ── Device 1 (Alice) secrets ──
    a1 = random.randint(-10**5, 10**5)
    b1 = random.randint(-10**5, 10**5)
    print(f"Alices secrets: {a1}\n")
    print(f"Alices secrets: {a2}")
    # ── Device 2 (Bob) secrets ──
    a2 = random.randint(-10**5, 10**5)
    b2 = random.randint(-10**5, 10**5)
    print(f"Bobs secrets: {a2}\nBobs secrets: {b2}\n")

    # ── Build secret matrices ──
    A1 = build_duo_circulant(a1, alpha, v, w, m)
    B1 = build_duo_circulant(b1, alpha, c, w, m)
    A2 = build_duo_circulant(a2, alpha, v, w, m)
    B2 = build_duo_circulant(b2, alpha, c, w, m)

    # ── Compute public messages ──
    Ka = trop_mat_mul(trop_mat_mul(A1, X), B1)
    Kb = trop_mat_mul(trop_mat_mul(A2, X), B2)

    # ── Compute shared session key (Alice's perspective) ──
    K_alice = trop_mat_mul(trop_mat_mul(A1, Kb), B1)

    # ── Verify correctness (Bob's perspective) ──
    K_bob = trop_mat_mul(trop_mat_mul(A2, Ka), B2)
    assert np.allclose(K_alice, K_bob), "Key agreement failed!"

    # ── Derive AES key from the session key matrix ──
    # Flatten, convert to string, hash with SHA-256
    key_material = ",".join(str(int(x)) for x in K_alice.flatten())
    aes_key = hashlib.sha256(key_material.encode()).digest()

    # ── Encrypt the flag ──
    iv = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(flag.encode(), AES.block_size))

    # ── Write output.txt ──
    output = {
        "description": (
            "TROPIKOS™ DuoCirculant Key Exchange — Intercepted Session\n"
            "You have captured one key-exchange session between two IoT gateways.\n"
            "The protocol uses α-v-w-duo circulant matrices over the max-plus semiring.\n"
            "Recover the shared session key to decrypt the flag."
        ),
        "public_params": {
            "m": m,
            "alpha": alpha,
            "w": w,
            "v": v,
            "c": c,
        },
        "public_matrix_X": X.tolist(),
        "intercepted": {
            "Ka": Ka.tolist(),
            "Kb": Kb.tolist(),
        },
        "encrypted_flag": {
            "iv": iv.hex(),
            "ciphertext": ct.hex(),
        },
    }

    out_path = os.path.join(os.path.dirname(__file__), "output.txt")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"[+] Challenge generated → output.txt")
    print(f"[+] Matrix dimension m = {m}")
    print(f"[+] Public params: α={alpha}, w={w}, v={v}, c={c}")
    print(f"[+] AES key (hex): {aes_key.hex()}")
    print(f"[+] Flag: {flag}")
=======
#!/usr/bin/env python3
"""
Tropic Like It's Hot
"""

from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path
from typing import List

# ---------------------- challenge parameters ----------------------

OUT_JSON = Path("challenge.json")
OUT_TXT = Path("challenge.txt")

# "Difficult" here means the one-time O(m^3) max-plus precomputation is larger.
# The scheme is still structurally broken by design.
M = 64

# Public "recipe" parameters
ALPHA = 913_271
W = 37
V = 22_001
C = -18_777
ZIG_A = 11
ZIG_B = 17
LIME_A = 29
LIME_B = 43

# Secret scalar parameters (the real secret material)
SECRET_RANGE = 2_000_000

FLAG = open('flag.txt', 'rb').read()
RNG = random.SystemRandom()

# ---------------------- max-plus helpers ----------------------

Matrix = List[List[int]]

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
            # max-plus: out[i][j] = max(out[i][j], A[i][k] + B[k][j])
            for j in range(n):
                cand = aik + Bk[j]
                if cand > out[i][j]:
                    out[i][j] = cand
    return out

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

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

def build_secret_family_member(secret: int, template: Matrix) -> Matrix:
    return maxplus_add_scalar(secret, template)

def random_matrix(m: int, lo: int, hi: int) -> Matrix:
    return [[RNG.randint(lo, hi) for _ in range(m)] for _ in range(m)]

# ---------------------- main generation ----------------------

def main() -> None:
    C_A = build_public_template(M, ALPHA, W, V, ZIG_A, LIME_A)
    C_B = build_public_template(M, ALPHA, W, C, ZIG_B, LIME_B)

    # Four secret scalars
    a1 = RNG.randint(-SECRET_RANGE, SECRET_RANGE)
    b1 = RNG.randint(-SECRET_RANGE, SECRET_RANGE)
    a2 = RNG.randint(-SECRET_RANGE, SECRET_RANGE)
    b2 = RNG.randint(-SECRET_RANGE, SECRET_RANGE)

    # Secret matrices
    A1 = build_secret_family_member(a1, C_A)
    B1 = build_secret_family_member(b1, C_B)
    A2 = build_secret_family_member(a2, C_A)
    B2 = build_secret_family_member(b2, C_B)

    # Public transport matrix
    X = random_matrix(M, -750_000, 750_000)

    # Protocol messages
    Ka = maxplus_mul(maxplus_mul(A1, X), B1)
    Kb = maxplus_mul(maxplus_mul(A2, X), B2)

    # Shared key matrix
    Y1 = maxplus_mul(maxplus_mul(A1, Kb), B1)
    Y2 = maxplus_mul(maxplus_mul(A2, Ka), B2)
    assert Y1 == Y2, "Protocol correctness failed unexpectedly."
    K = Y1

    # Encrypt the flag using a hash-derived keystream from the shared key matrix
    seed = hashlib.sha256(matrix_to_bytes(K)).digest()
    keystream = expand_keystream(seed, len(FLAG))
    flag_enc = xor_bytes(FLAG, keystream).hex()

    handout = f"""\
Tropic Like It's Hot
====================

SmoothieMesh IoT insists its beachside blender fleet uses a "tropical semiring secure
duo-circulant mixer exchange" that is definitely, absolutely, probably not broken.

You intercepted one session between Kiosk #1 ("Mango Oblivion") and Kiosk #2
("Banana Zero-Trust").

The vendor says the protocol is safe because:
  - it uses matrices,
  - it uses tropical algebra,
  - the brochure had a palm tree on it.

Recover the shared mixer state and decrypt the encrypted order token.

Public parameters:
  m      = {M}
  alpha  = {ALPHA}
  w      = {W}
  v      = {V}
  c      = {C}
  zig_a  = {ZIG_A}
  zig_b  = {ZIG_B}
  lime_a = {LIME_A}
  lime_b = {LIME_B}

Files:
  - challenge.json

Goal:
  Recover the flag from the intercepted transcript.
"""

    obj = {
        "name": "Tropic Like It's Hot",
        "flavor_text": handout,
        "public": {
            "m": M,
            "alpha": ALPHA,
            "w": W,
            "v": V,
            "c": C,
            "zig_a": ZIG_A,
            "zig_b": ZIG_B,
            "lime_a": LIME_A,
            "lime_b": LIME_B,
            "X": X,
            "Ka": Ka,
            "Kb": Kb,
            "flag_enc": flag_enc,
        },
        "_private": {
            "a1": a1,
            "b1": b1,
            "a2": a2,
            "b2": b2,
            "K": K,
            "flag": FLAG.decode(),
        },
    }

    OUT_JSON.write_text(json.dumps(obj), encoding="utf-8")
    OUT_TXT.write_text(handout, encoding="utf-8")

    print(f"[+] wrote {OUT_JSON}")
    print(f"[+] wrote {OUT_TXT}")
    print("[+] challenge generated")
    print(f"[+] matrix dimension m = {M}")
    print("[+] difficulty note: larger m only increases one-time tropical multiplication cost")
>>>>>>> bd185c3 (more stuff)


if __name__ == "__main__":
    main()
