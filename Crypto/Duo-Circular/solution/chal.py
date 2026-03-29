#!/usr/bin/env python3
"""
Ref: Amutha & Perumal, "Two party key exchange protocol based on duo
     circulant matrices for the IoT environment", Int J Inf Technol, 202

Ref: Chavhan & Chaudhari, "Structural Collapse of the Amutha–Perumal
     Scheme Based on Duo Circulant Matrices", ePrint 2026/354.
"""

import json
import os
import hashlib
import random
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


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


def main():
    # ── Read flag ──
    flag_path = os.path.join(os.path.dirname(__file__), "flag.txt")
    with open(flag_path, "r") as f:
        flag = f.read().strip()

    # ── Public parameters ──
    random.seed(0xDEAD_BEEF)  # reproducible for grading
    m = 6                     # matrix dimension
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

    # ── Device 2 (Bob) secrets ──
    a2 = random.randint(-10**5, 10**5)
    b2 = random.randint(-10**5, 10**5)

    A1 = build_duo_circulant(a1, alpha, v, w, m)
    B1 = build_duo_circulant(b1, alpha, c, w, m)
    A2 = build_duo_circulant(a2, alpha, v, w, m)
    B2 = build_duo_circulant(b2, alpha, c, w, m)

    Ka = trop_mat_mul(trop_mat_mul(A1, X), B1)
    Kb = trop_mat_mul(trop_mat_mul(A2, X), B2)

    K_alice = trop_mat_mul(trop_mat_mul(A1, Kb), B1)

    K_bob = trop_mat_mul(trop_mat_mul(A2, Ka), B2)
    assert np.allclose(K_alice, K_bob), "Key agreement failed!"

    key_material = ",".join(str(int(x)) for x in K_alice.flatten())
    aes_key = hashlib.sha256(key_material.encode()).digest()

    iv = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(flag.encode(), AES.block_size))

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


if __name__ == "__main__":
    main()
