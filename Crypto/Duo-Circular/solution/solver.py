<<<<<<< HEAD
#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  TROPIKOS IoT Key Exchange — Solve Script                        ║
║  Structural Collapse Attack (Chavhan & Chaudhari, ePrint 2026)   ║
║                                                                  ║
║  This implements Algorithm 1 from the paper:                     ║
║  "Structural Collapse of the Amutha–Perumal Scheme Based on      ║
║  Duo Circulant Matrices" (Cryptology ePrint Archive 2026/354).   ║
║                                                                  ║
║  The key insight (Lemma 3.1): Every α-v-w-duo circulant matrix   ║
║  with first-row parameter p1 decomposes as:                      ║
║                                                                  ║
║     A(p1) = p1 + C                                               ║
║                                                                  ║
║  where C is the CONSTANT matrix obtained by setting p1 = 0 in    ║
║  the recurrence, and "+ p1" means adding the scalar p1 to every  ║
║  entry.  This is the "affine collapse" — the entire secret       ║
║  matrix is determined by a single integer, and that integer       ║
║  can be extracted from a single entry of the public message.     ║
╚══════════════════════════════════════════════════════════════════╝
"""

import json
import hashlib
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ──────────────────────────────────────────────────────────────────
# Max-plus (tropical) semiring operations
# ──────────────────────────────────────────────────────────────────

NEG_INF = float("-inf")


def trop_mat_mul(A: np.ndarray, B: np.ndarray) -> np.ndarray:
    """
    Tropical matrix multiplication: (A ⊙ B)_{ij} = max_k { A_{ik} + B_{kj} }
    """
    m, p = A.shape
    _, n = B.shape
    C = np.full((m, n), NEG_INF)
    for i in range(m):
        for j in range(n):
            for k in range(p):
                a_val = A[i, k]
                b_val = B[k, j]
                if a_val == NEG_INF or b_val == NEG_INF:
                    val = NEG_INF
                else:
                    val = a_val + b_val
                if val > C[i, j]:
                    C[i, j] = val
    return C


# ──────────────────────────────────────────────────────────────────
# Build the "constant" part C of a duo circulant matrix
# by setting the first-row parameter p1 = 0 in the recurrence.
#
# Recurrence:
#   r_1 = p1 = 0
#   r_i = max(α + r_{i-1}, v)    for i = 2, ..., m
#
# The w-circulant structure then builds the full matrix.
# ──────────────────────────────────────────────────────────────────

def build_constant_matrix(alpha: int, v_or_c: int, w: int, m: int) -> np.ndarray:
    """
    Build C, the constant part of the duo circulant family,
    by evaluating the recurrence with p1 = 0.
    """
    row = [0] * m
    row[0] = 0  # p1 = 0
    for i in range(1, m):
        row[i] = max(alpha + row[i - 1], v_or_c)

    M = np.full((m, m), NEG_INF)
    for i in range(m):
        for j in range(m):
            shift = (j - i) % m
            wraps = 1 if j < i else 0
            M[i][j] = row[shift] + w * wraps
    return M.astype(float)


# ──────────────────────────────────────────────────────────────────
# STRUCTURAL COLLAPSE ATTACK (Algorithm 1)
#
# === Precomputation Phase (one-time, depends only on public params) ===
#
# 1.  C_A = constant matrix for family A_v  (p1 = 0)
#     C_B = constant matrix for family B_c  (p1 = 0)
#
# 2.  M  = C_A ⊙ X ⊙ C_B
#         This is the "base" of every public message Ka or Kb:
#           Ka = (a1 + C_A) ⊙ X ⊙ (b1 + C_B)
#            Since tropical multiplication distributes scalars:
#           Ka = (a1 + b1) + (C_A ⊙ X ⊙ C_B)
#           Ka = (a1 + b1) + M
#         So Ka(i,j) = M(i,j) + a1 + b1 for all i,j.
#
# 3.  U = C_A ⊙ C_A
# 4.  V = C_B ⊙ C_B
# 5.  W = U ⊙ X ⊙ V
#         The shared key has the form:
#           K = A1 ⊙ A2 ⊙ X ⊙ B1 ⊙ B2
#             = (a1 + a2) + C_A ⊙ C_A ⊙ X ⊙ C_B ⊙ C_B   ...wait,
#                                                              not quite.
#
#     Let's be precise.  We need:
#       K = A1 ⊙ A2 ⊙ X ⊙ B1 ⊙ B2
#
#     Since A1 = a1 + C_A  and  A2 = a2 + C_A  (entrywise scalar shift),
#     and tropical multiplication of (a + M) ⊙ N = a + (M ⊙ N):
#
#       A1 ⊙ A2 = (a1 + C_A) ⊙ (a2 + C_A)
#                = (a1 + a2) + (C_A ⊙ C_A)
#                = (a1 + a2) + U
#
#     Similarly:
#       B1 ⊙ B2 = (b1 + b2) + V
#
#     Therefore:
#       K = [(a1+a2) + U] ⊙ X ⊙ [(b1+b2) + V]
#         = (a1 + a2 + b1 + b2) + (U ⊙ X ⊙ V)
#         = (a1 + a2 + b1 + b2) + W
#
# === Online Phase (per intercepted session) ===
#
# 6.  Read Ka(0,0) and Kb(0,0) from the intercepted messages.
#
# 7.  s = Ka(0,0) - M(0,0)          → s = a1 + b1
# 8.  t = Kb(0,0) - M(0,0)          → t = a2 + b2
#
# 9.  K = (s + t) + W               (add scalar s+t to every entry of W)
#       = (a1 + b1 + a2 + b2) + W   ✓
#
# 10. return K
# ──────────────────────────────────────────────────────────────────


def structural_collapse_attack(params, X, Ka, Kb):
    """
    Execute the structural collapse attack.

    Args:
        params: dict with keys 'm', 'alpha', 'w', 'v', 'c'
        X:  public matrix (m×m numpy array)
        Ka: intercepted public message from Device 1
        Kb: intercepted public message from Device 2

    Returns:
        K:  the recovered shared session key (m×m numpy array)
    """
    m = params["m"]
    alpha = params["alpha"]
    w = params["w"]
    v = params["v"]
    c = params["c"]

    print("[*] ═══ PRECOMPUTATION PHASE ═══")

    # Step 1: Build constant matrices
    C_A = build_constant_matrix(alpha, v, w, m)
    C_B = build_constant_matrix(alpha, c, w, m)
    print(f"[+] Built C_A (constant matrix for family A_v, p1=0)")
    print(f"[+] Built C_B (constant matrix for family B_c, p1=0)")

    # Step 2: M = C_A ⊙ X ⊙ C_B
    M = trop_mat_mul(trop_mat_mul(C_A, X), C_B)
    print(f"[+] Computed M = C_A ⊙ X ⊙ C_B")
    print(f"    M[0,0] = {M[0,0]}")

    # Step 3: U = C_A ⊙ C_A
    U = trop_mat_mul(C_A, C_A)
    print(f"[+] Computed U = C_A ⊙ C_A")

    # Step 4: V = C_B ⊙ C_B
    V = trop_mat_mul(C_B, C_B)
    print(f"[+] Computed V = C_B ⊙ C_B")

    # Step 5: W = U ⊙ X ⊙ V
    W = trop_mat_mul(trop_mat_mul(U, X), V)
    print(f"[+] Computed W = U ⊙ X ⊙ V")

    print()
    print("[*] ═══ ONLINE PHASE ═══")

    # Step 6: Extract Ka(0,0) and Kb(0,0)
    ka_00 = Ka[0][0]
    kb_00 = Kb[0][0]
    print(f"[+] Ka[0,0] = {ka_00}")
    print(f"[+] Kb[0,0] = {kb_00}")

    # Step 7: s = Ka(0,0) - M(0,0)    → s = a1 + b1
    s = ka_00 - M[0, 0]
    print(f"[+] s = Ka[0,0] - M[0,0] = {s}  (= a1 + b1)")

    # Step 8: t = Kb(0,0) - M(0,0)    → t = a2 + b2
    t = kb_00 - M[0, 0]
    print(f"[+] t = Kb[0,0] - M[0,0] = {t}  (= a2 + b2)")

    # Step 9: K = (s + t) + W
    scalar = s + t
    K = W + scalar  # numpy broadcasts scalar addition
    print(f"[+] Recovered session key K = (s + t) + W")
    print(f"    scalar shift = {scalar}")

    return K


def main():
    # ── Load intercepted data ──
    with open("output.txt", "r") as f:
        data = json.load(f)

    params = data["public_params"]
    X = np.array(data["public_matrix_X"], dtype=float)
    Ka = np.array(data["intercepted"]["Ka"], dtype=float)
    Kb = np.array(data["intercepted"]["Kb"], dtype=float)

    iv = bytes.fromhex(data["encrypted_flag"]["iv"])
    ct = bytes.fromhex(data["encrypted_flag"]["ciphertext"])

    print("╔══════════════════════════════════════════════════════════════╗")
    print("║  Structural Collapse Attack on TROPIKOS™ DuoCirculant KE    ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║  Matrix dimension:  m = {params['m']}")
    print(f"║  Public parameters: α = {params['alpha']}, w = {params['w']}, "
          f"v = {params['v']}, c = {params['c']}")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()

    # ── Execute the attack ──
    K = structural_collapse_attack(params, X, Ka, Kb)

    print()
    print("[*] ═══ DECRYPTION ═══")

    # ── Derive AES key from recovered session key ──
    key_material = ",".join(str(int(x)) for x in K.flatten())
    aes_key = hashlib.sha256(key_material.encode()).digest()
    print(f"[+] Derived AES key: {aes_key.hex()}")

    # ── Decrypt the flag ──
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    try:
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        flag = pt.decode()
        print(f"[+] ✓ Decryption successful!")
        print()
        print(f"    ╔{'═' * (len(flag) + 4)}╗")
        print(f"    ║  {flag}  ║")
        print(f"    ╚{'═' * (len(flag) + 4)}╝")
    except Exception as e:
        print(f"[-] ✗ Decryption failed: {e}")
        print("    The recovered key does not match. Check the attack implementation.")


if __name__ == "__main__":
    main()
=======
#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  TROPIKOS IoT Key Exchange — Solve Script                        ║
║  Structural Collapse Attack (Chavhan & Chaudhari, ePrint 2026)   ║
║                                                                  ║
║  This implements Algorithm 1 from the paper:                     ║
║  "Structural Collapse of the Amutha–Perumal Scheme Based on      ║
║  Duo Circulant Matrices" (Cryptology ePrint Archive 2026/354).   ║
║                                                                  ║
║  The key insight (Lemma 3.1): Every α-v-w-duo circulant matrix   ║
║  with first-row parameter p1 decomposes as:                      ║
║                                                                  ║
║     A(p1) = p1 + C                                               ║
║                                                                  ║
║  where C is the CONSTANT matrix obtained by setting p1 = 0 in    ║
║  the recurrence, and "+ p1" means adding the scalar p1 to every  ║
║  entry.  This is the "affine collapse" — the entire secret       ║
║  matrix is determined by a single integer, and that integer       ║
║  can be extracted from a single entry of the public message.     ║
╚══════════════════════════════════════════════════════════════════╝
"""

import json
import hashlib
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ──────────────────────────────────────────────────────────────────
# Max-plus (tropical) semiring operations
# ──────────────────────────────────────────────────────────────────

NEG_INF = float("-inf")


def trop_mat_mul(A: np.ndarray, B: np.ndarray) -> np.ndarray:
    """
    Tropical matrix multiplication: (A ⊙ B)_{ij} = max_k { A_{ik} + B_{kj} }
    """
    m, p = A.shape
    _, n = B.shape
    C = np.full((m, n), NEG_INF)
    for i in range(m):
        for j in range(n):
            for k in range(p):
                a_val = A[i, k]
                b_val = B[k, j]
                if a_val == NEG_INF or b_val == NEG_INF:
                    val = NEG_INF
                else:
                    val = a_val + b_val
                if val > C[i, j]:
                    C[i, j] = val
    return C


# ──────────────────────────────────────────────────────────────────
# Build the "constant" part C of a duo circulant matrix
# by setting the first-row parameter p1 = 0 in the recurrence.
#
# Recurrence:
#   r_1 = p1 = 0
#   r_i = max(α + r_{i-1}, v)    for i = 2, ..., m
#
# The w-circulant structure then builds the full matrix.
# ──────────────────────────────────────────────────────────────────

def build_constant_matrix(alpha: int, v_or_c: int, w: int, m: int) -> np.ndarray:
    """
    Build C, the constant part of the duo circulant family,
    by evaluating the recurrence with p1 = 0.
    """
    row = [0] * m
    row[0] = 0  # p1 = 0
    for i in range(1, m):
        row[i] = max(alpha + row[i - 1], v_or_c)

    M = np.full((m, m), NEG_INF)
    for i in range(m):
        for j in range(m):
            shift = (j - i) % m
            wraps = 1 if j < i else 0
            M[i][j] = row[shift] + w * wraps
    return M.astype(float)


# ──────────────────────────────────────────────────────────────────
# STRUCTURAL COLLAPSE ATTACK (Algorithm 1)
#
# === Precomputation Phase (one-time, depends only on public params) ===
#
# 1.  C_A = constant matrix for family A_v  (p1 = 0)
#     C_B = constant matrix for family B_c  (p1 = 0)
#
# 2.  M  = C_A ⊙ X ⊙ C_B
#         This is the "base" of every public message Ka or Kb:
#           Ka = (a1 + C_A) ⊙ X ⊙ (b1 + C_B)
#            Since tropical multiplication distributes scalars:
#           Ka = (a1 + b1) + (C_A ⊙ X ⊙ C_B)
#           Ka = (a1 + b1) + M
#         So Ka(i,j) = M(i,j) + a1 + b1 for all i,j.
#
# 3.  U = C_A ⊙ C_A
# 4.  V = C_B ⊙ C_B
# 5.  W = U ⊙ X ⊙ V
#         The shared key has the form:
#           K = A1 ⊙ A2 ⊙ X ⊙ B1 ⊙ B2
#             = (a1 + a2) + C_A ⊙ C_A ⊙ X ⊙ C_B ⊙ C_B   ...wait,
#                                                              not quite.
#
#     Let's be precise.  We need:
#       K = A1 ⊙ A2 ⊙ X ⊙ B1 ⊙ B2
#
#     Since A1 = a1 + C_A  and  A2 = a2 + C_A  (entrywise scalar shift),
#     and tropical multiplication of (a + M) ⊙ N = a + (M ⊙ N):
#
#       A1 ⊙ A2 = (a1 + C_A) ⊙ (a2 + C_A)
#                = (a1 + a2) + (C_A ⊙ C_A)
#                = (a1 + a2) + U
#
#     Similarly:
#       B1 ⊙ B2 = (b1 + b2) + V
#
#     Therefore:
#       K = [(a1+a2) + U] ⊙ X ⊙ [(b1+b2) + V]
#         = (a1 + a2 + b1 + b2) + (U ⊙ X ⊙ V)
#         = (a1 + a2 + b1 + b2) + W
#
# === Online Phase (per intercepted session) ===
#
# 6.  Read Ka(0,0) and Kb(0,0) from the intercepted messages.
#
# 7.  s = Ka(0,0) - M(0,0)          → s = a1 + b1
# 8.  t = Kb(0,0) - M(0,0)          → t = a2 + b2
#
# 9.  K = (s + t) + W               (add scalar s+t to every entry of W)
#       = (a1 + b1 + a2 + b2) + W   ✓
#
# 10. return K
# ──────────────────────────────────────────────────────────────────


def structural_collapse_attack(params, X, Ka, Kb):
    """
    Execute the structural collapse attack.

    Args:
        params: dict with keys 'm', 'alpha', 'w', 'v', 'c'
        X:  public matrix (m×m numpy array)
        Ka: intercepted public message from Device 1
        Kb: intercepted public message from Device 2

    Returns:
        K:  the recovered shared session key (m×m numpy array)
    """
    m = params["m"]
    alpha = params["alpha"]
    w = params["w"]
    v = params["v"]
    c = params["c"]

    print("[*] ═══ PRECOMPUTATION PHASE ═══")

    # Step 1: Build constant matrices
    C_A = build_constant_matrix(alpha, v, w, m)
    C_B = build_constant_matrix(alpha, c, w, m)
    print(f"[+] Built C_A (constant matrix for family A_v, p1=0)")
    print(f"[+] Built C_B (constant matrix for family B_c, p1=0)")

    # Step 2: M = C_A ⊙ X ⊙ C_B
    M = trop_mat_mul(trop_mat_mul(C_A, X), C_B)
    print(f"[+] Computed M = C_A ⊙ X ⊙ C_B")
    print(f"    M[0,0] = {M[0,0]}")

    # Step 3: U = C_A ⊙ C_A
    U = trop_mat_mul(C_A, C_A)
    print(f"[+] Computed U = C_A ⊙ C_A")

    # Step 4: V = C_B ⊙ C_B
    V = trop_mat_mul(C_B, C_B)
    print(f"[+] Computed V = C_B ⊙ C_B")

    # Step 5: W = U ⊙ X ⊙ V
    W = trop_mat_mul(trop_mat_mul(U, X), V)
    print(f"[+] Computed W = U ⊙ X ⊙ V")

    print()
    print("[*] ═══ ONLINE PHASE ═══")

    # Step 6: Extract Ka(0,0) and Kb(0,0)
    ka_00 = Ka[0][0]
    kb_00 = Kb[0][0]
    print(f"[+] Ka[0,0] = {ka_00}")
    print(f"[+] Kb[0,0] = {kb_00}")

    # Step 7: s = Ka(0,0) - M(0,0)    → s = a1 + b1
    s = ka_00 - M[0, 0]
    print(f"[+] s = Ka[0,0] - M[0,0] = {s}  (= a1 + b1)")

    # Step 8: t = Kb(0,0) - M(0,0)    → t = a2 + b2
    t = kb_00 - M[0, 0]
    print(f"[+] t = Kb[0,0] - M[0,0] = {t}  (= a2 + b2)")

    # Step 9: K = (s + t) + W
    scalar = s + t
    K = W + scalar  # numpy broadcasts scalar addition
    print(f"[+] Recovered session key K = (s + t) + W")
    print(f"    scalar shift = {scalar}")

    return K


def main():
    # ── Load intercepted data ──
    with open("output.txt", "r") as f:
        data = json.load(f)

    params = data["public_params"]
    X = np.array(data["public_matrix_X"], dtype=float)
    Ka = np.array(data["intercepted"]["Ka"], dtype=float)
    Kb = np.array(data["intercepted"]["Kb"], dtype=float)

    iv = bytes.fromhex(data["encrypted_flag"]["iv"])
    ct = bytes.fromhex(data["encrypted_flag"]["ciphertext"])

    print("╔══════════════════════════════════════════════════════════════╗")
    print("║  Structural Collapse Attack on TROPIKOS™ DuoCirculant KE    ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║  Matrix dimension:  m = {params['m']}")
    print(f"║  Public parameters: α = {params['alpha']}, w = {params['w']}, "
          f"v = {params['v']}, c = {params['c']}")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()

    # ── Execute the attack ──
    K = structural_collapse_attack(params, X, Ka, Kb)

    print()
    print("[*] ═══ DECRYPTION ═══")

    # ── Derive AES key from recovered session key ──
    key_material = ",".join(str(int(x)) for x in K.flatten())
    aes_key = hashlib.sha256(key_material.encode()).digest()
    print(f"[+] Derived AES key: {aes_key.hex()}")

    # ── Decrypt the flag ──
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    try:
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        flag = pt.decode()
        print(f"[+] ✓ Decryption successful!")
        print()
        print(f"    ╔{'═' * (len(flag) + 4)}╗")
        print(f"    ║  {flag}  ║")
        print(f"    ╚{'═' * (len(flag) + 4)}╝")
    except Exception as e:
        print(f"[-] ✗ Decryption failed: {e}")
        print("    The recovered key does not match. Check the attack implementation.")


if __name__ == "__main__":
    main()
>>>>>>> bd185c3 (more stuff)
