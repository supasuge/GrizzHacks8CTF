#!/usr/bin/env python3
"""
Ashes of the Mint - intended solver

Solves a 2048-bit RSA challenge where the high bits of q are known.

Attack idea:
    We know:
        q = q_bar + x
    where:
        q_bar = q_prefix << unknown_bits
        0 <= x < X = 2^unknown_bits

    Define:
        f(x) = q_bar + x

    At the correct root x0:
        f(x0) = q
    and q divides N, so:
        f(x0) ≡ 0 mod q

    Since q is a large divisor of N and x0 is small, we can use the
    univariate Coppersmith / Howgrave-Graham method to recover x0.

Dependencies:
    pip install fpylll sympy pycryptodome
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import List

from Crypto.Util.number import GCD, inverse, long_to_bytes
from fpylll import IntegerMatrix, LLL as fpyLLL
from sympy import Poly, symbols, ZZ, factor_list

x_sym = symbols("x")
LN2 = math.log(2.0)

CHALLENGE_FILE = Path("challenge.json")
DEBUG = True

# ------------------ integer polynomial helpers ------------------
# coefficient list, low -> high

def poly_trim(a: List[int]) -> List[int]:
    a = a[:]
    while a and a[-1] == 0:
        a.pop()
    return a

def poly_sub(a: List[int], b: List[int]) -> List[int]:
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        out[i] = (a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0)
    return poly_trim(out)

def poly_mul(a: List[int], b: List[int]) -> List[int]:
    if not a or not b:
        return []
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            if bj == 0:
                continue
            out[i + j] += ai * bj
    return poly_trim(out)

def poly_scale_const(a: List[int], c: int) -> List[int]:
    if c == 0:
        return []
    return poly_trim([ai * c for ai in a])

def poly_substitute_x_to_xX(a: List[int], X: int) -> List[int]:
    out = [0] * len(a)
    powX = 1
    for i, ai in enumerate(a):
        out[i] = ai * powX
        powX *= X
    return poly_trim(out)

def poly_eval_int(a: List[int], x: int) -> int:
    acc = 0
    powx = 1
    for ai in a:
        if ai:
            acc += ai * powx
        powx *= x
    return acc

# ------------------ safe logs ------------------

def log2_int(n: int) -> float:
    if n <= 0:
        raise ValueError("log2_int requires n > 0")
    k = n.bit_length()
    if k <= 53:
        return math.log2(float(n))
    shift = k - 53
    m = n >> shift
    return math.log2(float(m)) + shift

def ln_int(n: int) -> float:
    return log2_int(n) * LN2

def log_pow_lt(base1: int, exp1: float, base2: int, exp2: float) -> bool:
    return exp1 * ln_int(base1) < exp2 * ln_int(base2)

# ------------------ attack core ------------------

def coppersmith_howgrave_univariate(pol: List[int], N: int, beta: float, m: int, t: int, X: int) -> List[int]:
    """
    pol: monic integer polynomial, coef list low->high
    N: modulus
    beta: target large-factor exponent; for factoring with q ~ N^1/2 use beta ~ 1/2
    m,t: lattice parameters
    X: root bound

    returns integer roots r with |r| < X such that gcd(N, f(r)) >= N^beta
    """
    d = len(pol) - 1
    assert d >= 1
    assert pol[-1] == 1  # monic

    n = d * m + t

    if DEBUG:
        print(f"[*] polynomial degree d={d}")
        print(f"[*] lattice params: m={m}, t={t}, n={n}")
        print(f"[*] root bound X=2^{X.bit_length()-1}")

        ok1 = log_pow_lt(X, n - 1, N, beta * m)
        print(f"[*] X^(n-1) < N^(beta*m) ? {ok1}")

        ln_detL = (d * m * (m + 1) / 2.0) * ln_int(N) + (n * (n - 1) / 2.0) * ln_int(X)
        ln_lhs = ((n - 1) / 4.0) * LN2 + (1.0 / n) * ln_detL
        ln_rhs = (beta * m) * ln_int(N) - 0.5 * math.log(n)
        print(f"[*] HG determinant heuristic satisfied? {ln_lhs < ln_rhs}")

    f_X = poly_substitute_x_to_xX(pol, X)

    f_X_pows = [[1]]
    for _ in range(1, m + 1):
        f_X_pows.append(poly_mul(f_X_pows[-1], f_X))

    rows = []

    # Block 1: (xX)^j * N^(m-i) * f(xX)^i
    for i in range(m):
        Ni = pow(N, m - i)
        base = poly_scale_const(f_X_pows[i], Ni)
        for j in range(d):
            mon = [0] * j + [pow(X, j)]
            gij = poly_mul(base, mon)
            rows.append(gij)

    # Block 2: (xX)^j * f(xX)^m
    base_m = f_X_pows[m]
    for j in range(t):
        mon = [0] * j + [pow(X, j)]
        gij = poly_mul(base_m, mon)
        rows.append(gij)

    assert len(rows) == n

    B = IntegerMatrix(n, n)
    for i in range(n):
        row = rows[i]
        for k, ck in enumerate(row):
            if k < n:
                B[i, k] = int(ck)

    print("[*] Running LLL...")
    fpyLLL.reduction(B)

    shortest = [int(B[0, j]) for j in range(n)]

    # Undo x -> xX scaling
    new_pol = []
    powX = 1
    for k in range(n):
        coeff = shortest[k]
        new_pol.append(coeff // powX)
        powX *= X
    new_pol = poly_trim(new_pol)

    if DEBUG:
        print(f"[*] Reduced polynomial degree: {len(new_pol)-1}")

    if not new_pol:
        return []

    P = Poly(sum(coef * x_sym**i for i, coef in enumerate(new_pol)), x_sym, domain=ZZ)
    facs = factor_list(P)[1]

    cand_roots = set()
    for fac, _mult in facs:
        if fac.degree() == 1:
            a, b = fac.all_coeffs()
            if b % a == 0:
                r = -(b // a)
                cand_roots.add(int(r))

    roots = []
    threshold = math.exp(beta * ln_int(N))

    for r in cand_roots:
        if abs(r) >= X:
            continue
        val = poly_eval_int(pol, r)
        g = GCD(N, val)
        if g >= threshold:
            roots.append(int(r))

    return sorted(set(roots))

# ------------------ main solve path ------------------

def main() -> None:
    chal = json.loads(CHALLENGE_FILE.read_text(encoding="utf-8"))

    N = int(chal["n"])
    e = int(chal["e"])
    c = int(chal["c"])
    unknown_bits = int(chal["unknown_bits"])
    q_prefix = int(chal["q_prefix"])

    X = 1 << unknown_bits
    q_bar = q_prefix << unknown_bits

    print("[*] Loaded challenge")
    print(f"    N bits         : {N.bit_length()}")
    print(f"    unknown bits   : {unknown_bits}")
    print(f"    q_prefix bits  : {q_prefix.bit_length()}")
    print()

    # f(x) = q_bar + x
    # coef low->high: [q_bar, 1]
    f = [q_bar, 1]

    # For factor recovery, the relevant divisor q is about N^(1/2), so beta = 1/2.
    beta = 0.5

    # Standard heuristic seed parameters.
    # For degree d=1:
    #   eps = beta / 7
    #   m = ceil(beta^2 / (d*eps))
    #   t = floor(d*m*(1/beta - 1))
    d = 1
    eps = beta / 7.0
    m = math.ceil(beta * beta / (d * eps))
    t = math.floor(d * m * ((1.0 / beta) - 1.0))

    print(f"[*] Starting with heuristic params m={m}, t={t}")
    roots = coppersmith_howgrave_univariate(f, N, beta, m, t, X)

    # If not found, do a local search around the heuristic.
    if not roots:
        print("[!] No root found with seed parameters; trying local neighborhood...")
        found = False
        for mm in range(max(1, m - 2), m + 4):
            for tt in range(max(0, t - 3), t + 4):
                print(f"    -> trying m={mm}, t={tt}")
                roots = coppersmith_howgrave_univariate(f, N, beta, mm, tt, X)
                if roots:
                    m, t = mm, tt
                    found = True
                    break
            if found:
                break

    if not roots:
        raise SystemExit("[-] Failed to recover the small root.")

    x = roots[0]
    print(f"[+] Recovered missing tail x = {x}")
    print(f"[+] x bit length = {x.bit_length()}")

    q = q_bar + x
    if N % q != 0:
        raise SystemExit("[-] Candidate q does not divide N.")

    p = N // q
    print(f"[+] Recovered factors:")
    print(f"    p = {p}")
    print(f"    q = {q}")

    phi = (p - 1) * (q - 1)
    d_priv = inverse(e, phi)
    m_plain = pow(c, d_priv, N)
    msg = long_to_bytes(m_plain)

    print()
    print("[+] Decrypted message:")
    try:
        print(msg.decode())
    except UnicodeDecodeError:
        print(msg)
        print("[!] Message was not valid UTF-8; raw bytes shown.")

if __name__ == "__main__":
    main()
