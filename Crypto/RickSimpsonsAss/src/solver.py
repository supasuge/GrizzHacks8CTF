#!/usr/bin/env python3
"""
Robust solver library + CLI for the known-high-bits factor attack.

This file can:
- solve one instance from JSON input
- be imported by benchmark_solver.py

Key improvements over naive implementations:
- scans ALL reduced basis rows
- validates roots by direct divisibility of N
- supports wider (m, t) search
- optional BKZ pass if available
"""

from __future__ import annotations

import json
import math
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from Crypto.Util.number import inverse, long_to_bytes
from fpylll import IntegerMatrix, LLL
from sympy import Poly, symbols, ZZ, factor_list

try:
    from fpylll import BKZ
    HAVE_BKZ = True
except Exception:
    HAVE_BKZ = False

x_sym = symbols("x")
LN2 = math.log(2.0)


# ------------------ polynomial helpers ------------------

def poly_trim(a: List[int]) -> List[int]:
    a = a[:]
    while a and a[-1] == 0:
        a.pop()
    return a

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

def row_to_unscaled_poly(row: List[int], X: int) -> List[int]:
    out = []
    powX = 1
    for coeff in row:
        out.append(coeff // powX)
        powX *= X
    return poly_trim(out)


# ------------------ integer roots ------------------

def integer_roots_from_poly(poly_coeffs: List[int]) -> Set[int]:
    if not poly_coeffs:
        return set()

    try:
        P = Poly(sum(c * x_sym**i for i, c in enumerate(poly_coeffs)), x_sym, domain=ZZ)
        facs = factor_list(P)[1]
    except Exception:
        return set()

    roots = set()
    for fac, _mult in facs:
        if fac.degree() == 1:
            a, b = fac.all_coeffs()
            if a != 0 and b % a == 0:
                roots.add(int(-(b // a)))
    return roots


# ------------------ lattice construction ------------------

def build_lattice(pol: List[int], N: int, m: int, t: int, X: int) -> IntegerMatrix:
    d = len(pol) - 1
    if d < 1:
        raise ValueError("Polynomial degree must be >= 1")
    if pol[-1] != 1:
        raise ValueError("Polynomial must be monic")

    n = d * m + t
    f_X = poly_substitute_x_to_xX(pol, X)

    f_X_pows = [[1]]
    for _ in range(1, m + 1):
        f_X_pows.append(poly_mul(f_X_pows[-1], f_X))

    rows = []

    # Block 1
    for i in range(m):
        Ni = pow(N, m - i)
        base = poly_scale_const(f_X_pows[i], Ni)
        for j in range(d):
            mon = [0] * j + [pow(X, j)]
            gij = poly_mul(base, mon)
            rows.append(gij)

    # Block 2
    base_m = f_X_pows[m]
    for j in range(t):
        mon = [0] * j + [pow(X, j)]
        gij = poly_mul(base_m, mon)
        rows.append(gij)

    if len(rows) != n:
        raise RuntimeError(f"Expected {n} rows, got {len(rows)}")

    B = IntegerMatrix(n, n)
    for i in range(n):
        row = rows[i]
        for k, ck in enumerate(row):
            if k < n:
                B[i, k] = int(ck)

    return B


def recover_roots_from_reduced_basis(B: IntegerMatrix, X: int) -> Set[int]:
    roots = set()
    for i in range(B.nrows):
        row = [int(B[i, j]) for j in range(B.ncols)]
        poly_coeffs = row_to_unscaled_poly(row, X)
        if not poly_coeffs:
            continue
        roots |= integer_roots_from_poly(poly_coeffs)
    return roots


# ------------------ attack core ------------------

def try_attack_known_high_bits(
    N: int,
    q_bar: int,
    unknown_bits: int,
    m: int,
    t: int,
    use_bkz: bool = False,
    bkz_block_size: int = 20,
) -> Optional[Tuple[int, int, Dict]]:
    """
    Returns:
        (p, q, debug_info) on success
        None on failure
    """
    X = 1 << unknown_bits
    f = [q_bar, 1]  # f(x) = q_bar + x
    n = m + t  # degree 1 => d*m+t = m+t

    B = build_lattice(f, N, m, t, X)

    LLL.reduction(B)

    if use_bkz and HAVE_BKZ:
        par = BKZ.Param(block_size=bkz_block_size)
        BKZ.reduction(B, par)

    roots = recover_roots_from_reduced_basis(B, X)

    for r in sorted(roots):
        if not (0 <= r < X):
            continue
        q = q_bar + r
        if q > 1 and N % q == 0:
            p = N // q
            return p, q, {
                "m": m,
                "t": t,
                "n": n,
                "use_bkz": use_bkz,
                "bkz_block_size": bkz_block_size,
                "candidate_root": r,
                "num_candidate_roots": len(roots),
            }

    return None


def solve_instance(
    inst: Dict,
    m_range: Tuple[int, int] = (2, 14),
    t_range: Tuple[int, int] = (1, 14),
    try_bkz: bool = True,
    bkz_block_sizes: Tuple[int, ...] = (20,),
) -> Dict:
    """
    Solve a single challenge instance and return detailed stats.
    """
    N = int(inst["n"])
    e = int(inst["e"])
    c = int(inst["c"])
    q_prefix = int(inst["q_prefix"])
    unknown_bits = int(inst["unknown_bits"])

    q_bar = q_prefix << unknown_bits

    start = time.perf_counter()

    attempts = 0
    success = False
    recovered_plaintext = None
    p = None
    q = None
    chosen = None

    for m in range(m_range[0], m_range[1] + 1):
        for t in range(t_range[0], t_range[1] + 1):
            attempts += 1
            result = try_attack_known_high_bits(
                N=N,
                q_bar=q_bar,
                unknown_bits=unknown_bits,
                m=m,
                t=t,
                use_bkz=False,
            )
            if result is not None:
                p, q, chosen = result
                success = True
                break
        if success:
            break

    if not success and try_bkz and HAVE_BKZ:
        for block_size in bkz_block_sizes:
            for m in range(max(3, m_range[0]), m_range[1] + 1):
                for t in range(max(2, t_range[0]), t_range[1] + 1):
                    attempts += 1
                    result = try_attack_known_high_bits(
                        N=N,
                        q_bar=q_bar,
                        unknown_bits=unknown_bits,
                        m=m,
                        t=t,
                        use_bkz=True,
                        bkz_block_size=block_size,
                    )
                    if result is not None:
                        p, q, chosen = result
                        success = True
                        break
                if success:
                    break
            if success:
                break

    elapsed = time.perf_counter() - start

    plaintext_ok = False
    factors_ok = False

    if success and p is not None and q is not None:
        phi = (p - 1) * (q - 1)
        d_priv = inverse(e, phi)
        m_plain = pow(c, d_priv, N)
        msg = long_to_bytes(m_plain)

        try:
            recovered_plaintext = msg.decode()
        except UnicodeDecodeError:
            recovered_plaintext = msg.hex()

        priv = inst.get("_private", {})
        expected_plaintext = priv.get("plaintext")
        expected_p = priv.get("p")
        expected_q = priv.get("q")

        plaintext_ok = (expected_plaintext == recovered_plaintext)
        factors_ok = (
            expected_p is not None
            and expected_q is not None
            and {str(p), str(q)} == {expected_p, expected_q}
        )

    return {
        "instance_id": inst.get("instance_id"),
        "success": success,
        "solve_time_sec": elapsed,
        "attempts": attempts,
        "factors_ok": factors_ok,
        "plaintext_ok": plaintext_ok,
        "chosen_params": chosen,
        "recovered_plaintext": recovered_plaintext,
        "n_bits": N.bit_length(),
        "unknown_bits": unknown_bits,
        "q_prefix_bits": q_prefix.bit_length(),
    }


# ------------------ CLI ------------------

def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Solve one known-high-bits RSA instance.")
    ap.add_argument("challenge_json", type=Path, help="Path to single-instance JSON file.")
    args = ap.parse_args()

    inst = json.loads(args.challenge_json.read_text(encoding="utf-8"))
    result = solve_instance(inst)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
