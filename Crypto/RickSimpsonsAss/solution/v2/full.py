#!/usr/bin/env python3
"""
Async benchmark + charting harness for:
- known-high-bits RSA factor recovery via Coppersmith/Howgrave-Graham lattices
- determinant-guided sublattice pruning experiments
- modified Kannan-style embedding experiments
- adaptive BKZ block-size descent

Outputs
-------
benchmark_artifacts/
├── run.log
├── results.json
├── results.jsonl
├── summary.json
├── summary.csv
├── chart_success_rate_by_strategy.png
├── chart_success_rate_by_unknown_bits.png
├── chart_time_boxplot_by_strategy.png
├── chart_time_boxplot_by_unknown_bits.png
├── chart_heatmap_strategy_vs_unknown_bits.png
├── chart_param_usage.png
└── chart_embedding_tau_sweep.png

Dependencies
------------
pip install pycryptodome sympy fpylll matplotlib pandas numpy
"""

from __future__ import annotations

import asyncio
import csv
import json
import logging
import math
import os
import statistics
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from Crypto.Util.number import getPrime, bytes_to_long, inverse, long_to_bytes
from fpylll import IntegerMatrix, LLL
from sympy import Poly, symbols, ZZ, factor_list

try:
    from fpylll import BKZ
    HAVE_BKZ = True
except Exception:
    HAVE_BKZ = False

# ------------------------- config -------------------------

OUTDIR = Path("benchmark_artifacts")
OUTDIR.mkdir(exist_ok=True)

LOG_FILE = OUTDIR / "run.log"
RESULTS_JSON = OUTDIR / "results.json"
RESULTS_JSONL = OUTDIR / "results.jsonl"
SUMMARY_JSON = OUTDIR / "summary.json"
SUMMARY_CSV = OUTDIR / "summary.csv"

RSA_BITS = 2048
PRIME_BITS = RSA_BITS // 2
E = 65537

UNKNOWN_BITS_GRID = [160, 180, 200, 220, 240]
INSTANCES_PER_UNKNOWN_BITS = 12
MAX_WORKERS = max(1, (os.cpu_count() or 4) - 1)

# Experimental strategy families
STRATEGIES = [
    {
        "name": "lll_small",
        "mode": "coppersmith",
        "m_range": (2, 8),
        "t_range": (1, 8),
        "use_bkz": False,
        "bkz_block_sizes": (),
        "sublattice_prune": False,
        "embedding": False,
    },
    {
        "name": "lll_wide",
        "mode": "coppersmith",
        "m_range": (2, 14),
        "t_range": (1, 14),
        "use_bkz": False,
        "bkz_block_sizes": (),
        "sublattice_prune": False,
        "embedding": False,
    },
    {
        "name": "bkz_descend",
        "mode": "coppersmith",
        "m_range": (3, 12),
        "t_range": (2, 12),
        "use_bkz": True,
        "bkz_block_sizes": (28, 24, 20),
        "sublattice_prune": False,
        "embedding": False,
    },
    {
        "name": "det_prune_lll",
        "mode": "coppersmith",
        "m_range": (2, 12),
        "t_range": (1, 12),
        "use_bkz": False,
        "bkz_block_sizes": (),
        "sublattice_prune": True,
        "embedding": False,
    },
    {
        "name": "det_prune_bkz",
        "mode": "coppersmith",
        "m_range": (3, 12),
        "t_range": (2, 12),
        "use_bkz": True,
        "bkz_block_sizes": (24, 20),
        "sublattice_prune": True,
        "embedding": False,
    },
    {
        "name": "embed_tau_sweep",
        "mode": "embedding",
        "m_range": (3, 10),
        "t_range": (2, 10),
        "use_bkz": True,
        "bkz_block_sizes": (24, 20),
        "sublattice_prune": True,
        "embedding": True,
        "tau_multipliers": (0.25, 0.5, 1.0, 2.0, 4.0),
    },
]

MESSAGE_PREFIXES = [
    "the crown survived the fire",
    "the mint remembered the divisor",
    "only the upper carving remained",
    "the tail was charred away",
    "the royal burden divided exactly",
    "the archivist restored the seal",
    "the fragment outlived the flames",
    "the decree slept behind the lock",
    "the sacred divisor lost its feet",
    "the ash concealed the remainder",
]

x_sym = symbols("x")

# ------------------------- logging -------------------------

logger = logging.getLogger("benchmark")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s", "%Y-%m-%d %H:%M:%S")

console = logging.StreamHandler(sys.stdout)
console.setLevel(logging.INFO)
console.setFormatter(formatter)
logger.addHandler(console)

fileh = logging.FileHandler(LOG_FILE, mode="w", encoding="utf-8")
fileh.setLevel(logging.DEBUG)
fileh.setFormatter(formatter)
logger.addHandler(fileh)

# ------------------------- dataclasses -------------------------

@dataclass
class ChallengeInstance:
    instance_id: int
    unknown_bits: int
    n: str
    e: int
    c: str
    q_prefix: str
    prime_bits: int
    plaintext: str
    p: str
    q: str
    q_bar: str
    x: str

@dataclass
class AttemptRecord:
    strategy_name: str
    mode: str
    success: bool
    solve_time_sec: float
    attempts: int
    factors_ok: bool
    plaintext_ok: bool
    chosen_params: Optional[Dict[str, Any]]
    recovered_plaintext: Optional[str]
    error: Optional[str]
    n_bits: int
    unknown_bits: int
    q_prefix_bits: int
    tau_used: Optional[float] = None
    pruned_dimension: Optional[int] = None
    full_dimension: Optional[int] = None

@dataclass
class TaskResult:
    instance_id: int
    unknown_bits: int
    strategy_name: str
    attempt: AttemptRecord

# ------------------------- polynomial helpers -------------------------

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

# ------------------------- instance generation -------------------------

def build_plaintext(i: int, ub: int) -> str:
    prefix = MESSAGE_PREFIXES[i % len(MESSAGE_PREFIXES)].replace(" ", "_")
    return f"GRIZZ{{inst_{i:03d}_ub_{ub}_{prefix}}}"

def gen_instance(instance_id: int, unknown_bits: int) -> ChallengeInstance:
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

        plaintext = build_plaintext(instance_id, unknown_bits)
        m = bytes_to_long(plaintext.encode())
        if m >= n:
            continue

        c = pow(m, E, n)

        q_prefix = q >> unknown_bits
        q_bar = q_prefix << unknown_bits
        x = q - q_bar
        if 0 <= x < (1 << unknown_bits):
            return ChallengeInstance(
                instance_id=instance_id,
                unknown_bits=unknown_bits,
                n=str(n),
                e=E,
                c=str(c),
                q_prefix=str(q_prefix),
                prime_bits=PRIME_BITS,
                plaintext=plaintext,
                p=str(p),
                q=str(q),
                q_bar=str(q_bar),
                x=str(x),
            )

# ------------------------- lattice construction -------------------------

def build_coppersmith_lattice(pol: List[int], N: int, m: int, t: int, X: int) -> IntegerMatrix:
    d = len(pol) - 1
    if d < 1 or pol[-1] != 1:
        raise ValueError("Expected monic polynomial degree >= 1")

    n = d * m + t
    f_X = poly_substitute_x_to_xX(pol, X)

    f_X_pows = [[1]]
    for _ in range(1, m + 1):
        f_X_pows.append(poly_mul(f_X_pows[-1], f_X))

    rows = []

    for i in range(m):
        Ni = pow(N, m - i)
        base = poly_scale_const(f_X_pows[i], Ni)
        for j in range(d):
            mon = [0] * j + [pow(X, j)]
            rows.append(poly_mul(base, mon))

    base_m = f_X_pows[m]
    for j in range(t):
        mon = [0] * j + [pow(X, j)]
        rows.append(poly_mul(base_m, mon))

    B = IntegerMatrix(n, n)
    for i, row in enumerate(rows):
        for j, coeff in enumerate(row[:n]):
            B[i, j] = int(coeff)
    return B

def reduce_lattice(B: IntegerMatrix, use_bkz: bool, bkz_block_size: int) -> IntegerMatrix:
    LLL.reduction(B)
    if use_bkz and HAVE_BKZ:
        par = BKZ.Param(block_size=bkz_block_size)
        BKZ.reduction(B, par)
    return B

def candidate_submatrices_by_determinant(B: IntegerMatrix, max_keep: int = 5) -> List[Tuple[List[int], float]]:
    """
    Experimental determinant-guided pruning:
    rank rows by row norm and evaluate top-k principal-like row subsets.
    This is only a proxy for volume-guided sublattice exploration.
    """
    n = B.nrows
    rows = []
    for i in range(n):
        row = np.array([int(B[i, j]) for j in range(B.ncols)], dtype=object)
        # Euclidean-like score proxy
        score = float(sum(int(x) * int(x) for x in row)) ** 0.5
        rows.append((i, score))
    rows.sort(key=lambda x: x[1])

    subsets = []
    for keep in range(max(3, n // 2), n + 1):
        idxs = [r[0] for r in rows[:keep]]
        # crude determinant proxy using Gram diagonal after selection
        proxy = sum(rows[k][1] for k in range(min(keep, len(rows))))
        subsets.append((idxs, proxy))
    subsets.sort(key=lambda x: x[1])
    return subsets[:max_keep]

def project_submatrix(B: IntegerMatrix, row_indices: List[int]) -> IntegerMatrix:
    dim = len(row_indices)
    P = IntegerMatrix(dim, dim)
    for i, ri in enumerate(row_indices):
        for j, rj in enumerate(row_indices):
            P[i, j] = int(B[ri, rj]) if rj < B.ncols else 0
    return P

def recover_roots_from_reduced_basis(B: IntegerMatrix, X: int) -> Set[int]:
    roots = set()
    for i in range(B.nrows):
        row = [int(B[i, j]) for j in range(B.ncols)]
        poly_coeffs = row_to_unscaled_poly(row, X)
        roots |= integer_roots_from_poly(poly_coeffs)
    return roots

# ------------------------- embedding experiments -------------------------

def build_modified_embedding_lattice(
    B: IntegerMatrix,
    target_row: List[int],
    tau: int,
) -> IntegerMatrix:
    """
    Experimental Kannan-style augmentation:
    [ B   t ]
    [ 0  tau ]

    This is a generic embedding form used in primal/BDD-style settings. Here it is
    used experimentally as an augmentation on a Coppersmith-derived basis, not as a
    theorem-backed replacement for the standard attack.
    """
    n = B.nrows
    EMat = IntegerMatrix(n + 1, n + 1)

    for i in range(n):
        for j in range(n):
            EMat[i, j] = int(B[i, j])
        EMat[i, n] = int(target_row[i] if i < len(target_row) else 0)

    for j in range(n):
        EMat[n, j] = 0
    EMat[n, n] = int(tau)
    return EMat

# ------------------------- solver cores -------------------------

def solve_coppersmith_strategy(instance: ChallengeInstance, strategy: Dict[str, Any]) -> AttemptRecord:
    N = int(instance.n)
    e = int(instance.e)
    c = int(instance.c)
    q_prefix = int(instance.q_prefix)
    unknown_bits = int(instance.unknown_bits)
    q_bar = q_prefix << unknown_bits
    X = 1 << unknown_bits
    f = [q_bar, 1]

    start = time.perf_counter()
    attempts = 0

    try:
        for m in range(strategy["m_range"][0], strategy["m_range"][1] + 1):
            for t in range(strategy["t_range"][0], strategy["t_range"][1] + 1):
                block_sizes = strategy["bkz_block_sizes"] if strategy["use_bkz"] else (20,)

                for blk in block_sizes:
                    attempts += 1
                    B = build_coppersmith_lattice(f, N, m, t, X)
                    full_dim = B.nrows

                    candidate_bases = [(B, None, full_dim)]

                    if strategy["sublattice_prune"]:
                        reduced_preview = IntegerMatrix(B)
                        LLL.reduction(reduced_preview)
                        for idxs, _proxy in candidate_submatrices_by_determinant(reduced_preview, max_keep=4):
                            try:
                                P = project_submatrix(reduced_preview, idxs)
                                candidate_bases.append((P, len(idxs), full_dim))
                            except Exception:
                                pass

                    for basis, pruned_dim, full_dimension in candidate_bases:
                        basis = reduce_lattice(basis, strategy["use_bkz"], blk)
                        roots = recover_roots_from_reduced_basis(basis, X)

                        for r in sorted(roots):
                            if not (0 <= r < X):
                                continue
                            q = q_bar + r
                            if q > 1 and N % q == 0:
                                p = N // q
                                phi = (p - 1) * (q - 1)
                                d_priv = inverse(e, phi)
                                msg = long_to_bytes(pow(c, d_priv, N))
                                try:
                                    recovered_plaintext = msg.decode()
                                except UnicodeDecodeError:
                                    recovered_plaintext = msg.hex()

                                return AttemptRecord(
                                    strategy_name=strategy["name"],
                                    mode=strategy["mode"],
                                    success=True,
                                    solve_time_sec=time.perf_counter() - start,
                                    attempts=attempts,
                                    factors_ok={str(p), str(q)} == {instance.p, instance.q},
                                    plaintext_ok=recovered_plaintext == instance.plaintext,
                                    chosen_params={
                                        "m": m,
                                        "t": t,
                                        "use_bkz": strategy["use_bkz"],
                                        "bkz_block_size": blk,
                                        "candidate_root": r,
                                        "num_candidate_roots": len(roots),
                                    },
                                    recovered_plaintext=recovered_plaintext,
                                    error=None,
                                    n_bits=N.bit_length(),
                                    unknown_bits=unknown_bits,
                                    q_prefix_bits=q_prefix.bit_length(),
                                    tau_used=None,
                                    pruned_dimension=pruned_dim,
                                    full_dimension=full_dimension,
                                )

        return AttemptRecord(
            strategy_name=strategy["name"],
            mode=strategy["mode"],
            success=False,
            solve_time_sec=time.perf_counter() - start,
            attempts=attempts,
            factors_ok=False,
            plaintext_ok=False,
            chosen_params=None,
            recovered_plaintext=None,
            error=None,
            n_bits=N.bit_length(),
            unknown_bits=unknown_bits,
            q_prefix_bits=q_prefix.bit_length(),
        )
    except Exception as exc:
        return AttemptRecord(
            strategy_name=strategy["name"],
            mode=strategy["mode"],
            success=False,
            solve_time_sec=time.perf_counter() - start,
            attempts=attempts,
            factors_ok=False,
            plaintext_ok=False,
            chosen_params=None,
            recovered_plaintext=None,
            error=f"{type(exc).__name__}: {exc}",
            n_bits=N.bit_length(),
            unknown_bits=unknown_bits,
            q_prefix_bits=q_prefix.bit_length(),
        )

def solve_embedding_strategy(instance: ChallengeInstance, strategy: Dict[str, Any]) -> AttemptRecord:
    """
    Experimental hybrid:
    - build Coppersmith basis
    - optionally prune
    - add Kannan-style embedding with tau sweep
    - reduce with LLL/BKZ descent
    - still validate by divisibility of N
    """
    N = int(instance.n)
    e = int(instance.e)
    c = int(instance.c)
    q_prefix = int(instance.q_prefix)
    unknown_bits = int(instance.unknown_bits)
    q_bar = q_prefix << unknown_bits
    X = 1 << unknown_bits
    f = [q_bar, 1]

    start = time.perf_counter()
    attempts = 0

    try:
        for m in range(strategy["m_range"][0], strategy["m_range"][1] + 1):
            for t in range(strategy["t_range"][0], strategy["t_range"][1] + 1):
                base = build_coppersmith_lattice(f, N, m, t, X)
                full_dim = base.nrows

                candidate_bases = [(base, None, full_dim)]
                if strategy["sublattice_prune"]:
                    preview = IntegerMatrix(base)
                    LLL.reduction(preview)
                    for idxs, _proxy in candidate_submatrices_by_determinant(preview, max_keep=4):
                        try:
                            P = project_submatrix(preview, idxs)
                            candidate_bases.append((P, len(idxs), full_dim))
                        except Exception:
                            pass

                for basis, pruned_dim, full_dimension in candidate_bases:
                    n = basis.nrows
                    target = [int(q_bar)] + [0] * (n - 1)
                    heur_tau = max(1, int((X / max(1, n)) ** 0.5))

                    for tau_mult in strategy["tau_multipliers"]:
                        tau = max(1, int(heur_tau * tau_mult))

                        EMat = build_modified_embedding_lattice(basis, target, tau)

                        for blk in strategy["bkz_block_sizes"]:
                            attempts += 1
                            R = IntegerMatrix(EMat)
                            reduce_lattice(R, True, blk)

                            # Recover roots from first n rows/cols projection
                            P = IntegerMatrix(n, n)
                            for i in range(n):
                                for j in range(n):
                                    P[i, j] = int(R[i, j])

                            roots = recover_roots_from_reduced_basis(P, X)
                            for r in sorted(roots):
                                if not (0 <= r < X):
                                    continue
                                q = q_bar + r
                                if q > 1 and N % q == 0:
                                    p = N // q
                                    phi = (p - 1) * (q - 1)
                                    d_priv = inverse(e, phi)
                                    msg = long_to_bytes(pow(c, d_priv, N))
                                    try:
                                        recovered_plaintext = msg.decode()
                                    except UnicodeDecodeError:
                                        recovered_plaintext = msg.hex()

                                    return AttemptRecord(
                                        strategy_name=strategy["name"],
                                        mode=strategy["mode"],
                                        success=True,
                                        solve_time_sec=time.perf_counter() - start,
                                        attempts=attempts,
                                        factors_ok={str(p), str(q)} == {instance.p, instance.q},
                                        plaintext_ok=recovered_plaintext == instance.plaintext,
                                        chosen_params={
                                            "m": m,
                                            "t": t,
                                            "use_bkz": True,
                                            "bkz_block_size": blk,
                                            "candidate_root": r,
                                            "num_candidate_roots": len(roots),
                                        },
                                        recovered_plaintext=recovered_plaintext,
                                        error=None,
                                        n_bits=N.bit_length(),
                                        unknown_bits=unknown_bits,
                                        q_prefix_bits=q_prefix.bit_length(),
                                        tau_used=tau_mult,
                                        pruned_dimension=pruned_dim,
                                        full_dimension=full_dimension,
                                    )

        return AttemptRecord(
            strategy_name=strategy["name"],
            mode=strategy["mode"],
            success=False,
            solve_time_sec=time.perf_counter() - start,
            attempts=attempts,
            factors_ok=False,
            plaintext_ok=False,
            chosen_params=None,
            recovered_plaintext=None,
            error=None,
            n_bits=N.bit_length(),
            unknown_bits=unknown_bits,
            q_prefix_bits=q_prefix.bit_length(),
        )
    except Exception as exc:
        return AttemptRecord(
            strategy_name=strategy["name"],
            mode=strategy["mode"],
            success=False,
            solve_time_sec=time.perf_counter() - start,
            attempts=attempts,
            factors_ok=False,
            plaintext_ok=False,
            chosen_params=None,
            recovered_plaintext=None,
            error=f"{type(exc).__name__}: {exc}",
            n_bits=N.bit_length(),
            unknown_bits=unknown_bits,
            q_prefix_bits=q_prefix.bit_length(),
        )

# ------------------------- worker wrapper -------------------------

def worker_run(task: Tuple[Dict[str, Any], Dict[str, Any]]) -> Dict[str, Any]:
    inst_dict, strategy = task
    instance = ChallengeInstance(**inst_dict)

    if strategy["mode"] == "embedding":
        attempt = solve_embedding_strategy(instance, strategy)
    else:
        attempt = solve_coppersmith_strategy(instance, strategy)

    result = TaskResult(
        instance_id=instance.instance_id,
        unknown_bits=instance.unknown_bits,
        strategy_name=strategy["name"],
        attempt=attempt,
    )
    return asdict(result)

# ------------------------- orchestration -------------------------

async def live_status(total_tasks: int, shared_state: Dict[str, int], interval: float = 2.0) -> None:
    while shared_state["completed"] < total_tasks:
        c = shared_state["completed"]
        s = shared_state["successes"]
        logger.info(f"[status] completed={c}/{total_tasks} ({100*c/total_tasks:.1f}%) successes={s} failures={c-s}")
        await asyncio.sleep(interval)

async def run_all_tasks(instances: List[ChallengeInstance], strategies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    loop = asyncio.get_running_loop()
    shared_state = {"completed": 0, "successes": 0}

    tasks = []
    for inst in instances:
        for strategy in strategies:
            tasks.append((asdict(inst), strategy))

    status_task = asyncio.create_task(live_status(len(tasks), shared_state))
    results = []

    with ProcessPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [loop.run_in_executor(pool, worker_run, task) for task in tasks]
        for fut in asyncio.as_completed(futures):
            result = await fut
            results.append(result)
            shared_state["completed"] += 1
            if result["attempt"]["success"]:
                shared_state["successes"] += 1

            rec = result["attempt"]
            logger.info(
                f"[done] inst={result['instance_id']:03d} ub={result['unknown_bits']} "
                f"strategy={result['strategy_name']} success={rec['success']} "
                f"time={rec['solve_time_sec']:.3f}s attempts={rec['attempts']} "
                f"tau={rec.get('tau_used')} pruned_dim={rec.get('pruned_dimension')} "
                f"params={rec['chosen_params']}"
            )

    await status_task
    return results

# ------------------------- reporting helpers -------------------------

def percentile(sorted_values: List[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    k = (len(sorted_values) - 1) * p
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_values[int(k)]
    return sorted_values[f] * (c - k) + sorted_values[c] * (k - f)

def summarize(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    df = pd.json_normalize(results)

    def block(sub: pd.DataFrame) -> Dict[str, Any]:
        times = sorted(sub["attempt.solve_time_sec"].tolist()) if not sub.empty else []
        n = int(len(sub))
        succ = int(sub["attempt.success"].sum()) if n else 0
        p_ok = int(sub["attempt.plaintext_ok"].sum()) if n else 0
        f_ok = int(sub["attempt.factors_ok"].sum()) if n else 0
        return {
            "count": n,
            "success_count": succ,
            "failure_count": n - succ,
            "success_rate": succ / n if n else 0.0,
            "plaintext_ok_rate": p_ok / n if n else 0.0,
            "factors_ok_rate": f_ok / n if n else 0.0,
            "timing": {
                "mean": float(np.mean(times)) if times else 0.0,
                "median": float(np.median(times)) if times else 0.0,
                "min": float(min(times)) if times else 0.0,
                "max": float(max(times)) if times else 0.0,
                "p90": percentile(times, 0.90) if times else 0.0,
                "p95": percentile(times, 0.95) if times else 0.0,
                "p99": percentile(times, 0.99) if times else 0.0,
            },
        }

    by_strategy = {name: block(g) for name, g in df.groupby("strategy_name")}
    by_unknown_bits = {str(name): block(g) for name, g in df.groupby("unknown_bits")}

    param_counter = Counter()
    for r in results:
        cp = r["attempt"]["chosen_params"]
        if cp:
            param_counter[(
                r["strategy_name"],
                cp.get("m"),
                cp.get("t"),
                cp.get("use_bkz"),
                cp.get("bkz_block_size"),
                r["attempt"].get("tau_used"),
            )] += 1

    summary = {
        "meta": {
            "rsa_bits": RSA_BITS,
            "prime_bits": PRIME_BITS,
            "e": E,
            "have_bkz": HAVE_BKZ,
            "max_workers": MAX_WORKERS,
            "unknown_bits_grid": UNKNOWN_BITS_GRID,
            "instances_per_unknown_bits": INSTANCES_PER_UNKNOWN_BITS,
            "total_instances": len({r["instance_id"] for r in results}),
            "total_strategy_runs": len(results),
        },
        "overall": block(df),
        "by_strategy": by_strategy,
        "by_unknown_bits": by_unknown_bits,
        "parameter_usage": [
            {
                "strategy_name": k[0],
                "m": k[1],
                "t": k[2],
                "use_bkz": k[3],
                "bkz_block_size": k[4],
                "tau_used": k[5],
                "count": v,
            }
            for k, v in param_counter.most_common()
        ],
    }
    return summary

def write_outputs(results: List[Dict[str, Any]], summary: Dict[str, Any]) -> None:
    RESULTS_JSON.write_text(json.dumps(results, indent=2), encoding="utf-8")
    with RESULTS_JSONL.open("w", encoding="utf-8") as fh:
        for r in results:
            fh.write(json.dumps(r) + "\n")
    SUMMARY_JSON.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    with SUMMARY_CSV.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow([
            "section", "name", "count", "success_count", "failure_count",
            "success_rate", "plaintext_ok_rate", "factors_ok_rate",
            "mean_time", "median_time", "p95_time", "max_time"
        ])

        def emit(section: str, name: str, blk: Dict[str, Any]) -> None:
            w.writerow([
                section, name, blk["count"], blk["success_count"], blk["failure_count"],
                blk["success_rate"], blk["plaintext_ok_rate"], blk["factors_ok_rate"],
                blk["timing"]["mean"], blk["timing"]["median"], blk["timing"]["p95"], blk["timing"]["max"],
            ])

        emit("overall", "overall", summary["overall"])
        for name, blk in summary["by_strategy"].items():
            emit("by_strategy", name, blk)
        for name, blk in summary["by_unknown_bits"].items():
            emit("by_unknown_bits", name, blk)

# ------------------------- charting -------------------------

def save_chart(fig: plt.Figure, path: Path) -> None:
    fig.tight_layout()
    fig.savefig(path, dpi=180, bbox_inches="tight")
    plt.close(fig)

def generate_charts(results: List[Dict[str, Any]]) -> None:
    df = pd.json_normalize(results)

    # 1) success rate by strategy
    success_by_strategy = df.groupby("strategy_name")["attempt.success"].mean().sort_values(ascending=False)
    fig, ax = plt.subplots(figsize=(10, 5))
    success_by_strategy.plot(kind="bar", ax=ax)
    ax.set_title("Success Rate by Strategy")
    ax.set_ylabel("Success Rate")
    ax.set_xlabel("Strategy")
    ax.set_ylim(0, 1.0)
    save_chart(fig, OUTDIR / "chart_success_rate_by_strategy.png")

    # 2) success rate by unknown bits
    success_by_ub = df.groupby("unknown_bits")["attempt.success"].mean().sort_index()
    fig, ax = plt.subplots(figsize=(8, 5))
    success_by_ub.plot(marker="o", ax=ax)
    ax.set_title("Success Rate by Unknown Bits")
    ax.set_ylabel("Success Rate")
    ax.set_xlabel("Unknown Bits")
    ax.set_ylim(0, 1.0)
    save_chart(fig, OUTDIR / "chart_success_rate_by_unknown_bits.png")

    # 3) time boxplot by strategy
    fig, ax = plt.subplots(figsize=(11, 6))
    df.boxplot(column="attempt.solve_time_sec", by="strategy_name", ax=ax, rot=30)
    ax.set_title("Solve Time Distribution by Strategy")
    ax.set_ylabel("Time (s)")
    ax.set_xlabel("Strategy")
    fig.suptitle("")
    save_chart(fig, OUTDIR / "chart_time_boxplot_by_strategy.png")

    # 4) time boxplot by unknown bits
    fig, ax = plt.subplots(figsize=(10, 6))
    df.boxplot(column="attempt.solve_time_sec", by="unknown_bits", ax=ax)
    ax.set_title("Solve Time Distribution by Unknown Bits")
    ax.set_ylabel("Time (s)")
    ax.set_xlabel("Unknown Bits")
    fig.suptitle("")
    save_chart(fig, OUTDIR / "chart_time_boxplot_by_unknown_bits.png")

    # 5) strategy vs unknown bits heatmap
    pivot = df.pivot_table(
        index="strategy_name",
        columns="unknown_bits",
        values="attempt.success",
        aggfunc="mean",
        fill_value=0.0,
    )
    fig, ax = plt.subplots(figsize=(10, 6))
    im = ax.imshow(pivot.values, aspect="auto")
    ax.set_xticks(range(len(pivot.columns)))
    ax.set_xticklabels(pivot.columns)
    ax.set_yticks(range(len(pivot.index)))
    ax.set_yticklabels(pivot.index)
    ax.set_title("Success-Rate Heatmap: Strategy vs Unknown Bits")
    ax.set_xlabel("Unknown Bits")
    ax.set_ylabel("Strategy")
    fig.colorbar(im, ax=ax)
    save_chart(fig, OUTDIR / "chart_heatmap_strategy_vs_unknown_bits.png")

    # 6) parameter usage
    param_rows = []
    for _, row in df.iterrows():
        cp = row.get("attempt.chosen_params")
        if isinstance(cp, dict):
            param_rows.append({
                "strategy": row["strategy_name"],
                "m": cp.get("m"),
                "t": cp.get("t"),
                "count": 1,
            })
    if param_rows:
        pdf = pd.DataFrame(param_rows)
        agg = pdf.groupby(["strategy", "m", "t"]).size().reset_index(name="count")
        agg["label"] = agg["strategy"] + ":(" + agg["m"].astype(str) + "," + agg["t"].astype(str) + ")"
        agg = agg.sort_values("count", ascending=False).head(20)
        fig, ax = plt.subplots(figsize=(12, 7))
        ax.barh(agg["label"], agg["count"])
        ax.set_title("Top Chosen (m,t) Parameter Pairs")
        ax.set_xlabel("Count")
        ax.invert_yaxis()
        save_chart(fig, OUTDIR / "chart_param_usage.png")

    # 7) tau sweep chart for embedding
    tau_df = df[df["attempt.tau_used"].notna()].copy()
    if not tau_df.empty:
        tau_success = tau_df.groupby("attempt.tau_used")["attempt.success"].mean().sort_index()
        fig, ax = plt.subplots(figsize=(8, 5))
        tau_success.plot(marker="o", ax=ax)
        ax.set_title("Embedding Tau Multiplier Sweep")
        ax.set_xlabel("Tau Multiplier")
        ax.set_ylabel("Success Rate")
        ax.set_ylim(0, 1.0)
        save_chart(fig, OUTDIR / "chart_embedding_tau_sweep.png")

# ------------------------- main -------------------------

async def main() -> None:
    t0 = time.perf_counter()
    logger.info("Starting benchmark")
    logger.info(f"BKZ available: {HAVE_BKZ}")
    logger.info(f"Workers: {MAX_WORKERS}")
    logger.info(f"Unknown bits grid: {UNKNOWN_BITS_GRID}")
    logger.info(f"Instances per unknown_bits: {INSTANCES_PER_UNKNOWN_BITS}")

    instances = []
    iid = 0
    logger.info("Generating instances...")
    for ub in UNKNOWN_BITS_GRID:
        for _ in range(INSTANCES_PER_UNKNOWN_BITS):
            inst = gen_instance(iid, ub)
            instances.append(inst)
            logger.debug(
                f"[gen] inst={iid:03d} ub={ub} N_bits={int(inst.n).bit_length()} "
                f"q_prefix_bits={int(inst.q_prefix).bit_length()} x_bits={int(inst.x).bit_length()}"
            )
            iid += 1

    logger.info(f"Generated {len(instances)} instances")
    results = await run_all_tasks(instances, STRATEGIES)

    summary = summarize(results)
    write_outputs(results, summary)
    generate_charts(results)

    logger.info(f"Completed in {time.perf_counter() - t0:.2f}s")
    logger.info(f"Overall success rate: {summary['overall']['success_rate']:.2%}")
    logger.info(f"Artifacts written to {OUTDIR.resolve()}")

    print("\n=== OVERALL SUMMARY ===")
    print(json.dumps(summary["overall"], indent=2))
    print("\n=== BY STRATEGY ===")
    print(json.dumps(summary["by_strategy"], indent=2))
    print("\n=== BY UNKNOWN_BITS ===")
    print(json.dumps(summary["by_unknown_bits"], indent=2))

if __name__ == "__main__":
    asyncio.run(main())
