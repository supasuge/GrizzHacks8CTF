#!/usr/bin/env python3
from __future__ import annotations

import heapq
import math
import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fpylll import IntegerMatrix, LLL

try:
    from fpylll import BKZ
    HAVE_BKZ = True
except Exception:
    HAVE_BKZ = False


@dataclass(order=True)
class SearchNode:
    priority: float
    score: float = field(compare=False)
    unknown_bits_guess: int = field(compare=False)
    m: int = field(compare=False)
    t: int = field(compare=False)
    prune_keep: Optional[int] = field(compare=False, default=None)
    tau_multiplier: Optional[float] = field(compare=False, default=None)
    transform_chain: Tuple[str, ...] = field(compare=False, default_factory=tuple)
    reduction_schedule: Tuple[Tuple[str, int], ...] = field(compare=False, default_factory=tuple)
    depth: int = field(compare=False, default=0)


def all_reduction_schedules() -> List[Tuple[Tuple[str, int], ...]]:
    schedules = [
        (("LLL", 0),),
        (("LLL", 0), ("BKZ", 20)),
        (("LLL", 0), ("BKZ", 24)),
        (("LLL", 0), ("BKZ", 28)),
        (("BKZ", 28), ("BKZ", 24), ("BKZ", 20)),
        (("BKZ", 20), ("BKZ", 24), ("BKZ", 28)),
        (("LLL", 0), ("BKZ", 24), ("BKZ", 20)),
    ]
    if not HAVE_BKZ:
        return [(("LLL", 0),)]
    return schedules


def all_transform_chains(prune_sizes: Iterable[int], tau_multipliers: Iterable[float]) -> List[Tuple[str, ...]]:
    chains = [("full",)]
    for k in prune_sizes:
        chains.append(("prune", f"keep={k}"))
    for tau in tau_multipliers:
        chains.append(("embed", f"tau={tau}"))
    for k in prune_sizes:
        for tau in tau_multipliers:
            chains.append(("prune", f"keep={k}", "embed", f"tau={tau}"))
    return chains


def enumerate_nodes(
    unknown_bits_guesses: Iterable[int],
    m_range: Tuple[int, int],
    t_range: Tuple[int, int],
    prune_sizes: Iterable[int],
    tau_multipliers: Iterable[float],
) -> List[SearchNode]:
    nodes = []
    schedules = all_reduction_schedules()
    chains = all_transform_chains(prune_sizes, tau_multipliers)

    for ub in unknown_bits_guesses:
        for m in range(m_range[0], m_range[1] + 1):
            for t in range(t_range[0], t_range[1] + 1):
                for chain in chains:
                    prune_keep = None
                    tau_mult = None
                    for item in chain:
                        if isinstance(item, str) and item.startswith("keep="):
                            prune_keep = int(item.split("=")[1])
                        elif isinstance(item, str) and item.startswith("tau="):
                            tau_mult = float(item.split("=")[1])

                    for sched in schedules:
                        nodes.append(
                            SearchNode(
                                priority=0.0,
                                score=0.0,
                                unknown_bits_guess=ub,
                                m=m,
                                t=t,
                                prune_keep=prune_keep,
                                tau_multiplier=tau_mult,
                                transform_chain=chain,
                                reduction_schedule=sched,
                                depth=0,
                            )
                        )
    return nodes


def apply_reduction_schedule(B: IntegerMatrix, schedule: Tuple[Tuple[str, int], ...]) -> IntegerMatrix:
    LLL.reduction(B)
    if not HAVE_BKZ:
        return B

    for alg, block_size in schedule:
        if alg == "LLL":
            LLL.reduction(B)
        elif alg == "BKZ":
            par = BKZ.Param(block_size=block_size)
            BKZ.reduction(B, par)
    return B


def determinant_proxy(B: IntegerMatrix) -> float:
    # Cheap proxy: sum of row norms in log-space.
    total = 0.0
    for i in range(B.nrows):
        s = 0
        for j in range(B.ncols):
            v = int(B[i, j])
            s += v * v
        total += math.log(max(1, s))
    return total


def score_candidate(
    full_dim: int,
    current_dim: int,
    det_before: float,
    det_after: float,
    root_count: int,
    runtime_cost: float,
    divisibility_signal: float,
    history_success: float,
) -> float:
    dim_gain = full_dim - current_dim
    det_gain = det_before - det_after
    root_penalty = math.log(1 + max(0, root_count - 1))
    return (
        3.0 * det_gain
        + 2.0 * dim_gain
        + 4.0 * divisibility_signal
        + 2.0 * history_success
        - 2.5 * root_penalty
        - 0.5 * runtime_cost
    )


def anneal_neighbors(node: SearchNode) -> List[SearchNode]:
    neigh = []
    ub_steps = (-8, -4, -2, 2, 4, 8)
    mt_steps = (-1, 1)
    tau_choices = [0.25, 0.5, 1.0, 2.0, 4.0]
    prune_steps = (-1, 1)

    for d in ub_steps:
        neigh.append(SearchNode(
            priority=0.0,
            score=0.0,
            unknown_bits_guess=max(32, node.unknown_bits_guess + d),
            m=node.m,
            t=node.t,
            prune_keep=node.prune_keep,
            tau_multiplier=node.tau_multiplier,
            transform_chain=node.transform_chain,
            reduction_schedule=node.reduction_schedule,
            depth=node.depth + 1,
        ))

    for d in mt_steps:
        neigh.append(SearchNode(
            priority=0.0,
            score=0.0,
            unknown_bits_guess=node.unknown_bits_guess,
            m=max(1, node.m + d),
            t=node.t,
            prune_keep=node.prune_keep,
            tau_multiplier=node.tau_multiplier,
            transform_chain=node.transform_chain,
            reduction_schedule=node.reduction_schedule,
            depth=node.depth + 1,
        ))
        neigh.append(SearchNode(
            priority=0.0,
            score=0.0,
            unknown_bits_guess=node.unknown_bits_guess,
            m=node.m,
            t=max(0, node.t + d),
            prune_keep=node.prune_keep,
            tau_multiplier=node.tau_multiplier,
            transform_chain=node.transform_chain,
            reduction_schedule=node.reduction_schedule,
            depth=node.depth + 1,
        ))

    for tau in tau_choices:
        neigh.append(SearchNode(
            priority=0.0,
            score=0.0,
            unknown_bits_guess=node.unknown_bits_guess,
            m=node.m,
            t=node.t,
            prune_keep=node.prune_keep,
            tau_multiplier=tau,
            transform_chain=node.transform_chain,
            reduction_schedule=node.reduction_schedule,
            depth=node.depth + 1,
        ))

    if node.prune_keep is not None:
        for d in prune_steps:
            neigh.append(SearchNode(
                priority=0.0,
                score=0.0,
                unknown_bits_guess=node.unknown_bits_guess,
                m=node.m,
                t=node.t,
                prune_keep=max(2, node.prune_keep + d),
                tau_multiplier=node.tau_multiplier,
                transform_chain=node.transform_chain,
                reduction_schedule=node.reduction_schedule,
                depth=node.depth + 1,
            ))

    for sched in all_reduction_schedules():
        neigh.append(SearchNode(
            priority=0.0,
            score=0.0,
            unknown_bits_guess=node.unknown_bits_guess,
            m=node.m,
            t=node.t,
            prune_keep=node.prune_keep,
            tau_multiplier=node.tau_multiplier,
            transform_chain=node.transform_chain,
            reduction_schedule=sched,
            depth=node.depth + 1,
        ))

    return neigh


def accept_annealed(current_score: float, new_score: float, temperature: float) -> bool:
    if new_score >= current_score:
        return True
    delta = current_score - new_score
    p = math.exp(-delta / max(1e-9, temperature))
    return random.random() < p


class OrbitalSublatticeSieve:
    """
    Meta-search controller.

    This does not build lattices itself.
    It expects the caller to:
      - build a basis from node state
      - reduce / extract roots
      - compute divisibility / runtime / determinant stats
      - feed back a score
    """

    def __init__(self, initial_nodes: List[SearchNode]) -> None:
        self.frontier: List[SearchNode] = []
        for node in initial_nodes:
            heapq.heappush(self.frontier, node)
        self.best_node: Optional[SearchNode] = None
        self.best_score: float = -10**18
        self.history_success: Dict[Tuple[int, int, int], float] = {}

    def update_history(self, node: SearchNode, success: bool) -> None:
        key = (node.unknown_bits_guess, node.m, node.t)
        self.history_success[key] = self.history_success.get(key, 0.0) * 0.8 + (1.0 if success else 0.0) * 0.2

    def history_score(self, node: SearchNode) -> float:
        return self.history_success.get((node.unknown_bits_guess, node.m, node.t), 0.0)

    def submit_result(self, node: SearchNode, score: float, success: bool) -> None:
        node.score = score
        node.priority = -score
        self.update_history(node, success)

        if score > self.best_score:
            self.best_score = score
            self.best_node = node

        temp = max(0.05, 2.0 / (1 + node.depth))
        for neigh in anneal_neighbors(node):
            hist = self.history_score(neigh)
            neigh.score = hist
            neigh.priority = -hist
            if accept_annealed(score, hist, temp):
                heapq.heappush(self.frontier, neigh)

    def next_batch(self, k: int = 16) -> List[SearchNode]:
        out = []
        seen = set()
        while self.frontier and len(out) < k:
            node = heapq.heappop(self.frontier)
            key = (
                node.unknown_bits_guess,
                node.m,
                node.t,
                node.prune_keep,
                node.tau_multiplier,
                node.transform_chain,
                node.reduction_schedule,
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(node)
        return out
