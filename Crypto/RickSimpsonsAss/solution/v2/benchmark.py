#!/usr/bin/env python3
"""
Benchmark the known-high-bits RSA solver across 100 generated instances.

Usage:
    python gen_batch_challenges.py
    python benchmark_solver.py

Outputs:
- benchmark_results.json
- benchmark_results.jsonl

Collected stats:
- total instances
- success count / success rate
- plaintext correctness rate
- factor recovery correctness rate
- mean / median / min / max solve time
- timing percentiles
- parameter usage frequencies
- per-instance records
"""

from __future__ import annotations

import json
import math
import statistics
from collections import Counter
from pathlib import Path
from typing import Dict, List

from solver import solve_instance

INFILE = Path("batch_challenges.json")
OUT_JSON = Path("benchmark_results.json")
OUT_JSONL = Path("benchmark_results.jsonl")


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
    d0 = sorted_values[f] * (c - k)
    d1 = sorted_values[c] * (k - f)
    return d0 + d1


def main() -> None:
    data = json.loads(INFILE.read_text(encoding="utf-8"))
    instances = data["instances"]

    results = []
    param_counter = Counter()

    with OUT_JSONL.open("w", encoding="utf-8") as fh:
        for inst in instances:
            result = solve_instance(
                inst,
                m_range=(2, 14),
                t_range=(1, 14),
                try_bkz=True,
                bkz_block_sizes=(20,),
            )
            results.append(result)
            fh.write(json.dumps(result) + "\n")

            cp = result.get("chosen_params")
            if cp:
                key = (
                    cp["m"],
                    cp["t"],
                    cp["use_bkz"],
                    cp.get("bkz_block_size"),
                )
                param_counter[key] += 1

            status = "OK" if result["success"] else "FAIL"
            print(
                f"[{status}] instance={result['instance_id']:03d} "
                f"time={result['solve_time_sec']:.4f}s "
                f"attempts={result['attempts']} "
                f"plaintext_ok={result['plaintext_ok']} "
                f"factors_ok={result['factors_ok']} "
                f"params={result['chosen_params']}"
            )

    total = len(results)
    success_results = [r for r in results if r["success"]]
    times = [r["solve_time_sec"] for r in results]
    success_times = [r["solve_time_sec"] for r in success_results]

    success_count = sum(r["success"] for r in results)
    plaintext_ok_count = sum(r["plaintext_ok"] for r in results)
    factors_ok_count = sum(r["factors_ok"] for r in results)

    sorted_times = sorted(times)
    sorted_success_times = sorted(success_times)

    summary = {
        "total_instances": total,
        "success_count": success_count,
        "failure_count": total - success_count,
        "success_rate": success_count / total if total else 0.0,
        "plaintext_ok_count": plaintext_ok_count,
        "plaintext_ok_rate": plaintext_ok_count / total if total else 0.0,
        "factors_ok_count": factors_ok_count,
        "factors_ok_rate": factors_ok_count / total if total else 0.0,
        "timing_all": {
            "mean": statistics.mean(times) if times else 0.0,
            "median": statistics.median(times) if times else 0.0,
            "min": min(times) if times else 0.0,
            "max": max(times) if times else 0.0,
            "p90": percentile(sorted_times, 0.90),
            "p95": percentile(sorted_times, 0.95),
            "p99": percentile(sorted_times, 0.99),
        },
        "timing_success_only": {
            "mean": statistics.mean(success_times) if success_times else 0.0,
            "median": statistics.median(success_times) if success_times else 0.0,
            "min": min(success_times) if success_times else 0.0,
            "max": max(success_times) if success_times else 0.0,
            "p90": percentile(sorted_success_times, 0.90) if success_times else 0.0,
            "p95": percentile(sorted_success_times, 0.95) if success_times else 0.0,
            "p99": percentile(sorted_success_times, 0.99) if success_times else 0.0,
        },
        "parameter_usage": [
            {
                "m": k[0],
                "t": k[1],
                "use_bkz": k[2],
                "bkz_block_size": k[3],
                "count": v,
            }
            for k, v in param_counter.most_common()
        ],
        "results": results,
    }

    OUT_JSON.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print()
    print("=== SUMMARY ===")
    print(f"Total instances     : {summary['total_instances']}")
    print(f"Success count       : {summary['success_count']}")
    print(f"Failure count       : {summary['failure_count']}")
    print(f"Success rate        : {summary['success_rate']:.2%}")
    print(f"Plaintext OK rate   : {summary['plaintext_ok_rate']:.2%}")
    print(f"Factors OK rate     : {summary['factors_ok_rate']:.2%}")
    print(f"Mean solve time     : {summary['timing_all']['mean']:.4f}s")
    print(f"Median solve time   : {summary['timing_all']['median']:.4f}s")
    print(f"P95 solve time      : {summary['timing_all']['p95']:.4f}s")
    print(f"Max solve time      : {summary['timing_all']['max']:.4f}s")
    print()
    print(f"[+] Wrote {OUT_JSON}")
    print(f"[+] Wrote {OUT_JSONL}")


if __name__ == "__main__":
    main()
