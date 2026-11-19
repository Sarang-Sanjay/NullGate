#!/usr/bin/env python3
"""
NullGate — SQLite UDF Sandboxing Performance Benchmark Harness
Pillar 1: Hardware-Enforced Compartmentalization & Low-Overhead Call Gate

Automates comparative throughput & latency profiling between:
  1. Native unconfined SQLite UDF execution
  2. NullGate hardware-isolated UDF compartment (Domain 3 / PKU Key 3)

Evaluates 100,000 queries, profiles QPS and tail latency (P50, P99),
verifies the strict < 5.0% performance overhead budget, and exports JSON results.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser(
        description="NullGate SQLite UDF Performance Benchmark Harness"
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=100000,
        help="Number of queries to benchmark (default: 100000)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="benchmarks/sqlite/sqlite_benchmark_results.json",
        help="Path for output JSON report",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    repo_root = Path(__file__).resolve().parent.parent.parent
    runner_bin = repo_root / "build" / "benchmarks" / "sqlite" / "bench_sqlite_runner"

    print("====================================================================")
    print("   NullGate — SQLite UDF Performance Benchmark Harness             ")
    print("   Pillars 1 & 7: Hardware Call-Gate & Low-Overhead Sandboxing     ")
    print("====================================================================")
    print(f"Iterations       : {args.iterations:,} queries")
    print(f"Runner Binary    : {runner_bin}")

    if not runner_bin.is_file():
        print(f"\n[BUILD] Building bench_sqlite_runner via cmake...")
        subprocess.run(
            ["cmake", "--build", str(repo_root / "build"), "--target", "bench_sqlite_runner"],
            check=True,
        )

    cmd = [str(runner_bin), "--iterations", str(args.iterations), "--json"]
    print(f"[RUN] Executing: {' '.join(cmd)}\n")

    t_start = time.time()
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    t_elapsed = time.time() - t_start

    if res.returncode != 0:
        print(f"[ERROR] Runner failed with exit code {res.returncode}:")
        print(res.stderr)
        sys.exit(res.returncode)

    try:
        report = json.loads(res.stdout)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Failed to parse JSON output: {e}")
        print("Raw output:\n", res.stdout)
        sys.exit(1)

    # Pretty print summary table
    base = report["baseline"]
    null = report["nullgate"]
    overhead_pct = report["overhead_percent"]
    budget_ok = report["within_budget"]

    print("====================================================================")
    print(f"Metric                    Baseline             NullGate Sandboxed")
    print("--------------------------------------------------------------------")
    print(f"Throughput (QPS)          {base['qps']:>15,.2f}     {null['qps']:>15,.2f} queries/s")
    print(f"Average Latency           {base['avg_ns']:>15.2f}     {null['avg_ns']:>15.2f} ns")
    print(f"P50 Median Latency        {base['p50_cycles']:>15,}     {null['p50_cycles']:>15,} cycles")
    print(f"P99 Tail Latency          {base['p99_cycles']:>15,}     {null['p99_cycles']:>15,} cycles")
    print("--------------------------------------------------------------------")
    print(f"Isolation Overhead Delta  : {overhead_pct:.2f}% (Budget: <= 5.00%)")
    print(f"Benchmark Wall Time       : {t_elapsed:.2f} seconds")
    print(f"Certification Status      : {'PASSED (Within 5.0% Budget)' if budget_ok else 'WARNING (Over Budget)'}")
    print("====================================================================")

    out_path = Path(args.output)
    if not out_path.is_absolute():
        out_path = repo_root / out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[REPORT] Saved benchmark metrics report to: {out_path.resolve()}\n")
    assert budget_ok, f"Overhead {overhead_pct:.2f}% exceeded 5.0% performance budget"
    print("[SUCCESS] SQLite UDF Benchmark completed within performance budget.")


if __name__ == "__main__":
    main()
