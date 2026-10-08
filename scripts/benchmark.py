"""Single-process benchmarks. All cryptographic work uses the local Python code.

Writes every raw repeat; pre-generates the same public test messages for both suites.
Fresh-commit timings include OS randomness; open/verify use a cached tree.
"""

import argparse
from datetime import datetime, timezone
import gc
import json
import os
from pathlib import Path
import platform
from statistics import median
import sys
from time import perf_counter_ns

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.hashes import HASHES
from src.merkle import MerkleCommitment, depth, verify
from src.codec import opening_to_bytes


def cpu_name():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
            return winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
    except (ImportError, OSError):
        return platform.processor()


def measure(function, iterations, repeats):
    function()  # Warm-up outside the measurement.
    values = []
    for _ in range(repeats):
        gc.collect()
        enabled = gc.isenabled()
        gc.disable()
        try:
            start = perf_counter_ns()
            for _ in range(iterations):
                function()
            elapsed = perf_counter_ns() - start
        finally:
            if enabled:
                gc.enable()
        values.append(elapsed / iterations / 1_000_000)
    return {"iterations_per_repeat": iterations, "samples_ms": values,
            "median_ms": median(values), "min_ms": min(values), "max_ms": max(values)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--max-n", type=int, default=4096)
    args = parser.parse_args()
    if args.repeats < 3 or args.max_n < 1:
        parser.error("at least 3 repeats and max-n >= 1 are required")
    result = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {"python": sys.version, "platform": platform.platform(),
                        "cpu": cpu_name(), "logical_cpus": os.cpu_count(), "processes": 1},
        "method": {"repeats": args.repeats, "timer": "perf_counter_ns",
                   "gc_during_timing": False, "warmup": "one call per case",
                   "commit_includes": "fresh salts, hashing, allocations; no JSON or disk I/O",
                   "open_verify": "cached tree; no file loading; verify includes leaf hashing",
                   "messages": "32-byte index encoding; identical for both suites",
                   "memory_metric": "exact byte payload only, not Python process RSS"},
        "hashes": [], "trees": []
    }
    for length in (0, 32, 46, 55, 56, 62, 64, 70, 94, 119, 120, 135, 136, 137, 1024, 4096, 65536):
        message = bytes(i % 251 for i in range(length))
        iterations = max(1, min(100, 16384 // max(1, length)))
        for suite, function in HASHES.items():
            row = {"suite": suite, "input_bytes": length,
                   **measure(lambda: function(message), iterations, args.repeats)}
            row["mib_per_s"] = length / (1 << 20) / (row["median_ms"] / 1000)
            result["hashes"].append(row)
    print("Hash microbenchmarks finished", flush=True)
    for n in (1, 3, 16, 64, 256, 257, 1024, 4096):
        if n > args.max_n:
            continue
        messages = [i.to_bytes(32, "big") for i in range(n)]
        for suite in HASHES:
            commit = measure(lambda: MerkleCommitment(messages, suite), 1, args.repeats)
            tree = MerkleCommitment(messages, suite)
            position = n // 2
            opening = tree.open(position)
            def check():
                if not verify(tree.commitment, opening, expected_index=position,
                              expected_message=messages[position]):
                    raise AssertionError("benchmark verification failed")
            check()
            opened = measure(lambda: tree.open(position), 1000, args.repeats)
            checked = measure(check, 20, args.repeats)
            capacity = 1 << depth(n)
            row = {"suite": suite, "n": n, "message_bytes": 32, "capacity": capacity,
                   "commit": commit, "open": opened, "verify": checked,
                   "path_hashes": depth(n), "path_bytes": 32 * depth(n),
                   "opening_binary_bytes": len(opening_to_bytes(opening)),
                   "tree_hash_payload_bytes": 32 * (2 * capacity - 1),
                   "salt_payload_bytes": 32 * n, "message_payload_bytes": 32 * n,
                   "commit_hash_calls": 2 * capacity, "verify_hash_calls": depth(n) + 2}
            result["trees"].append(row)
            print(f"{suite} n={n}: commit={commit['median_ms']:.3f} ms; verify={checked['median_ms']:.3f} ms", flush=True)
    (ROOT / "results" / "benchmark.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print("Wrote results/benchmark.json", flush=True)


if __name__ == "__main__":
    main()
