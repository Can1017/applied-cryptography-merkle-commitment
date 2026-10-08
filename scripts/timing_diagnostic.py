"""Repeat the anomalous 256/257-leaf verification cases without changing primary data."""

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.benchmark import measure
from src.merkle import MerkleCommitment, verify

rows = []
for n in (256, 257):
    for suite in ("sha256", "sha3-256"):
        tree = MerkleCommitment([i.to_bytes(32, "big") for i in range(n)], suite)
        proof = tree.open(n // 2)
        def check():
            assert verify(tree.commitment, proof, expected_index=n // 2)
        rows.append({"n": n, "suite": suite, "hash_calls": len(proof.siblings) + 2,
                     "verify": measure(check, 40, 5)})
result = {"reason": "Primary run SHA3 verification at n=257 was faster than n=256 despite one extra hash call.",
          "method": "same code, 5 repeats of 40 cached verifications; original data retained", "rows": rows}
(ROOT / "results" / "benchmark_diagnostic.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
print(json.dumps(result, indent=2))
