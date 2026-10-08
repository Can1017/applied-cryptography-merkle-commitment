"""Reproducible public sample and fresh randomized demo, both using local hashes."""

from dataclasses import replace
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.codec import commitment_to_dict, opening_to_dict, opening_to_bytes
from src.hashes import HASHES
from src.merkle import MerkleCommitment, verify

messages = [b"Alice", b"Bob", b"Carol"]
samples = {"warning": "Fixed salts below are public TEST FIXTURES, never use for secret commitments.",
           "fixed": [], "fresh_randomized": []}
for suite in HASHES:
    fixed = MerkleCommitment._restore(messages, suite, [i.to_bytes(32, "big") for i in range(3)])
    proof = fixed.open(1)
    row = {"suite": suite, "commitment": commitment_to_dict(fixed.commitment),
           "opening": opening_to_dict(proof), "opening_binary_hex": opening_to_bytes(proof).hex(),
           "valid": verify(fixed.commitment, proof, expected_index=1, expected_message=b"Bob"),
           "tampered_valid": verify(fixed.commitment, replace(proof, message=b"Mallory"), expected_index=1)}
    assert row["valid"] and not row["tampered_valid"]
    samples["fixed"].append(row)
    fresh = MerkleCommitment(messages, suite)
    p = fresh.open(1)
    samples["fresh_randomized"].append({"suite": suite,
        "commitment": commitment_to_dict(fresh.commitment),
        "opening": opening_to_dict(p),
        "valid": verify(fresh.commitment, p, expected_index=1, expected_message=b"Bob")})
(ROOT / "results" / "demo.json").write_text(json.dumps(samples, indent=2), encoding="utf-8")
for row in samples["fixed"]:
    print(f"{row['suite']}: c={row['commitment']['digest_hex']}; valid={row['valid']}; tampered={row['tampered_valid']}")
print("Wrote results/demo.json; deterministic samples are test-only.")
