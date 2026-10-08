"""Concrete attacks on weak designs; these finite experiments do not prove hiding."""

from dataclasses import replace
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.hashes import sha256
from src.merkle import MerkleCommitment, leaf_hash, verify


def naive_root(messages):
    level = [sha256(m) for m in messages]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def main():
    candidates = [str(score).encode() for score in range(101)]
    secret = b"73"
    target = sha256(secret)
    guessed = next(x for x in candidates if sha256(x) == target)

    public_salt = b"S" * 32
    public_target = leaf_hash("sha256", 1, 0, secret, public_salt)
    public_guess = next(x for x in candidates
                        if leaf_hash("sha256", 1, 0, x, public_salt) == public_target)

    shared = MerkleCommitment._restore([b"revealed", secret], "sha256", [public_salt] * 2)
    disclosure = shared.open(0)
    shared_guess = next(x for x in candidates
                        if leaf_hash("sha256", 2, 1, x, disclosure.salt) == disclosure.siblings[0])

    # This is an explicitly deterministic negative-control fixture, not a secure commit.
    independent = MerkleCommitment._restore([b"revealed", secret], "sha256", [b"A" * 32, b"B" * 32])
    other = independent.open(0)
    wrong_salt_matches = [x.decode() for x in candidates
                          if leaf_hash("sha256", 2, 1, x, other.salt) == other.siblings[0]]

    small_target = sha256(bytes([19]) + secret)
    attempts = 0
    found = None
    for salt in range(256):
        for guess in candidates:
            attempts += 1
            if sha256(bytes([salt]) + guess) == small_target:
                found = {"salt": salt, "message": guess.decode()}
                break
        if found is not None:
            break

    a, b = [b"A", b"B", b"C"], [b"A", b"B", b"C", b"C"]
    protected_a = MerkleCommitment._restore(a, "sha256", [bytes([i]) * 32 for i in range(3)])
    protected_b = MerkleCommitment._restore(b, "sha256", [bytes([i]) * 32 for i in range(4)])
    proof = protected_a.open(1)
    results = {
        "unsalted_dictionary": {"recovered": guessed.decode(), "candidates_tried": 74},
        "public_salt_dictionary": {"recovered": public_guess.decode(), "candidates_tried": 74},
        "shared_salt_after_one_opening": {"recovered": shared_guess.decode(), "candidates_tried": 74},
        "independent_salt_using_other_leaves_salt": {"candidate_count": 101, "matches": wrong_salt_matches},
        "weak_8_bit_salt": {"found": found, "hash_queries": attempts},
        "duplicate_tail_naive_roots_equal": naive_root(a) == naive_root(b),
        "duplicate_tail_mtc1_roots_equal": protected_a.commitment.digest == protected_b.commitment.digest,
        "valid_opening_accepted": verify(protected_a.commitment, proof, expected_index=1),
        "modified_message_accepted": verify(protected_a.commitment, replace(proof, message=b"changed"), expected_index=1),
        "limitation": "Failure of a restricted guessing attack is not a proof of hiding; see the ROM analysis."
    }
    assert guessed == public_guess == shared_guess == secret
    assert not wrong_salt_matches and found == {"salt": 19, "message": "73"}
    assert results["duplicate_tail_naive_roots_equal"] and not results["duplicate_tail_mtc1_roots_equal"]
    assert results["valid_opening_accepted"] and not results["modified_message_accepted"]
    (ROOT / "results" / "security_demo.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
