from dataclasses import replace
from unittest.mock import patch
import unittest

from src.hashes import HASHES
from src.merkle import (Commitment, MerkleCommitment, Opening, depth, finalize,
                        leaf_hash, padding_hash, parent_hash, verify, verify_all)


def flip(value):
    return bytes([value[0] ^ 1]) + value[1:]


class MerkleTests(unittest.TestCase):
    def setUp(self):
        self.messages = [b"alpha", b"beta", b"gamma", b"delta", b"epsilon"]
        self.salts = [i.to_bytes(32, "big") for i in range(5)]

    def test_all_positions_and_shapes(self):
        for suite in HASHES:
            for n in list(range(34)) + [63, 64, 65, 127, 128, 129]:
                messages = [b"" if i % 4 == 0 else i.to_bytes(2, "big") for i in range(n)]
                tree = MerkleCommitment(messages, suite)
                with self.subTest(suite=suite, n=n):
                    self.assertTrue(verify_all(tree.commitment, *tree.reveal_all()))
                    for i in range(n):
                        proof = tree.open(i)
                        self.assertEqual(len(proof.siblings), depth(n))
                        self.assertTrue(verify(tree.commitment, proof, expected_index=i,
                                               expected_message=messages[i]))

    def test_manual_three_leaf_construction(self):
        # Explicit formula is independent of the implementation's level-building loop.
        for suite in HASHES:
            tree = MerkleCommitment._restore(self.messages[:3], suite, self.salts[:3])
            leaves = [leaf_hash(suite, 3, i, self.messages[i], self.salts[i]) for i in range(3)]
            dummy = padding_hash(suite, 3, 3)
            left = parent_hash(suite, leaves[0], leaves[1])
            right = parent_hash(suite, leaves[2], dummy)
            expected = finalize(suite, 3, parent_hash(suite, left, right))
            self.assertEqual(tree.commitment.digest, expected)
            self.assertEqual(tree.open(2).siblings, (dummy, left))

    def test_empty_vector(self):
        for suite in HASHES:
            tree = MerkleCommitment([], suite)
            self.assertEqual(tree.commitment.digest, finalize(suite, 0, padding_hash(suite, 0, 0)))
            self.assertTrue(verify_all(tree.commitment, [], []))
            with self.assertRaises(ValueError):
                tree.open(0)
            proof = Opening(0, b"", bytes(32), ())
            self.assertFalse(verify(tree.commitment, proof, expected_index=0))

    def test_singleton_has_no_siblings(self):
        tree = MerkleCommitment([b"one"])
        self.assertEqual(tree.open(0).siblings, ())
        self.assertTrue(verify(tree.commitment, tree.open(0), expected_index=0))

    def test_fresh_randomness_and_requested_size(self):
        with patch("src.merkle.token_bytes", side_effect=self.salts) as source:
            tree = MerkleCommitment(self.messages)
            self.assertEqual(source.call_count, 5)
            self.assertTrue(all(call.args == (32,) for call in source.call_args_list))
            self.assertEqual(tree.reveal_all()[1], tuple(self.salts))
        a, b = MerkleCommitment(self.messages), MerkleCommitment(self.messages)
        self.assertNotEqual(a.commitment, b.commitment)  # overwhelmingly likely
        self.assertNotEqual(a.reveal_all()[1], b.reveal_all()[1])

    def test_duplicate_messages_have_position_bound_leaves(self):
        tree = MerkleCommitment._restore([b"same", b"same"], "sha256", [bytes(32)] * 2)
        self.assertNotEqual(tree._levels[0][0], tree._levels[0][1])
        self.assertFalse(verify(tree.commitment, tree.open(0), expected_index=1))

    def test_tampering_every_authenticated_component(self):
        for suite in HASHES:
            tree = MerkleCommitment._restore(self.messages, suite, self.salts)
            c, p = tree.commitment, tree.open(2)
            proofs = [replace(p, message=p.message + b"!"), replace(p, salt=flip(p.salt)),
                      replace(p, index=3), replace(p, siblings=p.siblings[:-1]),
                      replace(p, siblings=p.siblings + (bytes(32),)),
                      replace(p, siblings=tuple(reversed(p.siblings)))]
            for j in range(len(p.siblings)):
                path = list(p.siblings)
                path[j] = flip(path[j])
                proofs.append(replace(p, siblings=tuple(path)))
            for bad in proofs:
                with self.subTest(suite=suite, proof=bad):
                    self.assertFalse(verify(c, bad, expected_index=2))
            for bad_c in (replace(c, digest=flip(c.digest)), replace(c, n=6),
                          replace(c, suite="sha3-256" if suite == "sha256" else "sha256")):
                self.assertFalse(verify(bad_c, p, expected_index=2))
            self.assertFalse(verify(c, p, expected_index=True))
            self.assertFalse(verify(c, p, expected_index=2, expected_message=b"wrong"))
            self.assertFalse(verify(c, p, expected_index=2, expected_message="gamma"))
            self.assertFalse(verify(c, {}, expected_index=2))

    def test_size_binding_prevents_duplicate_tail_ambiguity(self):
        for suite in HASHES:
            a = MerkleCommitment._restore(self.messages[:3], suite, self.salts[:3])
            b = MerkleCommitment._restore(self.messages[:3] + [self.messages[2]], suite,
                                         self.salts[:3] + [self.salts[2]])
            self.assertNotEqual(a.commitment.digest, b.commitment.digest)

    def test_order_binding(self):
        a = MerkleCommitment._restore(self.messages, "sha256", self.salts)
        b = MerkleCommitment._restore(list(reversed(self.messages)), "sha256", self.salts)
        self.assertNotEqual(a.commitment.digest, b.commitment.digest)

    def test_input_validation(self):
        for bad in (["text"], b"not a vector", [bytearray(b"x")], [None]):
            with self.assertRaises(TypeError):
                MerkleCommitment(bad)
        with self.assertRaises(ValueError):
            MerkleCommitment([], "unknown")
        tree = MerkleCommitment(self.messages)
        for index in (-1, 5, True, "0", 1.5):
            with self.assertRaises(ValueError):
                tree.open(index)
        for n in (-1, True, 1 << 64):
            with self.assertRaises(ValueError):
                Commitment("sha256", n, bytes(32))
        for salts in ([], [b"short"] * 5, "not salts"):
            with self.assertRaises(ValueError):
                MerkleCommitment._restore(self.messages, "sha256", salts)
        with self.assertRaises(ValueError):
            Opening(0, b"", bytes(32), (b"short",))

    def test_full_opening_rejects_modification(self):
        tree = MerkleCommitment(self.messages)
        m, r = tree.reveal_all()
        self.assertFalse(verify_all(tree.commitment, m[:-1], r[:-1]))
        self.assertFalse(verify_all(tree.commitment, (b"bad",) + m[1:], r))
        self.assertFalse(verify_all(tree.commitment, m, (flip(r[0]),) + r[1:]))
        self.assertFalse(verify_all(tree.commitment, m, []))


if __name__ == "__main__":
    unittest.main()
