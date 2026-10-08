from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.cli import main
from src.codec import (commitment_from_bytes, commitment_from_dict, commitment_to_bytes,
                       commitment_to_dict, opening_from_bytes, opening_from_dict,
                       opening_to_bytes, opening_to_dict, read_json,
                       state_from_dict, state_to_dict, write_new_json)
from src.hashes import HASHES
from src.merkle import MerkleCommitment


class CodecTests(unittest.TestCase):
    def test_writer_rejects_unreadable_oversize_output_before_creation(self):
        with tempfile.TemporaryDirectory() as tmp, patch("src.codec.MAX_JSON_BYTES", 64):
            target = Path(tmp) / "oversize.json"
            with self.assertRaises(ValueError):
                write_new_json(target, {"message": "x" * 100})
            self.assertFalse(target.exists())

    def test_roundtrip(self):
        for suite in HASHES:
            for messages in ([], [b""], ["中文".encode(), b"\x00\xff", b"repeat", b"repeat", b""]):
                tree = MerkleCommitment(messages, suite)
                c = tree.commitment
                self.assertEqual(commitment_from_dict(commitment_to_dict(c)), c)
                self.assertEqual(commitment_from_bytes(commitment_to_bytes(c)), c)
                self.assertEqual(len(commitment_to_bytes(c)), 45)
                self.assertEqual(state_from_dict(state_to_dict(tree)).commitment, c)
                for i in range(len(messages)):
                    p = tree.open(i)
                    self.assertEqual(opening_from_dict(opening_to_dict(p)), p)
                    self.assertEqual(opening_from_bytes(opening_to_bytes(p)), p)
                    self.assertEqual(len(opening_to_bytes(p)), p.binary_size)

    def test_reject_noncanonical_json(self):
        tree = MerkleCommitment([b"abc"])
        c = commitment_to_dict(tree.commitment)
        p = opening_to_dict(tree.open(0))
        for change in ({"n": True}, {"n": -1}, {"extra": 3}, {"suite": "sha1"},
                       {"version": "MTC2"}, {"digest_hex": "00 " * 32},
                       {"digest_hex": "AA" * 32}, {"digest_hex": "0"}):
            with self.assertRaises(ValueError):
                commitment_from_dict(c | change)
        for change in ({"index": True}, {"salt_hex": "ff"}, {"siblings_hex": "00"},
                       {"siblings_hex": ["00"]}, {"siblings_hex": ["00" * 32] * 65},
                       {"message_hex": "gh"}, {"version": 1}):
            with self.assertRaises(ValueError):
                opening_from_dict(p | change)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            for value in ('{"n":1,"n":2}', '{"n":NaN}'):
                path.write_text(value, encoding="utf-8")
                with self.assertRaises(ValueError):
                    read_json(path)

    def test_binary_reject_truncation_extra_bytes_and_lengths(self):
        tree = MerkleCommitment([b"abc", b"def", b"ghi"])
        c, p = commitment_to_bytes(tree.commitment), opening_to_bytes(tree.open(1))
        for bad in (c[:-1], c + b"x", b"BAD!" + c[4:], c[:4] + b"\xff" + c[5:]):
            with self.assertRaises(ValueError):
                commitment_from_bytes(bad)
        for bad in (p[:-1], p + b"x", p[:8] + b"\xff" * 8 + p[16:], b""):
            with self.assertRaises(ValueError):
                opening_from_bytes(bad)

    def test_private_state_corruption(self):
        state = state_to_dict(MerkleCommitment([b"abc"]))
        state["salts_hex"][0] = "00" * 32
        with self.assertRaises(ValueError):
            state_from_dict(state)

    def test_cli_end_to_end_and_rejection(self):
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            base = Path(tmp)
            source, public, state, proof = [str(base / x) for x in ("input.json", "public.json", "private.json", "proof.json")]
            Path(source).write_text(json.dumps(["first", "中文", "last"]), encoding="utf-8")
            self.assertEqual(main(["commit", source, "--public", public, "--state", state]), 0)
            self.assertEqual(main(["open", state, "--index", "1", "--out", proof]), 0)
            self.assertEqual(main(["verify", public, proof, "--index", "1", "--message", "中文"]), 0)
            self.assertEqual(main(["verify", public, proof, "--index", "0"]), 1)
            self.assertEqual(main(["verify", public, proof, "--index", "1", "--message", "changed"]), 1)
            self.assertEqual(main(["commit", source, "--public", public, "--state", state]), 2)
            self.assertEqual(main(["commit", source, "--public", source, "--state", state]), 2)
            Path(proof).write_text('{"index":false}', encoding="utf-8")
            self.assertEqual(main(["verify", public, proof, "--index", "1"]), 2)


if __name__ == "__main__":
    unittest.main()
