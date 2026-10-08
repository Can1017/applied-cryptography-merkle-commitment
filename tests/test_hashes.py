import unittest

from src.hashes import HASHES, sha256, sha3_256
from tests.vector_loader import load_vectors


class HashTests(unittest.TestCase):
    def test_nist_sha256_short(self):
        for message, expected in load_vectors("SHA256ShortMsg.rsp"):
            with self.subTest(bytes=len(message)):
                self.assertEqual(sha256(message), expected)

    def test_nist_sha256_long(self):
        for message, expected in load_vectors("SHA256LongMsg.rsp"):
            with self.subTest(bytes=len(message)):
                self.assertEqual(sha256(message), expected)

    def test_nist_sha3_short(self):
        for message, expected in load_vectors("SHA3_256ShortMsg.rsp"):
            with self.subTest(bytes=len(message)):
                self.assertEqual(sha3_256(message), expected)

    def test_nist_sha3_long(self):
        for message, expected in load_vectors("SHA3_256LongMsg.rsp"):
            with self.subTest(bytes=len(message)):
                self.assertEqual(sha3_256(message), expected)

    def test_fips_examples(self):
        pairs = [
            (sha256, b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (sha256, b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
             "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
            (sha3_256, b"\xa3" * 200,
             "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787"),
        ]
        for function, message, expected in pairs:
            with self.subTest(function=function.__name__, length=len(message)):
                self.assertEqual(function(message).hex(), expected)

    def test_reject_implicit_encoding(self):
        for function in HASHES.values():
            for value in ("abc", 3, None, bytearray(b"abc")):
                with self.subTest(function=function.__name__, value=value):
                    with self.assertRaises(TypeError):
                        function(value)


if __name__ == "__main__":
    unittest.main()
