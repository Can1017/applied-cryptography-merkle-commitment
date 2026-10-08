"""MTC1: randomized, ordered Merkle vector commitments.

The public commitment is (suite, n, digest). Salts stay private until opening.
Binding assumes collision resistance; hiding additionally uses the random
oracle model and independent, secret 256-bit salts. See the design report.
"""

from dataclasses import dataclass
from secrets import token_bytes

from .hashes import HASHES, SUITE_IDS

VERSION = "MTC1"
SALT_BYTES = 32
MAX_U64 = (1 << 64) - 1
# Resource limit for this in-memory coursework implementation, not a security level.
MAX_LEAVES = 1 << 20


def _u64(value: int) -> bytes:
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise ValueError("expected an unsigned 64-bit integer (not bool)")
    return value.to_bytes(8, "big")


def _suite(suite: str) -> None:
    if type(suite) is not str or suite not in HASHES:
        raise ValueError("unsupported hash suite")


def _prefix(tag: int, suite: str) -> bytes:
    return bytes([tag]) + b"MTC1" + SUITE_IDS[suite]


def leaf_hash(suite: str, n: int, index: int, message: bytes, salt: bytes) -> bytes:
    return HASHES[suite](_prefix(0, suite) + _u64(n) + _u64(index)
                         + _u64(len(message)) + salt + message)


def padding_hash(suite: str, n: int, index: int) -> bytes:
    return HASHES[suite](_prefix(3, suite) + _u64(n) + _u64(index))


def parent_hash(suite: str, left: bytes, right: bytes) -> bytes:
    return HASHES[suite](_prefix(1, suite) + left + right)


def finalize(suite: str, n: int, tree_root: bytes) -> bytes:
    return HASHES[suite](_prefix(2, suite) + _u64(n) + tree_root)


def depth(n: int) -> int:
    return (max(1, n) - 1).bit_length()


@dataclass(frozen=True)
class Commitment:
    suite: str
    n: int
    digest: bytes

    def __post_init__(self):
        _suite(self.suite)
        _u64(self.n)
        if type(self.digest) is not bytes or len(self.digest) != 32:
            raise ValueError("commitment digest must be 32 bytes")


@dataclass(frozen=True)
class Opening:
    index: int
    message: bytes
    salt: bytes
    siblings: tuple[bytes, ...]

    def __post_init__(self):
        _u64(self.index)
        if type(self.message) is not bytes:
            raise ValueError("message must be bytes")
        _u64(len(self.message))
        if type(self.salt) is not bytes or len(self.salt) != SALT_BYTES:
            raise ValueError("salt must be 32 bytes")
        if type(self.siblings) is not tuple or len(self.siblings) > 64:
            raise ValueError("siblings must be a tuple of at most 64 digests")
        if any(type(x) is not bytes or len(x) != 32 for x in self.siblings):
            raise ValueError("each sibling must be 32 bytes")

    @property
    def binary_size(self) -> int:
        """Canonical compact size: index8 + len8 + m + salt32 + depth1 + path."""
        return 49 + len(self.message) + 32 * len(self.siblings)


class MerkleCommitment:
    """Keep messages, salts and levels in memory; commit once and open many times."""

    def __init__(self, messages: list[bytes] | tuple[bytes, ...], suite: str = "sha256"):
        values = self._validate_messages(messages, suite)
        self._build(values, suite, tuple(token_bytes(SALT_BYTES) for _ in values))

    @staticmethod
    def _validate_messages(messages, suite):
        _suite(suite)
        if type(messages) not in (list, tuple):
            raise TypeError("messages must be a list or tuple of bytes")
        if len(messages) > MAX_LEAVES:
            raise ValueError("in-memory limit exceeded")
        if any(type(m) is not bytes for m in messages):
            raise TypeError("every message must be bytes")
        # All suites use the SHA-256 compatible message length bound.
        if any(len(m) + 62 >= 1 << 61 for m in messages):
            raise ValueError("message too long")
        return tuple(messages)

    @classmethod
    def _restore(cls, messages, suite, salts):
        """Restore stored private randomness; also used for deterministic tests.

        Not the fresh-commit API. Arbitrary/reused salts invalidate hiding claims.
        """
        values = cls._validate_messages(messages, suite)
        if type(salts) not in (list, tuple) or len(salts) != len(values):
            raise ValueError("one salt per real leaf is required")
        if any(type(s) is not bytes or len(s) != SALT_BYTES for s in salts):
            raise ValueError("salts must be 32-byte strings")
        obj = cls.__new__(cls)
        obj._build(values, suite, tuple(salts))
        return obj

    def _build(self, values, suite, salts):
        self._messages, self._salts, self._suite = values, salts, suite
        n = len(values)
        capacity = 1 << depth(n)
        leaves = [leaf_hash(suite, n, i, m, salts[i]) for i, m in enumerate(values)]
        leaves.extend(padding_hash(suite, n, i) for i in range(n, capacity))
        levels = [tuple(leaves)]
        while len(levels[-1]) > 1:
            below = levels[-1]
            levels.append(tuple(parent_hash(suite, below[i], below[i + 1])
                                for i in range(0, len(below), 2)))
        self._levels = tuple(levels)
        self.commitment = Commitment(suite, n, finalize(suite, n, levels[-1][0]))

    def open(self, index: int) -> Opening:
        if type(index) is not int or not 0 <= index < self.commitment.n:
            raise ValueError("index outside real leaves")
        position = index
        siblings = []
        for level in self._levels[:-1]:
            siblings.append(level[position ^ 1])
            position >>= 1
        return Opening(index, self._messages[index], self._salts[index], tuple(siblings))

    def reveal_all(self) -> tuple[tuple[bytes, ...], tuple[bytes, ...]]:
        """Release every message and salt; this intentionally ends hiding."""
        return self._messages, self._salts


def verify(commitment: Commitment, opening: Opening, *, expected_index: int,
           expected_message: bytes | None = None) -> bool:
    """Verify against a separately trusted commitment and an explicit position.

    expected_message=None means accept and disclose the message inside opening.
    Supply bytes when checking a previously specified statement about its value.
    """
    if type(commitment) is not Commitment or type(opening) is not Opening:
        return False
    if type(expected_index) is not int or expected_index != opening.index:
        return False
    if expected_message is not None:
        if type(expected_message) is not bytes or expected_message != opening.message:
            return False
    if not 0 <= opening.index < commitment.n:
        return False
    if len(opening.siblings) != depth(commitment.n):
        return False
    suite = commitment.suite
    value = leaf_hash(suite, commitment.n, opening.index, opening.message, opening.salt)
    position = opening.index
    for sibling in opening.siblings:
        value = (parent_hash(suite, sibling, value) if position & 1
                 else parent_hash(suite, value, sibling))
        position >>= 1
    return finalize(suite, commitment.n, value) == commitment.digest


def verify_all(commitment: Commitment, messages, salts) -> bool:
    """Verify a complete vector opening; useful also for the empty vector."""
    if type(commitment) is not Commitment:
        return False
    try:
        restored = MerkleCommitment._restore(messages, commitment.suite, salts)
    except (TypeError, ValueError):
        return False
    return restored.commitment == commitment
