"""Strict JSON and compact binary transport for MTC1 (no cryptographic library)."""

import json
from pathlib import Path

from .hashes import SUITE_IDS
from .merkle import Commitment, Opening, MerkleCommitment, VERSION, _u64

MAX_JSON_BYTES = 16 * 1024 * 1024


def _keys(value, expected):
    if type(value) is not dict or set(value) != set(expected):
        raise ValueError("missing or unexpected object fields")


def _hex(value) -> bytes:
    if type(value) is not str or len(value) % 2:
        raise ValueError("expected even-length hexadecimal text")
    if any(c not in "0123456789abcdef" for c in value):
        raise ValueError("expected canonical lowercase hexadecimal text")
    return bytes.fromhex(value)


def commitment_to_dict(value: Commitment) -> dict:
    return {"version": VERSION, "suite": value.suite,
            "n": value.n, "digest_hex": value.digest.hex()}


def commitment_from_dict(value: dict) -> Commitment:
    _keys(value, ("version", "suite", "n", "digest_hex"))
    if value["version"] != VERSION:
        raise ValueError("unsupported commitment version")
    return Commitment(value["suite"], value["n"], _hex(value["digest_hex"]))


def opening_to_dict(value: Opening) -> dict:
    return {"version": VERSION, "index": value.index,
            "message_hex": value.message.hex(), "salt_hex": value.salt.hex(),
            "siblings_hex": [s.hex() for s in value.siblings]}


def opening_from_dict(value: dict) -> Opening:
    _keys(value, ("version", "index", "message_hex", "salt_hex", "siblings_hex"))
    if value["version"] != VERSION:
        raise ValueError("unsupported opening version")
    siblings = value["siblings_hex"]
    if type(siblings) is not list or len(siblings) > 64:
        raise ValueError("invalid sibling list")
    return Opening(value["index"], _hex(value["message_hex"]), _hex(value["salt_hex"]),
                   tuple(_hex(s) for s in siblings))


def commitment_to_bytes(value: Commitment) -> bytes:
    return b"MTC1" + SUITE_IDS[value.suite] + _u64(value.n) + value.digest


def commitment_from_bytes(value: bytes) -> Commitment:
    if type(value) is not bytes or len(value) != 45 or value[:4] != b"MTC1":
        raise ValueError("invalid binary commitment")
    suites = {v: k for k, v in SUITE_IDS.items()}
    if value[4:5] not in suites:
        raise ValueError("unsupported suite")
    return Commitment(suites[value[4:5]], int.from_bytes(value[5:13], "big"), value[13:])


def opening_to_bytes(value: Opening) -> bytes:
    return (_u64(value.index) + _u64(len(value.message)) + value.message + value.salt
            + bytes([len(value.siblings)]) + b"".join(value.siblings))


def opening_from_bytes(value: bytes) -> Opening:
    if type(value) is not bytes or len(value) < 49:
        raise ValueError("truncated binary opening")
    index = int.from_bytes(value[:8], "big")
    size = int.from_bytes(value[8:16], "big")
    tail = 16 + size
    if tail + 33 > len(value):
        raise ValueError("invalid message length")
    count = value[tail + 32]
    if count > 64 or len(value) != tail + 33 + count * 32:
        raise ValueError("invalid path length or trailing bytes")
    return Opening(index, value[16:tail], value[tail:tail + 32],
                   tuple(value[i:i + 32] for i in range(tail + 33, len(value), 32)))


def state_to_dict(tree: MerkleCommitment) -> dict:
    messages, salts = tree.reveal_all()
    return {"version": VERSION, "commitment": commitment_to_dict(tree.commitment),
            "messages_hex": [m.hex() for m in messages],
            "salts_hex": [s.hex() for s in salts]}


def state_from_dict(value: dict) -> MerkleCommitment:
    _keys(value, ("version", "commitment", "messages_hex", "salts_hex"))
    if value["version"] != VERSION:
        raise ValueError("unsupported state version")
    commitment = commitment_from_dict(value["commitment"])
    if type(value["messages_hex"]) is not list or type(value["salts_hex"]) is not list:
        raise ValueError("messages and salts must be arrays")
    tree = MerkleCommitment._restore([_hex(m) for m in value["messages_hex"]],
                                    commitment.suite, [_hex(s) for s in value["salts_hex"]])
    if tree.commitment != commitment:
        raise ValueError("private state does not reproduce its commitment")
    return tree


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _bad_constant(value):
    raise ValueError("non-finite JSON number")


def read_json(path) -> object:
    # Read a bounded amount even when the file is replaced after a size check.
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("JSON file exceeds 16 MiB limit")
    return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_object,
                      parse_constant=_bad_constant)


def write_new_json(path, value) -> None:
    # Exclusive creation prevents accidental replacement of private state.
    encoded = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(encoded) > MAX_JSON_BYTES:
        raise ValueError("serialized JSON exceeds 16 MiB limit")
    with Path(path).open("xb") as stream:
        stream.write(encoded)
