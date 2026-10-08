"""Run with python -m src.cli. All message arguments are UTF-8 unless --hex."""

import argparse
import json
from pathlib import Path
import sys

from .codec import (commitment_from_dict, commitment_to_dict, opening_from_dict,
                    opening_to_dict, read_json, state_from_dict, state_to_dict,
                    write_new_json)
from .hashes import HASHES
from .merkle import MerkleCommitment, verify


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="MTC1 randomized Merkle commitments")
    commands = parser.add_subparsers(dest="command", required=True)
    c = commands.add_parser("commit", help="commit to a JSON list of strings")
    c.add_argument("input")
    c.add_argument("--suite", choices=HASHES, default="sha256")
    c.add_argument("--hex", action="store_true", help="input strings contain hex bytes")
    c.add_argument("--public", required=True)
    c.add_argument("--state", required=True, help="private file: contains all messages and salts")
    o = commands.add_parser("open", help="open one zero-based position")
    o.add_argument("state")
    o.add_argument("--index", type=int, required=True)
    o.add_argument("--out", required=True)
    v = commands.add_parser("verify", help="verify against an independently trusted commitment")
    v.add_argument("commitment")
    v.add_argument("opening")
    v.add_argument("--index", type=int, required=True)
    v.add_argument("--message", help="optional expected UTF-8 message")
    a = parser.parse_args(argv)
    try:
        if a.command == "commit":
            paths = [Path(p).resolve() for p in (a.input, a.public, a.state)]
            if len(set(paths)) != 3:
                raise ValueError("input, public output and private state must be different paths")
            if any(p.exists() for p in paths[1:]):
                raise ValueError("output already exists; choose new filenames")
            values = read_json(a.input)
            if type(values) is not list or any(type(x) is not str for x in values):
                raise ValueError("input must be a JSON list of strings")
            messages = [bytes.fromhex(x) if a.hex else x.encode("utf-8") for x in values]
            tree = MerkleCommitment(messages, a.suite)
            write_new_json(a.state, state_to_dict(tree))
            write_new_json(a.public, commitment_to_dict(tree.commitment))
            print(json.dumps(commitment_to_dict(tree.commitment), ensure_ascii=False))
        elif a.command == "open":
            tree = state_from_dict(read_json(a.state))
            proof = tree.open(a.index)
            write_new_json(a.out, opening_to_dict(proof))
            print(f"opened index={a.index}; compact proof bytes={proof.binary_size}")
        else:
            commitment = commitment_from_dict(read_json(a.commitment))
            proof = opening_from_dict(read_json(a.opening))
            valid = verify(commitment, proof, expected_index=a.index,
                           expected_message=None if a.message is None else a.message.encode("utf-8"))
            print(json.dumps({"valid": valid, "index": proof.index,
                              "message_hex": proof.message.hex()}, ensure_ascii=False))
            return 0 if valid else 1
    except (ValueError, TypeError, OSError, UnicodeError, RecursionError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
