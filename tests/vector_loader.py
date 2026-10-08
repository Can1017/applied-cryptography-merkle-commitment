from pathlib import Path


def load_vectors(name):
    record = {}
    for raw in (Path(__file__).parent / "vectors" / name).read_text(encoding="utf-8-sig").splitlines():
        if " = " not in raw or raw.startswith("#"):
            continue
        key, value = raw.split(" = ", 1)
        record[key] = value.strip()
        if key == "MD":
            bits = int(record["Len"])
            if bits % 8:
                raise ValueError("only byte-oriented messages are supported")
            # The NIST zero-length representation has Msg=00: it is NOT a byte.
            message = b"" if bits == 0 else bytes.fromhex(record["Msg"])
            if len(message) * 8 != bits:
                raise ValueError("bad vector length")
            yield message, bytes.fromhex(record["MD"])
            record = {}
