"""Extract only official NIST .rsp DATA files; no reference code is used."""

from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
for archive, members in (
    ("shabytetestvectors.zip", ("SHA256ShortMsg.rsp", "SHA256LongMsg.rsp")),
    ("sha-3bytetestvectors.zip", ("SHA3_256ShortMsg.rsp", "SHA3_256LongMsg.rsp")),
):
    with ZipFile(ROOT / "research" / archive) as zipped:
        for name in members:
            matches = [m for m in zipped.namelist() if m.rsplit("/", 1)[-1] == name]
            if len(matches) != 1:
                raise ValueError(f"ambiguous or missing data file: {name}")
            target = ROOT / "tests" / "vectors" / name
            target.write_bytes(zipped.read(matches[0]))
            print(f"extracted {name}: {target.stat().st_size} bytes")
