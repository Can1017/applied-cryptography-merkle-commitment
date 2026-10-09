"""Bundle the reviewable coursework; excludes generated HTML/templates and local files."""

import json
from pathlib import Path
import sys
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.hashes import sha256

manifest = {"algorithm": "self-implemented SHA-256 in src/hashes.py",
            "purpose": "record the delivered source revision, not an independent correctness oracle",
            "files": {}}
for folder in ("src", "tests", "scripts"):
    for source in sorted((ROOT / folder).glob("*.py")):
        manifest["files"][source.relative_to(ROOT).as_posix()] = sha256(source.read_bytes()).hex()
(ROOT / "results" / "source_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

archive = ROOT / "应用密码学第一次作业_Merkle树承诺.zip"
files = [ROOT / "README.md", ROOT / ".gitignore", ROOT / ".gitattributes",
         ROOT / "requirements-docs.txt"]
for folder in ("src", "tests", "scripts", "docs", "research", "results", "examples", ".github"):
    for path in (ROOT / folder).rglob("*"):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        if path.suffix in (".zip", ".pyc", ".html") or path.name.endswith(".template.md"):
            continue
        if folder == "results" and path.suffix in (".png", ".yml", ".log"):
            continue
        files.append(path)
with ZipFile(archive, "w", compression=ZIP_DEFLATED, compresslevel=9) as zipped:
    for path in sorted(files):
        zipped.write(path, path.relative_to(ROOT).as_posix())
with ZipFile(archive) as zipped:
    bad = zipped.testzip()
    if bad is not None:
        raise RuntimeError(f"damaged archive member: {bad}")
    names = zipped.namelist()
    required = {"src/hashes.py", "src/merkle.py", "tests/vectors/SHA256ShortMsg.rsp",
                "tests/vectors/SHA3_256LongMsg.rsp", "results/tests.json", "results/benchmark.json",
                "docs/Merkle树承诺方案设计与安全性分析.md",
                "docs/Merkle树承诺作业详细说明与代码导读.md"}
    if not required.issubset(names):
        raise RuntimeError("missing required submission members")
print(f"Packaged {len(names)} files; {archive.stat().st_size:,} bytes")
print(archive.name)
