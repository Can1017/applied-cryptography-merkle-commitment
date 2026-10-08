"""Write reproducible test evidence including executed NIST vector counts."""

import io
import json
from pathlib import Path
import platform
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.vector_loader import load_vectors

stream = io.StringIO()
suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
started = time.perf_counter()
result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
elapsed = time.perf_counter() - started
text = stream.getvalue()
output = ROOT / "results"
output.mkdir(exist_ok=True)
(output / "tests.txt").write_text(text, encoding="utf-8")
counts = {p.name: len(list(load_vectors(p.name))) for p in (ROOT / "tests" / "vectors").glob("*.rsp")}
summary = {"python": sys.version, "platform": platform.platform(),
           "test_methods": result.testsRun, "failures": len(result.failures),
           "errors": len(result.errors), "success": result.wasSuccessful(),
           "elapsed_seconds": elapsed, "nist_vector_counts": counts,
           "nist_total": sum(counts.values()), "additional_fips_examples": 3,
           "external_hash_oracles_used": False}
(output / "tests.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
print(text)
raise SystemExit(0 if result.wasSuccessful() else 1)
