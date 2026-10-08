"""Restricted-source import/call review, not a proof about all Python internals."""

import ast
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
STANDARD_ALLOWED = {"argparse", "dataclasses", "json", "pathlib", "secrets", "sys"}
LOCAL_ALLOWED = {"hashes", "merkle", "codec"}
FORBIDDEN_CALLS = {"eval", "exec", "__import__", "compile"}
imports = {}
issues = []
for path in sorted((ROOT / "src").glob("*.py")):
    parsed = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports[path.name] = []
    for node in ast.walk(parsed):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[path.name].append(alias.name)
                if alias.name.split(".")[0] not in STANDARD_ALLOWED:
                    issues.append(f"{path.name}:{node.lineno}: unexpected import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            imports[path.name].append(("." * node.level) + (node.module or ""))
            allowed = LOCAL_ALLOWED if node.level else STANDARD_ALLOWED
            if root not in allowed:
                issues.append(f"{path.name}:{node.lineno}: unexpected import {node.module}")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in FORBIDDEN_CALLS:
                issues.append(f"{path.name}:{node.lineno}: dynamic execution")
report = {"scope": "src/*.py", "core_imports": imports, "issues": issues,
          "passed": not issues,
          "manual_review": "Digest and Merkle calculations are local arithmetic/byte operations; secrets.token_bytes supplies OS randomness only.",
          "limit": "AST allowlist is an implementation audit aid, not a security proof or a transitive stdlib audit."}
(ROOT / "results" / "dependency_audit.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
print(json.dumps(report, indent=2))
raise SystemExit(1 if issues else 0)
