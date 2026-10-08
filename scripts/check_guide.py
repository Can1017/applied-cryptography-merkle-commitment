"""Local integrity and structural QA for the standalone learning guide."""

import base64
from html.parser import HTMLParser
import json
from pathlib import Path
import re
from urllib.parse import unquote
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
TITLE = "Merkle树承诺作业详细说明与代码导读"
DOCS = ROOT / "docs"


class Extract(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.local_refs = []
        self.images = []
        self.h2_count = 0

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if "id" in values:
            self.ids.add(values["id"])
        if tag == "h2":
            self.h2_count += 1
        if tag == "a" and values.get("href", "").startswith("#"):
            self.local_refs.append(unquote(values["href"][1:]))
        if tag == "img":
            self.images.append(values.get("src", ""))


md = (DOCS / f"{TITLE}.md").read_text(encoding="utf-8")
page = (DOCS / f"{TITLE}.html").read_text(encoding="utf-8")
evidence = json.loads((ROOT / "results/guide_build_check.json").read_text(encoding="utf-8"))
check = Extract()
check.feed(page)
assert len(md) == evidence["characters"]
assert not re.search(r"\{\{[A-Z_]+\}\}", md + page)
assert check.h2_count == evidence["top_level_sections"] == 18
assert not (set(check.local_refs) - check.ids), "unresolved local anchors"
assert len(check.images) == evidence["html_images_embedded"] == 4
assert not re.search(r'<img[^>]*src="figures/', page), "non-embedded figure in HTML"
for embedded in check.images:
    assert embedded.startswith("data:image/") and ";base64," in embedded
    header, encoded = embedded.split(",", 1)
    data = base64.b64decode(encoded, validate=True)
    if "svg+xml" in header:
        assert ET.fromstring(data).tag == "{http://www.w3.org/2000/svg}svg"
    else:
        assert data.startswith(b"\x89PNG\r\n\x1a\n")
for image in re.findall(r"!\[[^]]*\]\((figures/[^)]+)\)", md):
    assert (DOCS / image).is_file(), image
assert "正确性测试结果解读" in md and "性能结果与适用范围" in md
assert "D:\\研究生\\应用密码学" not in md + page
assert "D:\\PostGraduate\\应用密码学\\第一次作业" in md
assert "python -m src.cli verify" in md
assert "fixed" in md and "benchmark_diagnostic.json" in md
print(json.dumps({"sections":check.h2_count,"local_anchor_links":len(check.local_refs),
                  "embedded_valid_images":len(check.images),"characters":len(md),
                  "source_functions_indexed":evidence["source_targets"],
                  "worked_example_verified":evidence["worked_example_verified"]},ensure_ascii=False))
