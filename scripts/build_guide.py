"""Render the learning guide from its prose template, current code and saved evidence.

Optional rendering dependency: Python-Markdown. Figures are SVG or embedded local
assets. Crypto in the worked example uses only this project's own implementation.
"""

import ast
import base64
import html
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.merkle import MerkleCommitment, leaf_hash, parent_hash, finalize, depth, verify
from src.codec import opening_to_bytes, commitment_to_bytes

TITLE = "Merkle树承诺作业详细说明与代码导读"


def read_json(name):
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def table(headers, rows):
    return "\n".join(["| " + " | ".join(headers) + " |",
                      "| " + " | ".join("---" for _ in headers) + " |"]
                     + ["| " + " | ".join(str(x).replace("|", "/") for x in row) + " |"
                        for row in rows])


def source_node(path, qualified_name):
    source = (ROOT / path).read_text(encoding="utf-8")
    body = ast.parse(source).body
    node = None
    for part in qualified_name.split("."):
        candidates = [n for n in body if isinstance(n, (ast.ClassDef, ast.FunctionDef)) and n.name == part]
        if len(candidates) != 1:
            raise ValueError(f"missing or ambiguous source target: {path}::{qualified_name}")
        node = candidates[0]
        body = node.body
    return source, node


def snippet(path, name):
    source, node = source_node(path, name)
    lines = source.splitlines()[node.lineno - 1:node.end_lineno]
    prefix = len(lines[0]) - len(lines[0].lstrip())
    code = "\n".join(line[prefix:] if line.strip() else "" for line in lines)
    return f"源码位置：`{path}`，第 {node.lineno} 行起。\n\n```python\n{code}\n```"


def make_path_figure():
    colors = {"blue": ("#eef5fb", "#245e91"), "orange": ("#fff3e7", "#a75a17"),
              "gray": ("#f5f6f7", "#68747e")}
    nodes = {
        "c": (500, 64, "公共承诺 c", "Final(n, T)", "blue"),
        "t": (500, 172, "内部树根 T", "Node(N₀₁, N₂₃)", "blue"),
        "left": (265, 290, "N₀₁", "Node(L₀, L₁)", "blue"),
        "right": (735, 290, "N₂₃", "第二个兄弟摘要", "orange"),
        "l0": (140, 416, "L₀", "第一个兄弟摘要", "orange"),
        "l1": (380, 416, "L₁", "从 Bob 与 r₁ 重算", "blue"),
        "l2": (620, 416, "L₂", "Carol 的叶摘要", "gray"),
        "p3": (860, 416, "P₃", "公开填充位置", "gray"),
    }
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="1000" height="560" viewBox="0 0 1000 560" role="img" aria-label="三叶 Merkle 树打开 Bob 的路径">',
             '<rect width="1000" height="560" fill="white"/>',
             '<style>text{font-family:"Microsoft YaHei","Noto Sans CJK SC",sans-serif;fill:#172735}.title{font-size:20px;font-weight:600}.small{font-size:15px}.legend{font-size:16px}</style>']
    for child, parent, color in (("l0", "left", "orange"), ("l1", "left", "blue"),
                                 ("l2", "right", "gray"), ("p3", "right", "gray"),
                                 ("left", "t", "blue"), ("right", "t", "orange"), ("t", "c", "blue")):
        x1, y1 = nodes[child][:2]
        x2, y2 = nodes[parent][:2]
        dash = ' stroke-dasharray="6 5"' if color == "gray" else ""
        parts.append(f'<path d="M{x1},{y1-35} L{x2},{y2+35}" fill="none" stroke="{colors[color][1]}" stroke-width="2.5"{dash}/>')
    for x, y, title, subtitle, color in nodes.values():
        fill, stroke = colors[color]
        parts.extend([f'<rect x="{x-103}" y="{y-35}" width="206" height="70" rx="5" fill="{fill}" stroke="{stroke}" stroke-width="1.8"/>',
                      f'<text class="title" x="{x}" y="{y-6}" text-anchor="middle">{html.escape(title)}</text>',
                      f'<text class="small" x="{x}" y="{y+20}" text-anchor="middle">{html.escape(subtitle)}</text>'])
    for x, label in ((140, "i = 0"), (380, "i = 1 目标位置"), (620, "i = 2"), (860, "i = 3 填充")):
        parts.append(f'<text class="small" x="{x}" y="474" text-anchor="middle">{label}</text>')
    for x, color, label in ((145, "blue", "验证者重算"), (410, "orange", "证明提供"), (655, "gray", "未打开的结构")):
        parts.append(f'<rect x="{x}" y="510" width="18" height="18" fill="{colors[color][0]}" stroke="{colors[color][1]}"/>')
        parts.append(f'<text class="legend" x="{x+28}" y="525">{label}</text>')
    parts.append("</svg>")
    target = ROOT / "docs/figures/guide_merkle_path.svg"
    target.parent.mkdir(exist_ok=True)
    target.write_text("\n".join(parts), encoding="utf-8")


def embed_images(body):
    def replace(match):
        rel = match.group(1)
        path = (ROOT / "docs" / rel).resolve()
        if not path.is_relative_to((ROOT / "docs").resolve()):
            raise ValueError("image path outside document folder")
        mime = "image/svg+xml" if path.suffix == ".svg" else "image/png"
        data = base64.b64encode(path.read_bytes()).decode("ascii")
        return f'src="data:{mime};base64,{data}"'
    return re.sub(r'src="(figures/[^"<>]+)"', replace, body)


def main():
    import markdown
    from build_figures import main as build_figures
    tests = read_json("results/tests.json")
    benchmark = read_json("results/benchmark.json")
    diagnostic = read_json("results/benchmark_diagnostic.json")
    attacks = read_json("results/security_demo.json")
    demo = read_json("results/demo.json")
    refs = read_json("research/references-verified.json")
    if not tests["success"] or tests["test_methods"] != 23 or tests["nist_total"] != 366:
        raise ValueError("guide narrative requires the documented successful 23-method / 366-vector run")
    if benchmark["method"]["repeats"] != 5 or max(r["n"] for r in benchmark["trees"]) != 4096:
        raise ValueError("guide narrative requires the full five-repeat n<=4096 benchmark")
    make_path_figure()
    build_figures()
    fixed_rows = []
    for row in demo["fixed"]:
        tree = MerkleCommitment._restore([b"Alice", b"Bob", b"Carol"], row["suite"],
                                         [i.to_bytes(32, "big") for i in range(3)])
        if tree.commitment.digest.hex() != row["commitment"]["digest_hex"]:
            raise ValueError("saved fixed example no longer agrees with the implementation")
        if not verify(tree.commitment, tree.open(1), expected_index=1, expected_message=b"Bob"):
            raise ValueError("worked example failed verification")
        fixed_rows.append([row["suite"], "`" + tree.commitment.digest.hex() + "`"])
    tree = MerkleCommitment._restore([b"Alice", b"Bob", b"Carol"], "sha256",
                                     [i.to_bytes(32, "big") for i in range(3)])
    proof = tree.open(1)
    if len(opening_to_bytes(proof)) != 116 or len(commitment_to_bytes(tree.commitment)) != 45:
        raise ValueError("worked example byte sizes changed")
    value = leaf_hash("sha256", 3, 1, proof.message, proof.salt)
    trace = [["1 目标叶子 L₁", "`" + value.hex() + "`"]]
    value = parent_hash("sha256", proof.siblings[0], value)
    trace.append(["2 父节点 N₀₁", "`" + value.hex() + "`"])
    value = parent_hash("sha256", value, proof.siblings[1])
    trace.append(["3 内部树根 T", "`" + value.hex() + "`"])
    value = finalize("sha256", 3, value)
    trace.append(["4 公开摘要 c", "`" + value.hex() + "`"])
    if value != tree.commitment.digest:
        raise ValueError("manual walkthrough does not reproduce commitment")
    targets = [
        ("src/cli.py", "main", "命令行分支与退出码"),
        ("src/merkle.py", "Commitment", "公共承诺对象"),
        ("src/merkle.py", "Opening", "消息与认证路径"),
        ("src/merkle.py", "MerkleCommitment.__init__", "校验并采样独立随机数"),
        ("src/merkle.py", "MerkleCommitment._restore", "复用保存的私有状态"),
        ("src/merkle.py", "MerkleCommitment._build", "构造并缓存各层"),
        ("src/merkle.py", "MerkleCommitment.open", "取出单点路径"),
        ("src/merkle.py", "verify", "独立验证单点开口"),
        ("src/merkle.py", "verify_all", "验证完整打开"),
        ("src/codec.py", "state_from_dict", "严格恢复私有状态"),
        ("src/codec.py", "opening_to_bytes", "紧凑开口编码"),
        ("src/codec.py", "read_json", "限制大小及拒绝重复键"),
        ("src/hashes.py", "sha256", "SHA-256 一次性摘要"),
        ("src/hashes.py", "_keccak_f1600", "Keccak 24 轮置换"),
        ("src/hashes.py", "sha3_256", "SHA3 吸收与输出"),
    ]
    function_rows = [[f"`{p}:{source_node(p,n)[1].lineno}`", f"`{n}`", note] for p,n,note in targets]
    original = {(r["suite"], r["n"]): r for r in benchmark["trees"]}
    perf_rows = [[r["suite"], r["n"], f"{r['commit']['median_ms']:.3f}",
                  f"{r['open']['median_ms']*1000:.3f}", f"{r['verify']['median_ms']:.3f}",
                  r["opening_binary_bytes"]] for r in benchmark["trees"] if r["n"] in (256,257,1024,4096)]
    diagnosed = {r["n"]: r for r in diagnostic["rows"] if r["suite"] == "sha3-256"}
    env = benchmark["environment"]
    substitutions = {
        "DEPTH_TABLE": table(["真实叶数 n", "树高 h", "容量 p", "填充数量", "路径摘要数"],
                             [[n, depth(n), 1 << depth(n), (1 << depth(n))-n,
                               "无合法单点开口" if n==0 else depth(n)] for n in (0,1,2,3,5,256,257)]),
        "FIXED_COMMITMENTS": table(["套件", "固定测试样例的公开摘要 c"], fixed_rows),
        "FIXED_OPENING": "```json\n" + json.dumps(demo["fixed"][0]["opening"], ensure_ascii=False, indent=2) + "\n```",
        "TRACE_TABLE": table(["复算步骤", "所得摘要的完整十六进制"], trace),
        "FUNCTION_INDEX": table(["文件与起始行", "函数或对象", "首先关注的问题"], function_rows),
        "BUILD_SOURCE": snippet("src/merkle.py", "MerkleCommitment._build"),
        "OPEN_SOURCE": snippet("src/merkle.py", "MerkleCommitment.open"),
        "VERIFY_SOURCE": snippet("src/merkle.py", "verify"),
        "TEST_SUMMARY": table(["结果字段", "保存值", "含义"], [
            ["test_methods", tests["test_methods"], "测试方法数量"],
            ["success", str(tests["success"]).lower(), "所有测试通过"],
            ["failures / errors", f"{tests['failures']} / {tests['errors']}", "断言失败及异常数"],
            ["nist_total", tests["nist_total"], "四个向量文件的已知答案总数"],
            ["additional_fips_examples", tests["additional_fips_examples"], "另行列出的标准示例"],
            ["elapsed_seconds", f"{tests['elapsed_seconds']:.3f}", "保存该日志的那一轮测试耗时"]]),
        "ATTACK_SUMMARY": table(["结果键", "保存值", "解释"], [
            ["unsalted_dictionary.recovered", attacks["unsalted_dictionary"]["recovered"], "无随机数时恢复成绩"],
            ["public_salt_dictionary.recovered", attacks["public_salt_dictionary"]["recovered"], "公开随机数不能消除枚举"],
            ["shared_salt_after_one_opening.recovered", attacks["shared_salt_after_one_opening"]["recovered"], "共享随机数打开后泄露其他低熵叶子"],
            ["weak_8_bit_salt.hash_queries", attacks["weak_8_bit_salt"]["hash_queries"], "小随机数空间可以穷举"],
            ["duplicate_tail_naive_roots_equal", str(attacks["duplicate_tail_naive_roots_equal"]).lower(), "朴素末尾复制有结构歧义"],
            ["duplicate_tail_mtc1_roots_equal", str(attacks["duplicate_tail_mtc1_roots_equal"]).lower(), "本方案这两组输入的根不同"]]),
        "ENV_SUMMARY": table(["环境项", "保存值"], [["CPU",env["cpu"]],["Python",env["python"]],
                            ["系统平台标识",env["platform"]],["基准时间 UTC",benchmark["timestamp_utc"]],
                            ["重复次数",benchmark["method"]["repeats"]]]),
        "PERFORMANCE_SUMMARY": table(["套件","n","Commit ms","Open μs","Verify ms","开口 B"],perf_rows),
        "TIMING_DIAGNOSTIC": (
            f"原始数据中，SHA3-256 在 n=256 时验证中位数为 {original['sha3-256',256]['verify']['median_ms']:.3f} ms，"
            f"n=257 时反而为 {original['sha3-256',257]['verify']['median_ms']:.3f} ms。"
            f"另一次局部复测分别得到 {diagnosed[256]['verify']['median_ms']:.3f} ms 和 "
            f"{diagnosed[257]['verify']['median_ms']:.3f} ms。模型上的调用次数是 10→11，并没有减少，"
            "因此不能从主基准的下降点推导出 257 叶子更容易验证。主基准和复测分别存放，保留了不稳定性的证据。"),
        "REFERENCES": "\n\n".join(
            f'<a id="ref-r{r["id"]}"></a>\n\n**R{r["id"]}** {r["authors"]}. '
            f'[{r["title"]}]({r["doi_or_url"]}). '
            f'查看范围：{r["checked_sections"]}。访问日期：{r["accessed"]}。' for r in refs),
    }
    text = (ROOT / "docs" / f"{TITLE}.template.md").read_text(encoding="utf-8")
    for key, value in substitutions.items():
        text = text.replace("{{" + key + "}}", value)
    if re.search(r"\{\{[A-Z_]+\}\}", text):
        raise ValueError("unresolved placeholder")
    # Only expand explicitly marked R references; never reinterpret numeric code indexes.
    def citation(match):
        ids = []
        for part in match.group(1).replace("R", "").split(","):
            bounds = re.split("[–-]", part)
            ids.extend(range(int(bounds[0]),int(bounds[-1])+1))
        if any(i < 1 or i > len(refs) for i in ids):
            raise ValueError("unknown reference")
        return "（" + "、".join(f"[R{i}](#ref-r{i})" for i in ids) + "）"
    text = re.sub(r"\[R([0-9R,–-]+)\]", citation, text)
    md_path = ROOT / "docs" / f"{TITLE}.md"
    md_path.write_text(text, encoding="utf-8")
    converter = markdown.Markdown(extensions=["tables", "fenced_code", "toc"],
                                  extension_configs={"toc":{"toc_depth":"2-3"}})
    body = embed_images(converter.convert(text))
    css = """
@page { size:A4; margin:19mm; }
* { box-sizing:border-box; }
html { scroll-behavior:smooth; }
body { margin:0; background:#f1f3f5; color:#202b35; font:16px/1.9 'Microsoft YaHei','Noto Sans CJK SC',sans-serif; }
main { max-width:1080px; margin:30px auto; padding:45px 62px 64px; background:#fff; }
h1,h2,h3 { color:#000; line-height:1.5; }
h1 { font-size:29px; margin:0 0 20px; }
h2 { font-size:23px; margin:44px 0 18px; }
h3 { font-size:18px; margin:28px 0 14px; }
p { margin:13px 0; overflow-wrap:anywhere; text-align:justify; }
a { color:#205e8a; text-decoration:none; overflow-wrap:anywhere; }
li { margin:4px 0; overflow-wrap:anywhere; }
pre { border:1px solid #d9dfe5; background:#f7f9fa; padding:15px 18px; line-height:1.65;
      white-space:pre-wrap; overflow-wrap:anywhere; tab-size:4; }
code { font-family:Consolas,'Microsoft YaHei',monospace; font-size:.9em; }
td code,p code,li code { background:#f2f4f6; padding:1px 3px; }
table { width:100%; border-collapse:collapse; margin:20px 0 25px; font-size:13px; line-height:1.7; }
th,td { border:1px solid #d9d9d9; padding:9px 11px; vertical-align:middle; overflow-wrap:anywhere; }
th { text-align:left; background:#e8eff4; color:#111; }
tbody tr:nth-child(even) { background:#fafbfd; }
img { display:block; max-width:100%; height:auto; margin:auto; }
details { margin:22px 0; padding:12px 0; }
summary { cursor:pointer; font-weight:600; }
.toc { columns:2; column-gap:35px; font-size:13px; }
.toc ul { padding-left:20px; }
.toc li { break-inside:avoid; }
@media(max-width:800px) { main { padding:26px 20px; margin:0; } .toc { columns:1; }
 h1 { font-size:25px; } table { font-size:11px; } td,th { padding:7px; } }
@media print { body { background:white; font-size:10.5pt; line-height:1.65; } main { margin:0; padding:0; }
 h1 { font-size:20pt; } h2 { font-size:15pt; } h3 { font-size:12pt; } h1,h2,h3 { break-after:avoid; }
 table { font-size:8.5pt; } td,th { padding:5px 6px; } thead { display:table-header-group; }
 tr,img { break-inside:avoid; } pre { font-size:9pt; } p { widows:3; orphans:3; }
 details { display:none; } a { color:inherit; } }
"""
    heading_end = body.index("</h1>") + len("</h1>")
    body = body[:heading_end] + f'<details><summary>章节导航</summary>{converter.toc}</details>' + body[heading_end:]
    document = (f'<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
                f'<meta name="viewport" content="width=device-width, initial-scale=1">'
                f'<title>{TITLE}</title><link rel="icon" href="data:,"><style>{css}</style>'
                f'</head><body><main>{body}</main></body></html>')
    (ROOT / "docs" / f"{TITLE}.html").write_text(document, encoding="utf-8")
    evidence = {"document":md_path.name,"characters":len(text),"top_level_sections":len(re.findall(r"^## ",text,re.M)),
                "source_targets":len(targets),"code_fragments_from_actual_source":3,
                "worked_example_verified":True,"fixed_sample_matches_saved_demo":True,
                "binary_commitment_bytes":45,"bob_opening_bytes":116,
                "nist_vectors_in_saved_evidence":tests["nist_total"],
                "html_images_embedded":len(re.findall(r'<img\b', body)),"references":len(refs),
                "performance_data":"existing results/benchmark.json; not rerun by this builder"}
    (ROOT / "results/guide_build_check.json").write_text(json.dumps(evidence,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps(evidence,ensure_ascii=False,indent=2))


if __name__ == "__main__":
    main()
