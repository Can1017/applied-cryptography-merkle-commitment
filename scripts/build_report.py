"""Build the Chinese Markdown report, printable HTML, and data-driven figure.

Optional presentation-only packages: matplotlib and markdown. No cryptographic
computation or third-party hash implementation is involved in this script.
"""

from datetime import datetime
import base64
import html
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
TITLE = "Merkle树承诺方案设计与安全性分析"


def load(name):
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def table(headers, rows):
    return "\n".join(["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
                     + ["| " + " | ".join(map(str, row)) + " |" for row in rows])


def make_figure(data):
    from build_figures import setup, BLUE, ORANGE
    plt = setup()
    plt.rcParams.update({"font.size": 10,
                         "axes.spines.top": False, "axes.spines.right": False,
                         "svg.fonttype": "path", "svg.hashsalt": "MTC1-coursework"})
    fig, axes = plt.subplots(1, 2, figsize=(11.6, 4.4), constrained_layout=True)
    colors = {"sha256": BLUE, "sha3-256": ORANGE}
    for suite, color in colors.items():
        rows = [r for r in data["trees"] if r["suite"] == suite]
        xs = [r["n"] for r in rows]
        for axis, key in zip(axes, ("commit", "verify")):
            ys = [r[key]["median_ms"] for r in rows]
            axis.plot(xs, ys, marker="o", markersize=4, color=color,
                      label="SHA-256" if suite == "sha256" else "SHA3-256")
            axis.fill_between(xs, [r[key]["min_ms"] for r in rows],
                              [r[key]["max_ms"] for r in rows], alpha=0.12, color=color)
            axis.set_xscale("log", base=2)
            axis.set_xlabel("真实叶子数量 n")
            axis.set_ylabel("耗时（ms）")
            axis.grid(True, alpha=0.20)
    axes[0].set_yscale("log")
    axes[0].set_title("建树 Commit（含新随机数生成）", loc="left", weight="bold")
    axes[1].set_title("单点验证 Verify（缓存树接口）", loc="left", weight="bold")
    axes[0].legend(frameon=False)
    axes[1].legend(frameon=False)
    folder = ROOT / "docs" / "figures"
    folder.mkdir(exist_ok=True)
    fig.savefig(folder / "merkle_scaling.png", dpi=220, facecolor="white")
    fig.savefig(folder / "merkle_scaling.svg", facecolor="white", metadata={"Date": None})
    svg = folder / "merkle_scaling.svg"
    svg.write_text("\n".join(line.rstrip() for line in svg.read_text(encoding="utf-8").splitlines()) + "\n",
                   encoding="utf-8")
    plt.close(fig)


def main():
    import markdown
    from build_figures import main as build_figures
    from build_guide import make_path_figure
    results = load("results/benchmark.json")
    tests = load("results/tests.json")
    attacks = load("results/security_demo.json")
    refs = load("research/references-verified.json")
    if not tests["success"]:
        raise RuntimeError("refusing to build a report from failed tests")
    if results["method"]["repeats"] != 5 or max(r["n"] for r in results["trees"]) != 4096:
        raise RuntimeError("report text requires the full five-repeat n<=4096 benchmark")
    make_figure(results)
    build_figures()
    make_path_figure()
    selected = (46, 55, 56, 70, 94, 119, 120, 135, 136, 137, 1024, 65536)
    lookup = {(r["suite"], r["input_bytes"]): r for r in results["hashes"]}
    hash_rows = []
    for n in selected:
        a, b = lookup["sha256", n], lookup["sha3-256", n]
        hash_rows.append([n, f"{a['median_ms']:.4f}", f"{b['median_ms']:.4f}",
                          f"{b['median_ms']/a['median_ms']:.2f}"])
    tree_rows = []
    for r in results["trees"]:
        tree_rows.append([r["suite"], r["n"], r["capacity"],
                          f"{r['commit']['median_ms']:.3f}",
                          f"{r['open']['median_ms']*1000:.2f}",
                          f"{r['verify']['median_ms']:.3f}", r["opening_binary_bytes"]])
    tree_lookup = {(r["suite"], r["n"]): r for r in results["trees"]}
    a, b = tree_lookup["sha256", 4096], tree_lookup["sha3-256", 4096]
    diagnostic_path = ROOT / "results" / "benchmark_diagnostic.json"
    diagnostic_text = ""
    if diagnostic_path.exists():
        diagnostic = load("results/benchmark_diagnostic.json")
        extra = {r["n"]: r for r in diagnostic["rows"] if r["suite"] == "sha3-256"}
        diagnostic_text = (
            f"\n\n针对原始测量中 SHA3-256 在 n=257 时验证反而更快的异常，另外执行了 "
            f"5 轮、每轮 40 次的局部复测。n=256 与 n=257 的中位数分别为 "
            f"{extra[256]['verify']['median_ms']:.3f} ms 和 {extra[257]['verify']['median_ms']:.3f} ms。"
            "复测与主测存在明显差异，说明当时的执行环境并不稳定；没有采集 CPU 频率或调度跟踪，不能确定具体原因。"
            "原始数据未被替换，复测单列于 results/benchmark_diagnostic.json，可用 scripts/timing_diagnostic.py 重现。"
            "所以本文仅将复杂度和总体趋势作为可解释结论，不把个别点或小幅比值当作稳定常数。")
    env = results["environment"]
    substitutions = {
        "TEST_RESULTS": table(["项目", "实测结果"], [
            ["测试方法数", tests["test_methods"]], ["失败与错误", f"{tests['failures']} / {tests['errors']}"],
            ["NIST 已知答案总数", tests["nist_total"]], ["附加标准示例", tests["additional_fips_examples"]],
            ["测试运行时间", f"{tests['elapsed_seconds']:.3f} 秒"],
            ["原始证据", "results/tests.txt 与 results/tests.json"]]),
        "SECURITY_RESULTS": table(["实验", "观察结果"], [
            ["不加随机数的成绩承诺", "枚举第 74 个候选恢复 73"],
            ["提前公开随机数", "枚举第 74 个候选恢复 73"],
            ["每叶共用随机数并打开一叶", "利用该随机数和兄弟叶摘要恢复 73"],
            ["不同叶随机数，用已公开的另一个随机数猜测", "101 个候选均未匹配；仅为受限负对照"],
            ["将随机数减为 8 位", f"{attacks['weak_8_bit_salt']['hash_queries']} 次查询恢复消息 73 和随机数 19"],
            ["复制末尾的朴素树", "[A,B,C] 与 [A,B,C,C] 根相同"],
            ["MTC1 对同样两组向量", "根摘要不同"],
            ["篡改开口消息", "验证拒绝"]]),
        "ENVIRONMENT": table(["环境项", "记录值"], [
            ["CPU", env["cpu"]], ["操作系统平台标识", env["platform"]],
            ["Python", env["python"].replace("|", "/")], ["逻辑 CPU 数", env["logical_cpus"]],
            ["进程数", 1], ["测量时间 UTC", results["timestamp_utc"]]]),
        "HASH_RESULTS": table(["输入字节数", "SHA-256 ms", "SHA3-256 ms", "SHA3 与 SHA-256 耗时比"], hash_rows),
        "HASH_INTERPRETATION": (
            f"在内部节点的 70 字节输入上，SHA3-256 的中位耗时约为 SHA-256 的 "
            f"{lookup['sha3-256',70]['median_ms']/lookup['sha256',70]['median_ms']:.2f} 倍；"
            f"在真实 32 字节消息对应的 94 字节叶子输入上，约为 "
            f"{lookup['sha3-256',94]['median_ms']/lookup['sha256',94]['median_ms']:.2f} 倍。"
            "这支持本实现选择 SHA-256。55→56、119→120 和 135→136 字节附近分别涉及不同算法的额外压缩或吸收块；"
            "实际跳变还叠加系统噪声，不能将所有时间变化都归因于分组数。"),
        "TREE_RESULTS": table(["套件", "n", "填充后 p", "Commit ms", "Open μs", "Verify ms", "完整开口 B"], tree_rows),
        "TREE_INTERPRETATION": (
            f"4096 叶子时，SHA-256 与 SHA3-256 的建树中位耗时分别为 "
            f"{a['commit']['median_ms']/1000:.3f} 秒和 {b['commit']['median_ms']/1000:.3f} 秒，"
            f"后者约为前者 {b['commit']['median_ms']/a['commit']['median_ms']:.2f} 倍。"
            f"对应单点验证分别为 {a['verify']['median_ms']:.3f} ms 和 {b['verify']['median_ms']:.3f} ms。"
            "缓存开口只复制路径摘要，不重新做密码哈希，所以耗时远低于验证。"
            "建树总体随填充后容量增长，而验证随树高增长；个别规模的测量并不单调，不能隐藏或平滑掉这些噪声。"
            "从 256 到 257 时缓存容量翻倍，额外填充叶子与内部节点解释了建树成本的明显上升。" + diagnostic_text),
        "REFERENCES": "\n\n".join(
            f"[{r['id']}] {r['authors']}. [{r['title']}]({r['doi_or_url']}). "
            f"{r['source']}" + (f", {r['year']}" if r['year'] else "")
            + f". 访问日期 {r['accessed']}。" for r in refs)
    }
    text = (ROOT / "docs" / f"{TITLE}.template.md").read_text(encoding="utf-8")
    for key, value in substitutions.items():
        text = text.replace("{{" + key + "}}", value)
    if re.search(r"\{\{[A-Z_]+\}\}", text):
        raise RuntimeError("unresolved report placeholder")
    (ROOT / "docs" / f"{TITLE}.md").write_text(text, encoding="utf-8")
    converter = markdown.Markdown(extensions=["tables", "fenced_code", "toc"],
                                  extension_configs={"toc": {"toc_depth": "2-3"}})
    body = converter.convert(text)
    def embed(match):
        path = ROOT / "docs" / match.group(1)
        mime = "image/svg+xml" if path.suffix == ".svg" else "image/png"
        encoded = base64.b64encode(path.read_bytes()).decode("ascii")
        return f'src="data:{mime};base64,{encoded}"'
    body = re.sub(r'src="(figures/[^"<>]+)"', embed, body)
    # Citations become local anchors without modifying code blocks or source URLs.
    body = re.sub(r"<p>\[(\d+)\] ", r'<p id="ref-\1">[\1] ', body)
    ref_ids = {str(r["id"]) for r in refs}
    body = re.sub(r"\[(\d+)\](?!\s*</a>)", lambda m:
                  f'<a href="#ref-{m[1]}" class="cite">[{m[1]}]</a>' if m[1] in ref_ids else m[0], body)
    css = """
@page { size: A4; margin: 19mm 19mm 20mm; }
* { box-sizing: border-box; }
body { margin: 0; background: #f0f2f4; color: #1d252d;
 font: 16px/1.85 'Microsoft YaHei','Noto Sans CJK SC','SimSun',sans-serif; }
main { max-width: 1030px; margin: 32px auto; padding: 48px 62px 70px; background: white; }
h1 { font-size: 30px; line-height: 1.45; margin: 0 0 22px; color: #000; }
h2 { font-size: 23px; margin-top: 44px; color: #000; line-height: 1.5; }
h3 { font-size: 18px; margin-top: 28px; color: #000; }
p { margin: 12px 0; text-align: justify; overflow-wrap: anywhere; }
a { color: #185783; text-decoration: none; overflow-wrap: anywhere; }
code { font-family: Consolas,'Microsoft YaHei',monospace; font-size: .88em; }
p code,li code,td code { background: #f1f3f5; padding: 1px 4px; }
pre { padding: 15px 18px; border: 1px solid #d9dfe5; background: #f7f8fa;
 line-height: 1.65; white-space: pre-wrap; overflow-wrap: anywhere; }
table { border-collapse: collapse; width: 100%; margin: 18px 0 24px; font-size: 13px; line-height: 1.65; }
td,th { border: 1px solid #d9d9d9; padding: 9px 10px; vertical-align: middle; overflow-wrap: anywhere; }
th { text-align: left; background: #e6eef4; color: #111; }
tbody tr:nth-child(even) { background: #fafbfd; }
img { width: 100%; height: auto; }
.toc { padding: 4px 0 18px; font-size: 14px; columns: 2; column-gap: 40px; }
.toc ul { padding-left: 20px; }
.toc li { break-inside: avoid; }
details { margin: 24px 0; }
summary { cursor: pointer; font-weight: 600; }
.cite { font-size: .9em; }
@media(max-width: 800px) { main { padding: 25px 20px; margin: 0; } .toc { columns: 1; }
 table { font-size: 11px; } td,th { padding: 6px; } h1 { font-size: 25px; } }
@media print { body { background: white; font-size: 10.5pt; line-height: 1.65; }
 main { margin: 0; padding: 0; max-width: none; } details { display: none; }
 h1 { font-size: 20pt; } h2 { font-size: 15pt; } h3 { font-size: 12pt; }
 h1,h2,h3 { break-after: avoid; } tr,pre,img { break-inside: avoid; }
 thead { display: table-header-group; } table { font-size: 8.5pt; }
 td,th { padding: 5px 6px; } a { color: inherit; } p { orphans: 3; widows: 3; } }
"""
    document = (f'<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
                f'<meta name="viewport" content="width=device-width, initial-scale=1">'
                f'<title>{TITLE}</title><link rel="icon" href="data:,"><style>{css}</style></head><body><main>'
                f'<details><summary>目录</summary>{converter.toc}</details>{body}</main></body></html>')
    (ROOT / "docs" / f"{TITLE}.html").write_text(document, encoding="utf-8")
    mapping = {"figures": [
        {"number": "4-1", "name": "protocol_workflow", "section": "4.1", "source": "MTC1 specification", "generator": "scripts/build_figures.py"},
        {"number": "4-2", "name": "guide_merkle_path", "section": "4.4", "source": "three-leaf example", "generator": "scripts/build_guide.py"},
        {"number": "6-1", "name": "project_architecture", "section": "6.1", "source": "src/ module responsibilities", "generator": "scripts/build_figures.py"},
        {"number": "7-1", "name": "hash_node_cost", "section": "7.4", "source": "results/benchmark.json", "generator": "scripts/build_figures.py"},
        {"number": "7-2", "name": "merkle_scaling", "section": "7.5", "source": "results/benchmark.json", "generator": "scripts/build_report.py"},
    ]}
    (ROOT / "docs" / "image-map.json").write_text(json.dumps(mapping, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote Markdown, HTML, PNG and SVG. Report characters: {len(text)}")


if __name__ == "__main__":
    main()
