"""Reproducible protocol diagrams and a chart from saved benchmark data.

Matplotlib is used only for document presentation, never for cryptography.
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIGURES = ROOT / "docs" / "figures"
BLUE = "#245e91"
ORANGE = "#a75a17"
GRAY = "#68747e"
INK = "#172735"


def setup():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib import font_manager
    installed = {font.name for font in font_manager.fontManager.ttflist}
    families = [name for name in ("Microsoft YaHei", "Noto Sans CJK SC", "DejaVu Sans")
                if name in installed]
    plt.rcParams.update({
        "font.family": families,
        "font.size": 11, "axes.unicode_minus": False,
        "svg.fonttype": "path", "svg.hashsalt": "MTC1-coursework",
        "axes.spines.top": False, "axes.spines.right": False,
    })
    return plt


def save(fig, name):
    FIGURES.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURES / f"{name}.png", dpi=200, facecolor="white", bbox_inches="tight")
    fig.savefig(FIGURES / f"{name}.svg", facecolor="white", bbox_inches="tight",
                metadata={"Date": None})
    svg = FIGURES / f"{name}.svg"
    svg.write_text("\n".join(line.rstrip() for line in svg.read_text(encoding="utf-8").splitlines()) + "\n",
                   encoding="utf-8")


def box(ax, x, y, title, subtitle, color=BLUE, width=2.4, height=1.0):
    from matplotlib.patches import FancyBboxPatch
    fill = "#fff3e7" if color == ORANGE else "#eef5fb"
    ax.add_patch(FancyBboxPatch((x-width/2, y-height/2), width, height,
                               boxstyle="round,pad=0.025,rounding_size=0.07",
                               linewidth=1.4, edgecolor=color, facecolor=fill))
    ax.text(x, y+0.15, title, ha="center", va="center", color=INK,
            fontsize=13, weight="bold")
    ax.text(x, y-0.22, subtitle, ha="center", va="center", color=INK, fontsize=10)


def arrow(ax, start, end, color=BLUE):
    ax.annotate("", xy=end, xytext=start,
                arrowprops={"arrowstyle": "-|>", "color": color,
                            "lw": 1.6, "mutation_scale": 13})


def protocol_workflow(plt):
    fig, ax = plt.subplots(figsize=(12, 5.3))
    ax.set(xlim=(0, 12), ylim=(0, 5.3))
    ax.axis("off")
    ax.text(0.3, 5.05, "随机化 Merkle 承诺：公开承诺与按位置打开", color=INK,
            fontsize=17, weight="bold")
    for x, title, subtitle in [
        (1.5, "输入向量 M", "每叶独立秘密随机数 rᵢ"),
        (4.5, "Commit", "编码、建树、根封装"),
        (7.5, "公共承诺 C", "套件、n、根摘要 c"),
        (10.5, "Verify", "固定预期索引；接受 / 拒绝"),
    ]:
        box(ax, x, 3.65, title, subtitle)
    for x, title, subtitle in [
        (4.5, "私有状态 st", "消息、随机数、缓存树"),
        (7.5, "Open(st, i)", "读取目标消息与认证路径"),
        (10.5, "单点开口 π", "i、mᵢ、rᵢ、兄弟摘要"),
    ]:
        box(ax, x, 1.45, title, subtitle, ORANGE)
    for x in (1.5, 4.5, 7.5):
        arrow(ax, (x+1.23, 3.65), (x+1.75, 3.65))
    arrow(ax, (4.5, 3.12), (4.5, 1.99), ORANGE)
    arrow(ax, (5.73, 1.45), (6.25, 1.45), ORANGE)
    arrow(ax, (8.73, 1.45), (9.25, 1.45), ORANGE)
    arrow(ax, (10.5, 1.99), (10.5, 3.12), ORANGE)
    ax.text(7.5, 4.37, "通过可信方式提前固定", ha="center", color=BLUE, fontsize=10)
    ax.text(4.5, 0.53, "由承诺者本地保管", ha="center", color=ORANGE, fontsize=10)
    ax.text(10.5, 0.53, "授权打开时公开", ha="center", color=ORANGE, fontsize=10)
    ax.text(0.3, 0.15, "新承诺重新采样随机数；未打开位置的随机数继续保密。", color=GRAY, fontsize=10)
    save(fig, "protocol_workflow")
    plt.close(fig)


def project_architecture(plt):
    fig, ax = plt.subplots(figsize=(10, 6.2))
    ax.set(xlim=(0, 10), ylim=(0, 6.2))
    ax.axis("off")
    ax.text(0.5, 5.92, "项目模块与证据来源", color=INK, fontsize=17, weight="bold")
    rows = [
        (5.10, "src/cli.py", "commit / open / verify：命令行与退出码"),
        (3.95, "src/codec.py", "公共承诺、开口、私有状态的规范编码"),
        (2.80, "src/merkle.py", "独立随机化、域分离、建树与路径验证"),
        (1.65, "src/hashes.py", "手写 SHA-256 与 SHA3-256"),
    ]
    for y, title, subtitle in rows:
        box(ax, 5, y, title, subtitle, width=7.8, height=0.84)
    for y in (5.10, 3.95, 2.80):
        arrow(ax, (5, y-0.45), (5, y-0.68))
    ax.text(5, 0.76, "测试：NIST 已知答案、树结构、篡改输入、编解码与 CLI", ha="center", color=INK)
    ax.text(5, 0.27, "实验：benchmark.py、security_demo.py → results/ 原始记录 → 报告图表",
            ha="center", color=GRAY, fontsize=10)
    save(fig, "project_architecture")
    plt.close(fig)


def hash_node_cost(plt):
    data = json.loads((ROOT / "results/benchmark.json").read_text(encoding="utf-8"))
    lookup = {(r["suite"], r["input_bytes"]): r for r in data["hashes"]}
    # Length 22 is not a saved microbenchmark. Do not invent its timing.
    lengths = [46, 70, 94]
    labels = ["最终封装\n46 B", "内部节点\n70 B", "真实叶子（消息 32 B）\n94 B"]
    fig, ax = plt.subplots(figsize=(10, 4.6), constrained_layout=True)
    width = 0.33
    for suite, shift, color, hatch in [
        ("sha256", -width/2, BLUE, ""), ("sha3-256", width/2, ORANGE, "//")
    ]:
        rows = [lookup[suite, n] for n in lengths]
        values = [r["median_ms"] for r in rows]
        errors = [[r["median_ms"]-r["min_ms"] for r in rows],
                  [r["max_ms"]-r["median_ms"] for r in rows]]
        bars = ax.bar([i+shift for i in range(3)], values, width,
                      color=color, hatch=hatch, label="SHA-256" if suite == "sha256" else "SHA3-256",
                      yerr=errors, capsize=4, error_kw={"lw": 1.1})
        for bar, row in zip(bars, rows):
            ax.text(bar.get_x()+bar.get_width()/2, row["max_ms"]+0.035,
                    f'{row["median_ms"]:.3f}', ha="center", va="bottom", fontsize=10)
    ax.set_xticks(range(3), labels)
    ax.set_ylabel("每次哈希耗时（ms）")
    ax.set_ylim(0, max(lookup[s, n]["max_ms"] for s in ("sha256", "sha3-256") for n in lengths)*1.24)
    ax.set_title("实际节点输入的计算成本：五轮中位数与最小—最大范围", loc="left", weight="bold")
    ax.legend(frameon=False)
    ax.grid(axis="y", alpha=0.2)
    ax.set_axisbelow(True)
    save(fig, "hash_node_cost")
    plt.close(fig)


def main():
    plt = setup()
    protocol_workflow(plt)
    project_architecture(plt)
    hash_node_cost(plt)
    print("Wrote protocol, architecture and measured hash-cost figures (PNG/SVG).")


if __name__ == "__main__":
    main()
