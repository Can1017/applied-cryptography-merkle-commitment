# 随机化 Merkle Tree Commitment

应用密码学第一次作业。

小组成员：李灿、杨赟。项目使用 Python 自行实现 SHA-256、SHA3-256 及有序 Merkle 树，提供承诺、单点打开、验证和完整打开验证。每个真实叶子使用独立的秘密随机数，并采用域分离和规范编码绑定消息位置与向量长度。核心实现、测试和基准均不调用现成密码哈希函数或 Merkle Tree 库。

## 报告与阅读路径

- [方案设计与安全性分析](docs/Merkle树承诺方案设计与安全性分析.md)：调研、哈希选型、协议设计、binding/hiding 分析及实验结论。
- [详细说明与代码导读](docs/Merkle树承诺作业详细说明与代码导读.md)：基本原理、逐步算例、源码解读、运行步骤及结果判读。

![承诺、打开与验证流程](docs/figures/protocol_workflow.png)

蓝色表示输入与公共承诺，橙色表示私有状态和授权打开流程。验证者应事先固定可信的公共承诺，再检查目标位置的开口。

## 运行与验证

Python 3.11 或更新版本。核心程序与测试无需安装第三方包。进入包含 `src`、`tests` 和 `README.md` 的项目根目录；本机路径示例为 `D:\PostGraduate\应用密码学\第一次作业`，克隆到其他位置时使用实际目录。

从 GitHub 获取项目后，在任意终端中进入仓库目录：

```powershell
git clone https://github.com/Can1017/applied-cryptography-merkle-commitment.git
Set-Location applied-cryptography-merkle-commitment
```

```powershell
python --version
python -B -m unittest discover -s tests -v
```

已保存的验证包含 23 个测试方法、366 组 NIST 已知答案和 3 个标准示例，覆盖两种哈希、树形边界、合法开口、篡改输入、传输格式与 CLI。GitHub Actions 使用 Python 3.11 自动执行测试。测试向量随仓库提供，测试运行无需联网。

以下命令在新目录中创建三条示例消息的承诺，并打开索引 1 的 Bob：

```powershell
$runDir = Join-Path 'runs' ('demo-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
python -m src.cli commit examples/messages.json --public "$runDir/public.json" --state "$runDir/private-state.json"
python -m src.cli open "$runDir/private-state.json" --index 1 --out "$runDir/opening.json"
python -m src.cli verify "$runDir/public.json" "$runDir/opening.json" --index 1 --message Bob
```

`public.json` 是公共承诺；`private-state.json` 保存所有消息和秘密随机数，应由承诺者本地保管；`opening.json` 在授权打开时发布。输出文件采用独占创建，重复演示应使用新目录。commit 命令增加 `--suite sha3-256` 可切换套件；消息默认按 UTF-8 编码，索引从 0 开始。验证退出码为 0（成功）、1（声明不匹配）、2（解析或输入错误）。

## 实验结果与安全前提

![实际节点输入的哈希成本](docs/figures/hash_node_cost.png)

性能图直接读取 `results/benchmark.json`，柱高为五轮中位数，误差线为最小值至最大值。在原测量环境中，4096 叶子时 SHA-256 与 SHA3-256 的建树中位耗时分别为 4.298 秒和 6.862 秒，单点验证分别为 7.196 ms 和 11.667 ms。该比较适用于本项目的纯 Python 实现与记录的测量环境。

- **Binding**：同一承诺、同一位置的不同消息双重开口可归约为哈希碰撞；256 位摘要对应约 128 位经典通用碰撞强度。
- **Hiding**：额外依赖随机预言机建模、每叶独立的新鲜 256 位随机数及保密存储。普通确定性 Merkle 根不能自动隐藏低熵消息。
- **公开信息**：套件、向量长度、被打开的位置与内容按协议公开。根的可信来源由应用约定，测试通过不等于取得密码模块认证。

缓存树的 API 开口为 O(log n)；CLI 打开前从私有状态重建树，总成本为 O(B+n)。完整公共承诺为 45 字节，单点开口为 `49 + 消息字节数 + 32 × 树高` 字节。

## 项目结构与复现

```text
src/          手写密码哈希、承诺协议、编解码和 CLI
tests/       已知答案、功能与篡改测试及 NIST 静态向量
scripts/     测试、攻击演示、性能测量和图表
docs/        中文 Markdown 报告及图表
research/    调研来源、测试向量来源与课程要求
results/     原始实验记录、测试日志和源码清单
examples/    公开教学输入
.github/     自动验证工作流
```

需要生成新的实验记录时执行以下命令。它们会更新 `results/` 中的对应文件；如需保留原测量，应先复制结果目录。

```powershell
python scripts/run_tests.py
python scripts/demo.py
python scripts/security_demo.py
python scripts/benchmark.py
python scripts/audit_dependencies.py
```

默认基准测量五轮、最大 4096 叶子。`--max-n 1024` 可缩短运行，但正式报告的重建要求使用默认完整数据。256 与 257 叶子附近的局部复测保存在 `results/benchmark_diagnostic.json`，主实验记录保留原始波动。

图表已经随项目提供；如需重新生成图表，可安装可选展示依赖。这些包不参与密码运算：

```powershell
python -m pip install -r requirements-docs.txt
python scripts/build_figures.py
python scripts/package_submission.py
```

图表生成源码位于 `scripts/build_figures.py`。两份正式报告直接以 Markdown 形式维护，图片使用 `docs/figures/` 中的相对路径。

仓库保留源码、测试、所用测试向量、报告及图表、来源记录和原始实验数据。个人运行目录、私有状态、浏览器日志、检查截图及重复压缩包由 `.gitignore` 排除。官方向量完整下载 ZIP 留在本机，仓库仅提供测试所需的四个 `.rsp` 文件，其来源见 [测试向量来源](research/测试向量来源.md)。
