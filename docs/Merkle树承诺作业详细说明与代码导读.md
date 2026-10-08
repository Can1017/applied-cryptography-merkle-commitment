# Merkle 树承诺作业详细说明与代码导读

应用密码学第一次作业学习与运行手册

本说明作为课程报告的配套文档，依次介绍调研与设计依据、基本原理、代码结构、运行步骤及实验结果。协议说明对应项目实际实现；调研来源与查看范围记录在核验清单中，性能数据来自已保存的实验记录。文档修订日期为 2026 年 10 月 8 日，基准实验日期为 2026 年 9 月 20 日。

正式方案见同目录的《Merkle 树承诺方案设计与安全性分析》。该报告侧重方案规格与安全论证；本说明增加术语解释、逐步算例、函数导读、可复制命令和结果判读。建议第一次阅读先看第 1 至 5 章，再执行第 11 章；需要讲解源码时重点阅读第 7 至 10 章。

## 1 作业目标与实现范围

### 1.1 课程要求与交付内容

本次作业要求设计并实现 Merkle Tree Commitment，明确承诺对象、打开方法和验证规则，并分析承诺者事后更改消息与接收者提前识别消息的难度。实现部分需要选择具体密码哈希函数，自行完成底层运算，验证正确性并评估性能。

| 要回答的问题 | 项目中的回答 | 可查看的证据 |
| --- | --- | --- |
| 承诺的是什么 | 一个有顺序、允许重复、元素为字节串的消息向量 | `src/merkle.py`、正式报告第 4 节 |
| 如何证明某个位置的消息 | 消息、该叶的随机数和自下而上的兄弟摘要 | `Opening`、`open`、`verify` |
| 如何避免承诺后改口 | 规范编码、域分离及哈希抗碰撞性 | 正式报告的 binding 归约 |
| 如何避免提前猜出消息 | 每叶独立且未公开的 32 字节随机数 | 构造函数、hiding 模型、攻击演示 |
| 哈希是否自己编写 | SHA-256 和 SHA3-256 都由位运算、整数运算和字节操作实现 | `src/hashes.py` |
| 是否确实算对 | 与 NIST 给出的输入及预期摘要比较 | `tests/vectors/`、`results/tests.json` |
| 速度和证明大小如何 | 原始重复计时和明确的字节大小公式 | `results/benchmark.json` |

课程允许使用 AI 辅助完成作业。本说明聚焦方案与实现，所述功能均以源码和实验记录为依据。

### 1.2 当前实现的功能边界

项目已经支持新建承诺、打开任意合法位置、验证单点开口、完整打开验证、两种哈希套件、JSON 与紧凑二进制编解码。代码以课程理解和复现为目标，使用 Python 3.11，核心程序无需安装第三方包。

实现范围为静态、有序向量的随机化承诺与按位置打开。每次打开会公开对应消息和随机数；可信根的传递及消息来源认证由应用另行处理。当前版本采用缓存树和单点认证路径，尚未加入增量更新或多叶共享证明。

## 2 调研过程与设计决策

### 2.1 要求提取与调研范围

最初先阅读作业截图，提取“设计、安全性、哈希选型、自行实现、验证、性能”六类要求。最关键的实现约束是禁止调用现成哈希函数和 Merkle Tree 库。因此，调研开源项目的用途是理解树形、编码、接口及已知问题，最终运行路径不能依赖这些项目。

项目保留了 `research/作业要求.png`，便于核对原始要求。`README.md` 是操作入口，正式报告的要求矩阵用于确认没有只完成程序而遗漏安全性或实验说明。

### 2.2 代表性实现的树形与编码约定

研究首先围绕树的基本约定展开：叶子是否排序、奇数节点如何处理、叶子与内部节点是否区分、路径如何编码，以及证明的语义是集合成员关系还是向量位置关系。

| 查看来源 | 实际查看的重点 | 对本方案的影响 |
| --- | --- | --- |
| RFC 9162 第 2.1 节 | 有序树、叶子与内部节点的前缀、包含及一致性证明 | 采用明确域分离和严格路径验证；没有照搬它的非满树拓扑 |
| Bitcoin Core 的 `src/consensus/merkle.cpp` | 源码中关于重复末尾、重复交易及 mutation 的说明 | 不采用没有额外约束的末尾复制规则 |
| OpenZeppelin merkle-tree README 和 `src/core.ts` | 双重叶哈希、默认排序、树和证明接口 | 确认集合式排序与本项目保序需求不同；不引入 ABI、Keccak256 依赖 |
| pymerkle 项目文档 | Python API、域分离、树拓扑 | 参考接口组织，独立编写树逻辑 |
| Ethereum 开发者文档 | Merkle Patricia Trie 的键值路径与节点类型 | 确定本次只需要有序二叉树，无需 trie 的复杂编码 |

调研表明，承诺对象、节点编码与验证规则共同决定协议语义。不同项目使用 Merkle 结构，但树形和编码约定不同，根与证明通常无法直接互换。（[R1](#ref-r1)、[R2](#ref-r2)、[R3](#ref-r3)、[R4](#ref-r4)、[R5](#ref-r5)）

### 2.3 确定性 Merkle 根的隐藏性限制

接下来把认证数据结构与承诺方案分开思考。成绩、投票选项等消息空间很小，即使哈希函数没有被攻破，接收者仍可计算所有候选并比较根。由此得出：仅实现确定性 Merkle 树不能充分回答题目的 hiding 要求。

参考向量承诺论文的定义，明确本项目关注同一位置的 binding；参考随机预言机承诺的教学材料，明确“抗碰撞”不能单独推出“隐藏”。向量承诺论文的查看范围为摘要与出版信息；教学讲义的查看范围为随机化哈希承诺、随机预言机及 Merkle 树的相关页面。具体范围记录在来源清单中。（[R6](#ref-r6)、[R13](#ref-r13)）

据此提出每叶独立的秘密随机数。这里的随机数不是随公共承诺一起发布的普通盐值，而是必须暂时保密的开口材料。第 5、14 章进一步解释这个区别。

### 2.4 基于算法标准实现密码哈希

SHA-256 依据 FIPS 180-4，SHA3-256 依据 FIPS 202。轮常量和旋转偏移属于算法规范参数，使用这些公开参数不等于调用现成实现。Keccak 团队的规格摘要用于交叉核对状态映射和偏移。（[R7](#ref-r7)、[R8](#ref-r8)、[R17](#ref-r17)）

理论比较还查看了 BLAKE2 的 RFC、BLAKE3 官方规格仓库以及 Poseidon 论文简介。BLAKE2、BLAKE3、SHA-512/256 与 Poseidon 没有在本项目中实现或实测，因此报告没有给出它们的自制性能数据。Poseidon 的主要比较维度是算术电路成本，而本作业直接处理字节串，不能混用这两种评价目标。（[R10](#ref-r10)、[R11](#ref-r11)、[R12](#ref-r12)）

### 2.5 独立测试数据与实验验证

从 NIST 官方下载 SHA 和 SHA-3 的 byte-oriented 测试向量 ZIP，仅提取四个 `.rsp` 数据文件。每条记录包含消息长度、消息和预期摘要；实现计算出来的摘要与该预期值比较。没有用现成哈希库作为运行时对照。（[R14](#ref-r14)）

随后检查树的边界与篡改输入，运行攻击演示，再测量短输入和整棵树的成本。性能测量中发现 256 与 257 叶子附近的异常点后，保留了原始结果，并另外保存局部复测，而不是删除不符合预期的样本。

### 2.6 调研结论与设计选择

| 发现的问题 | 最终选择 | 对应代码 |
| --- | --- | --- |
| 确定性根可被字典枚举 | 每叶独立 256 位私有随机数 | `MerkleCommitment.__init__` |
| 叶子和内部节点可能有结构混淆 | 用不同单字节域标记 | `_prefix` 与四类节点函数 |
| 变长拼接可能不唯一 | 用固定宽度整数记录位置、向量长和消息长 | `_u64`、`leaf_hash` |
| 末尾复制存在根歧义 | 补专用填充叶，并绑定真实长度 n | `padding_hash`、`finalize` |
| 排序会改变向量语义 | 保留输入顺序并绑定索引 | `_build`、`verify` |
| 仅凭轮数无法预测 Python 速度 | 对真实节点长度和整棵树实测 | `scripts/benchmark.py` |

完整来源与查看范围记录在 `research/references-verified.json`。仓库的 `master`、文档的 `latest` 可能变化，记录反映 2026-09-20 的查看结果，不声称已经固定其提交版本。设计决策、标准事实和本机测量是三类不同证据，应分别引用。

## 3 基本概念与符号约定

### 3.1 bytes、bit 和十六进制

本项目哈希函数的输入、输出类型都是 Python `bytes`。1 字节等于 8 位；256 位摘要就是 32 字节。在 JSON 中，这 32 字节被写成 64 个十六进制字符，因为每个字节需要两个 hex 字符表示。

`Bob` 按 UTF-8 编码是 `b"Bob"`，长度为 3，十六进制为 `426f62`。中文按 UTF-8 编码后的字节数通常不同于字符数，因此不能用“有几个汉字”替代 `len(message_bytes)`。CLI 负责文字到 UTF-8 的转换，底层哈希函数不自动替调用者选择编码。

```python
message = "Bob".encode("utf-8")
print(message)        # b'Bob'
print(len(message))   # 3
print(message.hex())  # 426f62
```

十六进制是可逆的展示格式，不是加密。任何人都可以把 `426f62` 还原成 `Bob`；所以把明文写成 hex 并不能让私有状态变成密文。

### 3.2 密码哈希函数的三个常见性质

| 性质 | 攻击者面对的任务 | 与本作业的关系 |
| --- | --- | --- |
| 原像抵抗 | 给定摘要 y，寻找 x 使 H(x)=y | 不能据此认为小消息空间无法枚举 |
| 第二原像抵抗 | 给定 x，再找不同 x′ 使 H(x)=H(x′) | 与对已经确定内容的修改有关 |
| 抗碰撞 | 自行选择任意两个不同输入，使摘要相同 | binding 归约采用的主要假设 |

哈希输出长度固定，输入空间更大，所以碰撞在数学上必然存在。安全要求是计算上难以找到，而不是“摘要绝对唯一”。理想 256 位输出的经典通用碰撞搜索约需 2¹²⁸ 量级工作，不能把它说成 256 位碰撞安全。（[R9](#ref-r9)）

### 3.3 承诺与加密、签名的功能区别

承诺有两个阶段：先固定一个值，之后按需打开。binding 限制发送方事后改变值，hiding 限制接收方提前识别值。验证者收到开口后重新计算即可检查，没有从根中“解密”出原消息的操作。

加密主要服务于保密通信；数字签名提供基于密钥的来源认证。Merkle 承诺自身没有证明谁发布了根、何时发布，也没有阻止攻击者将根和证明一起更换。验证方必须先固定可信的公共承诺，才有一个值得比较的目标。

### 3.4 向量、集合和位置

本项目输入 `[Alice, Bob, Carol]` 是有序向量。位置从 0 开始，Bob 的位置是 1。`[Bob, Alice, Carol]` 表示不同向量，即使三条消息的集合相同。重复消息是允许的，它们的索引不同，叶子输入也不同。

验证的语句不是笼统的“Bob 在某处”，而是“在预先接受的承诺下，位置 1 打开为 Bob”。这正是 `expected_index` 必须显式传入的原因。

## 4 随机化 Merkle 承诺的基本原理

### 4.1 二叉 Merkle 树与认证路径

假设先对每条消息哈希，再将相邻两个摘要连接后哈希，逐层向上得到一个根。消息变化会改变叶子摘要，并沿路径影响根。若要证明某个叶子，只需给出沿途缺失的兄弟摘要，而不用给出所有其他消息。

当叶子数为 p=2ʰ 时，树高为 h。一个单点证明每层提供一个兄弟，共 h 个。比如 p=4096 时，h=12，认证路径只需 12 个摘要，即 384 字节；但完整开口还要包含消息、随机数和少量字段。

### 4.2 三条消息的树形

本项目将三条真实消息补到四个叶子。第 4 个位置使用专门的填充节点 P₃，不重复 Carol。

![三条消息打开 Bob 的认证路径](figures/guide_merkle_path.svg)

图 4-1 位置 1 的开口。蓝色为验证者重算的路径，橙色为证明提供的兄弟摘要。P₃ 是填充，不是第 4 条真实消息。

设四个叶子为 L₀、L₁、L₂、P₃。先算 `N₀₁=Node(L₀,L₁)` 和 `N₂₃=Node(L₂,P₃)`，再算 `T=Node(N₀₁,N₂₃)`。最后对 T 和公共元数据进行一次额外封装，得到公开摘要 c。T 是内部树根，c 才是 `Commitment.digest`。

### 4.3 独立随机数与叶子计算

对每个真实消息 mᵢ，生成独立的 32 字节 rᵢ。叶子不再只是 `H(mᵢ)`，而是将协议标签、位置、长度、随机数与消息一起编码后哈希。同一个消息用新的随机数承诺，通常会得到新的叶子和根。

新随机数不能改变哈希函数本身的确定性：固定全部输入时，H 的输出始终相同。随机性位于传给 H 的数据中。因此，恢复旧承诺必须保留旧随机数，不能用同一明文再调用新建构造函数来“恢复”。

### 4.4 四类节点的完整格式

记 D 为四个 ASCII 字节 `MTC1`，A 为一个字节的套件编号。SHA-256 使用 A=`01`，SHA3-256 使用 A=`02`。`U64` 是 8 字节大端无符号整数，`||` 表示字节连接。

```text
真实叶子 = H(00 || D || A || U64(n) || U64(i)
               || U64(message_length) || salt32 || message)
内部节点 = H(01 || D || A || left32 || right32)
最终承诺 = H(02 || D || A || U64(n) || tree_root32)
填充叶子 = H(03 || D || A || U64(n) || U64(i))
```

`00` 是一个值为 0 的字节，不是字符串 `"00"`。`_prefix` 的总长度为 1+4+1=6 字节。真实叶子的固定开销是 6+8+8+8+32=62 字节，因此 Bob 对应的叶子哈希输入长 65 字节；基准测试的 32 字节消息则对应 94 字节输入。

| 字段 | 为什么存在 | 如果随意删除会失去什么 |
| --- | --- | --- |
| 域标记 | 区分叶子、内部节点、封装和填充 | 跨类型输入空间的明确分隔 |
| MTC1 | 说明协议版本 | 后续更改协议时的版本隔离 |
| 套件编号 | 固定所用算法 | 算法选择与承诺内容的明确关联 |
| n | 绑定真实向量长度 | 长度语义及填充边界的清晰性 |
| i | 绑定位置 | 重复消息和位置语义的明确关联 |
| 消息长度 | 给变长消息一个规范边界 | 后续解析和证明编码的唯一性 |
| salt32 | 对低熵消息提供秘密随机化 | 本方案的 hiding 前提 |

不是说表中每个字段在任何其他安全设计中都不可省略，而是本版本的定义依赖它们；修改任一字段都会改变规范和摘要，需要重新分析与验证。

### 4.5 不足二次幂和特殊输入

| 真实叶数 n | 树高 h | 容量 p | 填充数量 | 路径摘要数 |
| --- | --- | --- | --- | --- |
| 0 | 0 | 1 | 1 | 无合法单点开口 |
| 1 | 0 | 1 | 0 | 0 |
| 2 | 1 | 2 | 0 | 1 |
| 3 | 2 | 4 | 1 | 2 |
| 5 | 3 | 8 | 3 | 3 |
| 256 | 8 | 256 | 0 | 8 |
| 257 | 9 | 512 | 255 | 9 |

空向量使用一个填充节点来定义根，但没有可以打开的真实索引。单叶树的路径为空，验证仍需算一次叶子哈希和一次最终封装。填充节点不需要秘密随机数，因为它表示公开的结构而不是一条待隐藏消息。

所有真实叶子的索引都必须小于 n，不能拿填充位置作为正常数据打开。当前内存构造上限为 2²⁰ 个真实叶子；这个上限是资源策略，本项目实测最大规模为 4096，并没有测量满上限时的时间和内存。

## 5 单点开口的完整算例

### 5.1 输入和固定测试随机数

使用 `examples/messages.json` 中的三条消息：Alice、Bob、Carol。为了让本节可以逐字核对，采用公开的测试随机数 `rᵢ=i.to_bytes(32,"big")`。也就是 r₀ 全零，r₁ 末字节为 1，r₂ 末字节为 2，其余为零。

这种随机数是固定教学样例，不满足隐藏要求；它只用于解释内部计算。正常 CLI 和构造函数使用新的操作系统随机数，用户运行后不应期待得到下面同一个根。

| 套件 | 固定测试样例的公开摘要 c |
| --- | --- |
| sha256 | `a63c3725bc8b8bfe80fb95aae18995641dee2438738228075878618984310766` |
| sha3-256 | `eb52676647e94739766f696ba1381b522bed910aebec39d03783ad950ffce33e` |

上述摘要与 `results/demo.json` 的 `fixed` 分支一致。它们来自本项目自身的确定性样例，可以用于追踪接口和字节编码，不是证明哈希算法正确性的独立预期值；后者来自 NIST 向量。

### 5.2 单点开口的传输内容

Bob 位于 i=1，二进制低两位为 `01`。路径按从低位到高位读取，而不是按通常阅读二进制文字的从左至右顺序。

| 层 | 当前位置 | 位置奇偶 | 证明给出的兄弟 | 验证者组合方式 |
| --- | ---: | --- | --- | --- |
| 叶子层 | 1 | 奇数，当前值在右侧 | L₀ | `Node(L₀,L₁)` |
| 上一层 | 0 | 偶数，当前值在左侧 | N₂₃ | `Node(N₀₁,N₂₃)` |

验证者只需要 Bob、r₁、L₀、N₂₃，以及先前接受的公共承诺。不需要 Alice、Carol、r₀ 或 r₂ 的原文。对 SHA-256 固定样例，开口 JSON 是：

```json
{
  "version": "MTC1",
  "index": 1,
  "message_hex": "426f62",
  "salt_hex": "0000000000000000000000000000000000000000000000000000000000000001",
  "siblings_hex": [
    "ac4fb884ff98c5ec6cb134523afe94fc312895ff0504468f702c36c93168cece",
    "210e08112c930227259dc4e2a8fa9f27f0f57676b1093d93bd2230e83c6882d3"
  ]
}
```

这里两个 `siblings_hex` 的顺序具有意义：先 L₀，再 N₂₃。把两项反过来会改变计算，不是同一个证明。

### 5.3 逐步复算的摘要

| 复算步骤 | 所得摘要的完整十六进制 |
| --- | --- |
| 1 目标叶子 L₁ | `ebc2b182166a02def1673fd798efb15443f2f3db0acf0a8cdb5cd6d7c0ec9f76` |
| 2 父节点 N₀₁ | `6eeb2abdfdb9571d075411774e6c7770421b3b015b6ed94d89a08a67e2e9cec7` |
| 3 内部树根 T | `64a3a060892530fb2eb7174640aca7074c2caa0d157aaf07efcd126e21654953` |
| 4 公开摘要 c | `a63c3725bc8b8bfe80fb95aae18995641dee2438738228075878618984310766` |

第一次计算使用索引、长度、随机数和 `b"Bob"` 得到 L₁；第二次与第一个兄弟合并得到 N₀₁；第三次与第二个兄弟合并得到 T；第四次对 T 进行最终封装。只有第四步的摘要才应与公共 `digest_hex` 比较。

这次证明包含 2 个路径摘要。Bob 长 3 字节，因此完整紧凑开口是 `49+3+32×2=116` 字节。基准表中 n=3 的开口为 145 字节，是因为基准消息长 32 字节，不是本例的 3 字节。

### 5.4 篡改输入与验证拒绝

把 Bob 改成 Mallory，即使随机数和路径都保留不变，第一步叶子输入也已经改变，通常无法再次得到同一最终摘要。把索引改成 0，会同时改变叶子编码和左右路径方向。改变套件则改变具体哈希函数以及前缀内的套件编号。

验证器不负责自动纠正这些字段。它根据已固定的承诺和调用者明确给出的预期语句进行检查，不匹配就返回 False。与之不同，合法输入被截断、字节长度不合法或版本无法解析时，解码阶段可能直接报错。

## 6 项目结构与建议阅读路线

### 6.1 目录与模块职责

![核心模块的职责与调用关系](figures/project_architecture.png)

图 6-1 项目模块与实验记录的关系。密码计算由 `src/hashes.py` 完成，传输编码与命令行接口分别处理文件格式和用户输入。

```text
第一次作业/
├─ README.md                         快速入口和运行命令
├─ examples/messages.json            Alice、Bob、Carol 样例
├─ src/
│  ├─ hashes.py                      两种手写密码哈希
│  ├─ merkle.py                      承诺、打开和验证
│  ├─ codec.py                       编解码与文件格式
│  └─ cli.py                         命令行入口
├─ tests/
│  ├─ test_hashes.py                 哈希已知答案检查
│  ├─ test_merkle.py                 树、开口、篡改和边界
│  ├─ test_codec_cli.py              格式、文件和端到端命令
│  ├─ vector_loader.py               解析 NIST 数据记录
│  └─ vectors/                       四个官方 .rsp 数据文件
├─ scripts/                          演示、测试、基准及文档工具
├─ results/                          可追踪的原始结果
├─ research/                         要求截图及来源核验清单
└─ docs/                             方案报告、本说明与图像
```

`src/__init__.py` 使 `src` 成为包，适合用 `python -m src.cli` 启动。核心模块职责分开：哈希层不理解树，树层处理 bytes 和密码逻辑，编解码层处理文件格式，CLI 负责参数与输入输出。

### 6.2 调用关系与阅读顺序

建议先看 `cli.main` 的三个分支，知道程序入口；再读 `MerkleCommitment` 的构造、`open` 和 `verify`，理解数据流；接着读 `codec.py` 确认对象如何写入文件；最后阅读两个哈希函数的内部轮运算。这样可以先理解“为什么需要这次哈希”，再研究“这次哈希内部怎么算”。

```text
commit 命令
  → read_json → UTF-8/hex 解码 → MerkleCommitment
  → 校验消息 → 采样随机数 → leaf/padding/parent/finalize
  → 本地 sha256 或 sha3_256 → 写公共文件和私有状态

open 命令
  → read_json → state_from_dict → _restore 重建树
  → tree.open(index) → opening_to_dict → 写开口文件

verify 命令
  → 分别读公共承诺与开口 → 严格解码
  → verify(expected_index, expected_message) → 输出 valid 和退出码
```

### 6.3 核心函数定位表

| 文件与起始行 | 函数或对象 | 首先关注的问题 |
| --- | --- | --- |
| `src/cli.py:15` | `main` | 命令行分支与退出码 |
| `src/merkle.py:57` | `Commitment` | 公共承诺对象 |
| `src/merkle.py:70` | `Opening` | 消息与认证路径 |
| `src/merkle.py:97` | `MerkleCommitment.__init__` | 校验并采样独立随机数 |
| `src/merkle.py:116` | `MerkleCommitment._restore` | 复用保存的私有状态 |
| `src/merkle.py:130` | `MerkleCommitment._build` | 构造并缓存各层 |
| `src/merkle.py:144` | `MerkleCommitment.open` | 取出单点路径 |
| `src/merkle.py:159` | `verify` | 独立验证单点开口 |
| `src/merkle.py:187` | `verify_all` | 验证完整打开 |
| `src/codec.py:94` | `state_from_dict` | 严格恢复私有状态 |
| `src/codec.py:67` | `opening_to_bytes` | 紧凑开口编码 |
| `src/codec.py:121` | `read_json` | 限制大小及拒绝重复键 |
| `src/hashes.py:38` | `sha256` | SHA-256 一次性摘要 |
| `src/hashes.py:96` | `_keccak_f1600` | Keccak 24 轮置换 |
| `src/hashes.py:121` | `sha3_256` | SHA3 吸收与输出 |

定位信息由生成脚本从实际源码提取，避免凭印象填写。若以后修改源码，可重新生成本说明更新行号。模块前缀加下划线表示内部接口，不代表 Python 会阻止调用者访问它。

## 7 哈希函数的代码解读

### 7.1 定长字运算与位掩码

Python 整数可以增长到超过 32 或 64 位，而标准哈希算法的字运算有固定宽度。代码中的 `MASK32=(1<<32)-1` 和 `MASK64=(1<<64)-1` 用来截取低位。例如 `value & MASK32` 相当于保留 value 的低 32 位，对非负加法结果就是模 2³²。

`_rotr32` 用右移和左移组合模拟循环右移。普通右移会丢弃低位，循环右移还要把这些低位放回高位。`_rotl64` 做对应的 64 位循环左移，且处理偏移为 0 的情况。位操作 `^` 是异或，不是乘方；Python 中乘方是 `**`。

### 7.2 SHA-256 的填充和消息扩展

SHA-256 每次处理 64 字节。先加入一个 `80` 字节，再补零，最后用 8 字节记录原消息的比特长度。这里记录的是填充前长度，不能把新填充的字节算进去。（[R7](#ref-r7)）

```python
padded = message + b"\x80"
padded += b"\x00" * ((56 - len(padded)) % 64)
padded += (len(message) * 8).to_bytes(8, "big")
```

最后 8 字节必须留给长度，所以补零目标是当前分组的第 56 字节处。55 字节消息加 `80` 后正好到 56，只需再加长度；56 字节消息则需要另一个分组。这解释了微基准为什么专门测 55 与 56 字节。

每个 64 字节分组先按大端解析为 16 个 32 位字，然后扩展成 64 个字：

```text
σ₀(x) = ROTR(x,7)  XOR ROTR(x,18) XOR (x >> 3)
σ₁(x) = ROTR(x,17) XOR ROTR(x,19) XOR (x >> 10)
W[t] = W[t−16] + σ₀(W[t−15]) + W[t−7] + σ₁(W[t−2]) mod 2³²
```

消息扩展让后续轮使用原始分组各部分混合产生的字。`words` 是当前分组的消息调度数组，不是整棵树的节点集合。名称相近但数据层级不同。

### 7.3 SHA-256 的压缩轮和最终输出

压缩维护 a 到 h 八个工作变量。每轮计算选择函数 Ch、多数函数 Maj、两种大写 Σ 旋转组合以及临时值 t1、t2，然后整体更新八个变量。元组赋值使右侧先根据旧状态算出，再统一写入，避免部分变量提前更新而污染同一轮的计算。

```python
choice = (e & f) ^ ((~e) & g)
majority = (a & b) ^ (a & c) ^ (b & c)
a, b, c, d, e, f, g, h = (
    (t1 + t2) & MASK32, a, b, c, (d + t1) & MASK32, e, f, g
)
```

64 轮之后，将工作变量与该分组开始前的链值相加，再进入下一分组。所有分组处理完，把八个 32 位状态按大端序连接，得到 8×4=32 字节摘要。轮数是对每个分组计算的；一个节点如果需要两个分组，就会执行两次 64 轮压缩。

### 7.4 SHA3-256 的整体结构

SHA3-256 采用海绵结构。内部状态共有 1600 位，分成 25 个 64 位 lane，按 5×5 矩阵理解；代码将坐标 (x,y) 放在列表下标 `x+5*y`。rate 为 1088 位，即每次可吸收 136 字节；capacity 为 512 位。（[R8](#ref-r8)）

先将消息填充，再分成 136 字节块。每块按小端序解析为 17 个 lane，异或进状态的前 17 项，然后执行 Keccak-f[1600] 的 24 轮置换。这里是异或吸收，不是覆盖整个状态。完成全部吸收后，取前四个 lane 的小端字节，正好得到 32 字节输出。

### 7.5 Keccak 一轮中的五步

| 步骤 | 代码中的主要对象 | 作用 |
| --- | --- | --- |
| θ theta | `columns`、`delta` | 计算列异或及邻列影响，再异或到各 lane |
| ρ rho | `_KECCAK_ROT`、`_rotl64` | 对各 lane 作不同偏移的循环旋转 |
| π pi | `new_index`、`moved` | 将旋转后的 lane 放到新的矩阵位置 |
| χ chi | 每行的 `row` | 用与、取反和异或加入非线性 |
| ι iota | `_KECCAK_RC` | 将本轮常量异或入第一个 lane |

`moved` 和 `row` 的临时副本用于保留当前步骤需要的旧值。若直接在原数组中覆盖后又读取更新过的位置，会改变算法。实现将 ρ 和 π 放在一个双重循环中，但逻辑上仍是两步。

### 7.6 SHA3 的填充细节

对于这里支持的字节对齐输入，首填充字节取 `06`，末填充字节设置 `80` 位；当它们是同一个字节时，得到 `86`。

```python
padding = bytearray(136 - (len(message) % 136))
padding[0] = 0x06
padding[-1] |= 0x80
```

135 字节消息只需要 1 个 `86` 字节，吸收一次；136 字节消息必须额外添加一整块填充，所以吸收两次。因为输出仅 32 字节，小于 136 字节 rate，不需要为了继续挤出输出再做一次置换。

本函数实现的是 FIPS 202 的 SHA3-256，不能将它当作 Ethereum 使用的 Keccak256。共同使用 Keccak 置换并不意味着后缀和输出相同。（[R3](#ref-r3)、[R8](#ref-r8)）

### 7.7 节点输入长度与哈希选型

| 节点 | 哈希输入长度 | SHA-256 的压缩次数 | SHA3-256 的置换次数 |
| --- | ---: | ---: | ---: |
| 填充 | 22 字节 | 1 | 1 |
| 最终封装 | 46 字节 | 1 | 1 |
| 内部节点 | 70 字节 | 2 | 1 |
| 32 字节消息叶子 | 94 字节 | 2 | 1 |

一次 SHA-256 压缩与一次 Keccak 置换的成本不同，所以次数更少不必然更快。Python 循环、索引、临时数组、整数宽度及旋转操作都有成本。项目选择标准充分、实现便于核查的 SHA-256 为默认，并用另一种结构的 SHA3-256 作实测对照；不是通过增加轮数或串联两个哈希来自行“加强”算法。

## 8 Merkle 核心模块的代码解读

### 8.1 公共对象与开口对象

`Commitment` 保存 `suite`、`n` 和 `digest`。版本常量在协议前缀及传输对象中出现。`Opening` 保存索引、消息、32 字节随机数和一个兄弟摘要元组。两者使用 `dataclass(frozen=True)`，避免正常调用路径中意外修改字段。

`__post_init__` 检查字段类型及长度。特别注意代码使用 `type(value) is int`，而不是单纯的 `isinstance(value,int)`：因为 Python 的 bool 是 int 的子类，若不区分，True 可能被当作索引 1。

不可变对象并不自动等于安全输入。解析时仍要检查版本、字段集合和编码；验证时还要检查相应索引和路径是否属于本次公共承诺。

### 8.2 新承诺的随机数生成

构造函数先调用 `_validate_messages`，确认每条消息都是 bytes、规模在上限内、消息长度符合约束，再执行：

```python
self._build(values, suite, tuple(token_bytes(SALT_BYTES) for _ in values))
```

列表推导式每轮都重新调用 `token_bytes`，所以每叶独立采样。若把一次生成的随机数乘 n 次复制，就会变成共享随机数。`secrets.token_bytes` 的用途是获取操作系统随机字节，不是代算 SHA-256 或 SHA3-256。

`_restore` 接收已经存在的随机数，用于从私有文件恢复原承诺，也用于固定测试。它不会检查随机数是否真的来自安全采样过程；输入了全零或可预测值，程序仍能计算出摘要，但不能据此宣称满足 hiding。

### 8.3 `_build` 的分层构造与缓存

源码位置：`src/merkle.py`，第 130 行起。

```python
def _build(self, values, suite, salts):
    self._messages, self._salts, self._suite = values, salts, suite
    n = len(values)
    capacity = 1 << depth(n)
    leaves = [leaf_hash(suite, n, i, m, salts[i]) for i, m in enumerate(values)]
    leaves.extend(padding_hash(suite, n, i) for i in range(n, capacity))
    levels = [tuple(leaves)]
    while len(levels[-1]) > 1:
        below = levels[-1]
        levels.append(tuple(parent_hash(suite, below[i], below[i + 1])
                            for i in range(0, len(below), 2)))
    self._levels = tuple(levels)
    self.commitment = Commitment(suite, n, finalize(suite, n, levels[-1][0]))
```

先算全部真实叶子，再用专用填充叶补到 capacity。`levels[0]` 保存叶子层，`levels[1]` 保存父层，依次向上。内部循环每次取 `below[i]` 和 `below[i+1]`，左右次序固定。最终 `levels[-1]` 只含一个内部树根，随后调用 `finalize` 生成公开摘要。

这是用元组数组保存各层的实现，没有为每个节点创建带父子指针的对象。保存所有层会占用 O(n) 摘要空间，但生成开口时能直接按索引取兄弟，不需要重新哈希其他子树。

### 8.4 `depth` 的树高计算

代码是 `(max(1,n)-1).bit_length()`。对 n=3，n−1=2，其二进制是 `10`，位数为 2；对 n=4，n−1=3，位数仍为 2；对 n=5，n−1=4，二进制为 `100`，位数变为 3。它精确实现向上取整的 log₂，避免浮点对数在大整数边界上的舍入。

`max(1,n)` 统一处理 n=0 和 n=1，使树高为 0。容量随后用 `1 << depth(n)` 计算，这里的左移等价于 2 的相应次幂。

### 8.5 `open` 的兄弟节点定位

源码位置：`src/merkle.py`，第 144 行起。

```python
def open(self, index: int) -> Opening:
    if type(index) is not int or not 0 <= index < self.commitment.n:
        raise ValueError("index outside real leaves")
    position = index
    siblings = []
    for level in self._levels[:-1]:
        siblings.append(level[position ^ 1])
        position >>= 1
    return Opening(index, self._messages[index], self._salts[index], tuple(siblings))
```

相邻叶子成对出现：0 与 1、2 与 3、4 与 5。下标异或 1 切换最低位，正好得到兄弟下标。右移 1 位得到父下标，例如位置 5 的父位置为 2。循环不处理最后的根层，因为根没有需要提供的兄弟。

这里仅取出路径摘要并构造 Opening，不调用哈希函数，因此缓存树的开口很快。取出的 message 和 salt 是不可变 bytes 的引用；若继续序列化或传输整个开口，仍需处理全部消息字节，不能把序列化成本忽略后声称所有操作都与消息长度无关。

### 8.6 `verify` 的三段逻辑

源码位置：`src/merkle.py`，第 159 行起。

```python
def verify(commitment: Commitment, opening: Opening, *, expected_index: int,
           expected_message: bytes | None = None) -> bool:
    """Verify against a separately trusted commitment and an explicit position.

    expected_message=None means accept and disclose the message inside opening.
    Supply bytes when checking a previously specified statement about its value.
    """
    if type(commitment) is not Commitment or type(opening) is not Opening:
        return False
    if type(expected_index) is not int or expected_index != opening.index:
        return False
    if expected_message is not None:
        if type(expected_message) is not bytes or expected_message != opening.message:
            return False
    if not 0 <= opening.index < commitment.n:
        return False
    if len(opening.siblings) != depth(commitment.n):
        return False
    suite = commitment.suite
    value = leaf_hash(suite, commitment.n, opening.index, opening.message, opening.salt)
    position = opening.index
    for sibling in opening.siblings:
        value = (parent_hash(suite, sibling, value) if position & 1
                 else parent_hash(suite, value, sibling))
        position >>= 1
    return finalize(suite, commitment.n, value) == commitment.digest
```

第一段检查对象、预期索引、可选预期消息和路径长度。第二段重算叶子，并根据当前位置最低位决定兄弟在左还是右。第三段对复原的内部根作最终封装，再与承诺比较。

`expected_message=None` 并不是“不验证叶子消息”。它表示接受证明中披露的那条消息作为本次待验证内容；消息仍然参与叶子哈希。若调用方要验证事先指定的 Bob，就应传 `expected_message=b"Bob"`，否则它只是知道“这个位置的开口有效，并披露了该消息”。

比较的是公开摘要，代码使用普通相等比较。项目没有承诺整个 Python 实现具备常数时间行为，也没有宣称抵抗本地时间或内存侧信道。

### 8.7 `verify_all` 的完整重建验证

完整打开就是提供所有消息和各自随机数，再从头构建并比较同一公共对象。只有明文无法恢复随机化承诺，因为原先的叶摘要还依赖旧随机数。`reveal_all` 一旦发布，就结束所有这些消息的隐藏阶段。

单点验证只检查一条路径，不证明其余所有消息可用，也不检查每个不可见子树是否都按照本构造诚实生成。完整打开可以检查整棵构造是否与给定向量和随机数一致；这与单点 position binding 是不同的保证。

## 9 编解码和文件格式的代码解读

### 9.1 三类 JSON 文件的公开范围

| 文件类型 | 主要字段 | 保管或发送方式 |
| --- | --- | --- |
| 公共承诺 | version、suite、n、digest_hex | 可发布，验证者应固定可信副本 |
| 私有状态 | commitment、messages_hex、salts_hex | 由承诺者保管，不随根一起发送 |
| 单点开口 | version、index、message_hex、salt_hex、siblings_hex | 需要打开该位置时发送 |

公共承诺不包含消息或私有随机数。私有状态以明文 hex 形式存储全部数据，没有加密。单点开口只含目标消息和目标随机数，兄弟是摘要，不是兄弟原文。

`state_from_dict` 会调用 `_restore` 重建树，并比较保存的承诺，能够发现某些意外损坏。但若攻击者同时改写整个私有状态和它记录的承诺，这一步不能提供外部真实性；最后仍需与原来接受的公共承诺比较。

### 9.2 严格解析与输入校验

`_keys` 要求对象字段集合恰好相同，既不能缺字段，也不能默默接受额外字段。`_hex` 要求偶数字符、只含小写十六进制字符；`_unique_object` 通过 `object_pairs_hook` 拒绝重复 JSON 键，避免对同一字段出现两种解释。

`read_json` 最多读取 16 MiB 加 1 字节，用最后那一个字节判断是否超限；支持 UTF-8 及带 BOM 的 UTF-8，不接受非有限 JSON 数值。`write_new_json` 先序列化再检查同一上限，并以 `xb` 模式独占创建文件，避免把已有私有状态覆盖掉。

输出上限检查很有必要：输入的普通文字变成十六进制后体积会增大，不能仅检查输入文件大小，就写出程序自己无法重新读取的状态文件。

### 9.3 紧凑二进制格式与字节大小

公共承诺为：

```text
MTC1 4B | suite 1B | n 8B | digest 32B = 45B
```

开口为：

```text
index 8B | message_length 8B | message | salt 32B | depth 1B | path
固定开销 = 8 + 8 + 32 + 1 = 49B
完整开口大小 = 49 + message_length + 32 × depth
```

二进制开口的版本由它对应的公共承诺确定，没有额外重复存一个 `MTC1` 魔数。解码时先读消息长度，据此定位 salt 和 depth，再检查剩余字节恰好等于路径长度，不接受截断或多出来的尾随字节。

JSON 文件通常更大，因为有字段名、引号、换行和 hex 扩展。报告中的 45、116、465 字节等均指明确的紧凑格式，不是磁盘 JSON 文件的大小。

## 10 命令行接口与辅助脚本

### 10.1 三个子命令的行为

`commit` 读取字符串数组，默认按 UTF-8 编码，指定 `--hex` 时按十六进制还原 bytes。它检查输入、公共输出和私有输出是不同路径，且输出未存在，再新建承诺、保存状态和公共对象。

`open` 从私有文件恢复整棵树，然后提取目标路径。因为磁盘没有保存全部层缓存，单次命令行打开包含 O(B+n) 的恢复成本。这里 B 为全部消息字节数。

`verify` 不读取私有状态，只读取公共承诺和开口。参数 `--index` 必填，`--message` 是可选的预期 UTF-8 文字。对于任意非文字字节串，可通过 Python API 的 `expected_message` 检查；CLI 目前没有 `--message-hex` 参数。

### 10.2 脚本输入与输出文件

| 命令 | 主要用途 | 写入或覆盖的结果 |
| --- | --- | --- |
| `python -m unittest discover -s tests -v` | 直接查看测试过程 | 不重写项目结果日志，可能产生 Python 字节码缓存 |
| `python scripts/run_tests.py` | 执行测试并保存证据 | `results/tests.txt`、`results/tests.json` |
| `python scripts/demo.py` | 固定与新随机样例 | `results/demo.json` |
| `python scripts/security_demo.py` | 枚举、共享随机数、弱随机数、结构歧义 | `results/security_demo.json` |
| `python scripts/benchmark.py` | 完整性能测量 | `results/benchmark.json` |
| `python scripts/timing_diagnostic.py` | 单独复测 256、257 叶子附近 | `results/benchmark_diagnostic.json` |
| `python scripts/audit_dependencies.py` | 核心源码导入和动态执行检查 | `results/dependency_audit.json` |
| `python scripts/build_report.py` | 按既有数据重建正式报告及性能图 | 正式报告 Markdown、HTML、图像 |
| `python scripts/build_guide.py` | 按实际源码和既有结果生成本说明 | 本说明 Markdown、HTML、路径示意图 |
| `python scripts/check_guide.py` | 核对本说明、图像和本地链接 | 只输出核对摘要 |
| `python scripts/package_submission.py` | 记录源码摘要并打包 | 源码清单与根目录的作业 ZIP |

`prepare_vectors.py` 只负责从官方 ZIP 重新提取数据，不是每次测试都必须运行。交付包已包含实际使用的 `.rsp` 文件；只有需要重新提取时才要准备完整下载包。

核心、测试和基准仅使用 Python 标准库。重建 HTML 需要可选的 Python-Markdown，重画性能图需要可选的 Matplotlib；这些包只参与文档展示，不参与密码计算。

## 11 从解压到验证的完整操作

### 11.1 进入正确目录并检查解释器

以下命令用于 Windows PowerShell。从 GitHub 克隆或解压到其他位置时，应将第一行改为实际项目根目录。终端当前目录中应能看到 `src`、`tests`、`scripts`、`examples` 和 `README.md`。

```powershell
Set-Location -LiteralPath 'D:\PostGraduate\应用密码学\第一次作业'
python --version
Get-ChildItem
python -m src.cli --help
```

使用 Python 3.11 或更新版本。原测量环境是本机 Anaconda 提供的 Python 3.11.7，但运行不要求使用 Anaconda。若 `python` 不可用，可以尝试 `py -3 --version`，确认版本后将后续命令的 `python` 替换为 `py -3`，或使用已安装解释器的完整路径。

CLI 应通过 `python -m src.cli` 按包执行，以正确解析 `.merkle`、`.codec` 等相对导入。

### 11.2 先运行不改写原始结果的测试

```powershell
python -m unittest discover -s tests -v
$LASTEXITCODE
```

预期列出测试名称，最后出现 `Ran 23 tests` 和 `OK`，退出码为 0。耗时随机器变化，不需要与报告中的秒数完全一致。这些测试会运行多个子用例和数百个哈希向量，所以 23 不是实际比较次数。

测试不需要联网，也不需要安装哈希或 Merkle 相关包。如果缺 `.rsp` 文件，应先检查是否完整解压了 `tests/vectors/`，而不是通过安装一个哈希库绕过验证过程。

### 11.3 准备一个新的演示目录

使用新目录可以连续体验命令，而不会碰到之前已经存在的输出文件。

```powershell
$runDir = Join-Path 'runs' ('walkthrough-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
$publicFile = Join-Path $runDir 'commitment.json'
$stateFile = Join-Path $runDir 'private-state.json'
$openingFile = Join-Path $runDir 'opening-1.json'
```

保留这个 PowerShell 会话，因为后续命令会使用这些变量。`runs/` 是个人运行目录，不属于提交打包脚本自动收集的目录。不要为了分享演示而把其中的真实私有状态一并公开。

### 11.4 创建公共承诺

```powershell
python -m src.cli commit examples/messages.json --public $publicFile --state $stateFile
$LASTEXITCODE
Get-Content -LiteralPath $publicFile
```

预期退出码 0，公共文件包含版本 MTC1、suite 为 sha256、n 为 3，以及 64 个十六进制字符形式的摘要。它表示 32 字节、也就是 256 bit；64 是展示字符数，不是安全位数。

同样输入重新承诺，摘要通常不同，这是重新采样随机数的预期行为。不要拿正常随机化输出与第 5 章的固定测试根逐字比较。要恢复原承诺，应使用对应的私有状态。

### 11.5 打开索引 1 的 Bob

```powershell
python -m src.cli open $stateFile --index 1 --out $openingFile
$LASTEXITCODE
Get-Content -LiteralPath $openingFile
```

预期终端给出：

```text
opened index=1; compact proof bytes=116
```

开口中的 `message_hex` 应为 `426f62`，`siblings_hex` 应有 2 项，`salt_hex` 应长 64 个字符。随机数和兄弟摘要的具体值通常每次新承诺都不同。

### 11.6 验证成功和两种失败

```powershell
python -m src.cli verify $publicFile $openingFile --index 1 --message Bob
$LASTEXITCODE
```

预期输出与下面一致，退出码 0：

```json
{"valid": true, "index": 1, "message_hex": "426f62"}
```

接着故意要求错误的消息：

```powershell
python -m src.cli verify $publicFile $openingFile --index 1 --message Mallory
$LASTEXITCODE
```

这次 `valid` 应为 false，退出码 1。再要求错误的位置：

```powershell
python -m src.cli verify $publicFile $openingFile --index 0 --message Bob
$LASTEXITCODE
```

同样应为 false、退出码 1。程序输出中的 `index` 是开口自带字段，因此可能仍显示 1；不能只读索引而忽略 `valid`。这两步在验证调用者要求的语句；实际改写开口消息、随机数或路径的测试位于 `test_merkle.py`。

### 11.7 切换到 SHA3-256

继续使用同一演示目录，但选择新的输出文件名：

```powershell
$public3 = Join-Path $runDir 'commitment-sha3.json'
$state3 = Join-Path $runDir 'private-state-sha3.json'
$opening3 = Join-Path $runDir 'opening-sha3-1.json'
python -m src.cli commit examples/messages.json --suite sha3-256 --public $public3 --state $state3
python -m src.cli open $state3 --index 1 --out $opening3
python -m src.cli verify $public3 $opening3 --index 1 --message Bob
```

仍应验证为 true，开口大小仍为 116 字节，但根和路径摘要会改变。套件必须在创建承诺时确定，不能把一个 SHA-256 开口交给另一个 SHA3-256 公共对象期待通过。

### 11.8 使用自己的消息

输入文件必须是 JSON 字符串数组。下面用 PowerShell 生成 UTF-8 文件，避免中文编码由编辑器默认值决定：

```powershell
$inputFile = Join-Path $runDir 'my-messages.json'
$myMessages = @('第一条消息', '成绩73', '第三条消息')
ConvertTo-Json -InputObject $myMessages | Set-Content -LiteralPath $inputFile -Encoding utf8
python -m src.cli commit $inputFile --public (Join-Path $runDir 'my-public.json') --state (Join-Path $runDir 'my-private.json')
```

空向量输入为 `[]`；包含一条空消息的输入为 `[""]`。两者不是同一个对象，n 分别为 0 和 1。文字大小写、空格和末尾换行若属于消息内容，都影响承诺；程序不自动对文字作 Unicode 规范化或去空格。

二进制输入可以写成十六进制字符串数组，例如 `["00ff", "426f62", ""]`，在 commit 时加入 `--hex`。这时第一项表示两个字节 `00 ff`，而不是四个可见字符。

### 11.9 在 Python 程序中调用

下面代码可在项目根目录的 Python 交互环境中运行，或者保存为根目录下的单独 `.py` 文件后执行：

```python
from dataclasses import replace
from src.merkle import MerkleCommitment, verify, verify_all
from src.codec import commitment_to_bytes, opening_to_bytes

tree = MerkleCommitment([b"Alice", b"Bob", b"Carol"])
public = tree.commitment
proof = tree.open(1)
print(verify(public, proof, expected_index=1, expected_message=b"Bob"))
print(len(commitment_to_bytes(public)), len(opening_to_bytes(proof)))
changed = replace(proof, message=b"Mallory")
print(verify(public, changed, expected_index=1))
print(verify_all(public, *tree.reveal_all()))
```

预期依次输出 `True`、`45 116`、`False`、`True`。最后一行只在本地调用；若把 `reveal_all()` 的返回值发送出去，就已经公开全部消息与随机数。

## 12 实验复现与结果管理

### 12.1 先保留当前数据

若要保留交付时的原始计时，可以在运行会覆盖结果的脚本之前复制一次 results 目录：

```powershell
$snapshotDir = 'results-snapshot-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
Copy-Item -LiteralPath 'results' -Destination $snapshotDir -Recurse
```

副本名称是本次运行时生成的独立路径；无需删除已有文件。文档工具默认仍读取 `results/`，不会自动读取新副本。

### 12.2 生成测试和攻击记录

```powershell
python scripts/run_tests.py
python scripts/demo.py
python scripts/security_demo.py
python scripts/audit_dependencies.py
```

`run_tests.py` 在内存中收集测试输出，结束后统一打印并写日志，所以运行中暂时看不到逐项进度属于正常行为。想实时看到每项测试，可以使用第 11.2 节的直接 unittest 命令。

固定示例分支应保持一致，新随机示例分支会变化。攻击演示的候选顺序和弱随机数样例是固定的，所以恢复值和查询次数应能重复出现。依赖审查的 `passed=true` 表示当前源码通过其检查规则，不是一个形式化安全证明。

### 12.3 完整性能测量

```powershell
python scripts/benchmark.py
```

默认执行 5 轮重复，最大 n=4096，先测哈希微基准，再按规模测 Commit、Open、Verify。输出开始时可能较少，因为需要先完成微基准。这个脚本只重写性能 JSON，不会自动更新报告里的表格或图片。

想先确认脚本能运行，可以执行：

```powershell
python scripts/benchmark.py --max-n 1024 --repeats 3
```

但这同样会覆盖 `results/benchmark.json`。这种缩短运行不能直接套入现有正式报告，因为报告写明 5 轮和 4096 叶子；`build_report.py` 会拒绝这些不匹配的数据。要重建完整报告，应重新执行默认完整基准。

若要复测 256、257 叶子附近的波动，运行：

```powershell
python scripts/timing_diagnostic.py
```

局部复测只写 `benchmark_diagnostic.json`，不替换主基准。分析时应标注它来自另一轮运行，不将两轮数据选择性拼成一条“更好看”的曲线。

### 12.4 重建文档和提交包

已有 HTML 和图片可以直接阅读，不需要安装文档生成依赖。只有重建时才需要安装可选包；在允许联网安装的环境，可执行：

```powershell
python -m pip install Markdown matplotlib
python scripts/build_report.py
python scripts/build_guide.py
python scripts/package_submission.py
```

这些安装仅用于生成文档和图表。不要安装或引入哈希、Merkle Tree 库替换课程实现。重建本说明时会从当前源码提取片段和行号，从结果文件读取表格；若源数据不满足文档口径，生成脚本应直接报错，避免悄悄生成失真的说明。

提交包会包含规定的源码、文档、结果和所需测试数据，排除字节码缓存、页面检查截图以及完整 NIST ZIP。它不收集个人 `runs/` 文件夹，避免把运行时私有状态混入交付物。

## 13 正确性测试结果解读

### 13.1 已保存结果的含义

| 结果字段 | 保存值 | 含义 |
| --- | --- | --- |
| test_methods | 23 | 测试方法数量 |
| success | true | 所有测试通过 |
| failures / errors | 0 / 0 | 断言失败及异常数 |
| nist_total | 366 | 四个向量文件的已知答案总数 |
| additional_fips_examples | 3 | 另行列出的标准示例 |
| elapsed_seconds | 15.029 | 保存该日志的那一轮测试耗时 |

23 表示 unittest 测试方法数量。四个向量测试方法内部又执行 366 组静态已知答案检查；另外有 3 个标准示例，并非总共只哈希了 23 次。树形测试在两种套件下遍历多个规模的所有合法位置，共检查 2,274 条合法路径。

测试通过表示这些输入下的结果符合预期，并且被覆盖的错误情况能够拒绝；它不证明不存在其他程序缺陷，也不证明 SHA-256、SHA3-256 的密码学假设。NIST 官方还明确区分使用公开向量的自检与正式 CAVP 认证。（[R14](#ref-r14)）

### 13.2 四个测试文件分别负责什么

| 文件或模块 | 核查内容 | 典型错误 |
| --- | --- | --- |
| `test_hashes.py` | 官方短、长消息与标准示例 | 填充、字节序、轮常量、位掩码错误 |
| `vector_loader.py` | 把 `.rsp` 转成 bytes 与预期摘要 | Len=0 的 Msg=00 被误读成一个零字节 |
| `test_merkle.py` | 各位置、边界、重复、长度绑定、篡改与完整打开 | 左右顺序反转、多余路径被接受 |
| `test_codec_cli.py` | JSON、二进制和命令行 | 重复键、布尔索引、尾随字节、覆盖文件、过大输出 |

普通的“建树后自己生成证明，再用自己验证器通过”只是自洽性检查：若两边犯了同一种错误，仍可能一起通过。因此项目同时使用外部静态哈希预期值，以及显式展开的三叶树公式来增加检查的独立性。

### 13.3 如何定位失败

如果 NIST 向量失败，先确认加载的输入与官方长度一致，再检查算法；不要先修改预期摘要迎合程序。如果只有树证明失败，优先检查域前缀、n、索引、随机数、左右方向及路径顺序。如果只有 JSON 恢复失败，检查文件类型、编码与字段完整性。

一次失败意味着需要解释原因，而不是简单重跑到成功。若修改了源码，应保存修正后的日志，再重新生成引用这些结果的文档。性能实验不应被用来覆盖正确性检查。

## 14 攻击演示与安全性分析

### 14.1 低熵消息的字典枚举

`security_demo.py` 使用 0 至 100 的成绩字符串，秘密值为 73。按顺序枚举 0、1、…、73，共 74 个候选便可匹配未随机化摘要。这个实验利用的是输入可预测性，而不是在 2²⁵⁶ 大空间中解决一般原像问题。

当随机数提前公开时，接收者把公开随机数与每个候选一起编码，仍可用同样的候选空间恢复值。公开盐通常有助于避免跨对象共用预计算，但本作业要求对接收者隐藏，因此需要私有随机性。

### 14.2 共享随机数与部分打开泄露

在两叶树中，打开第 0 叶后，证明携带第 0 叶随机数以及第 1 叶摘要。若两叶共用随机数，接收者就同时知道第 1 叶用于承诺的随机数，于是可以枚举第 1 叶的低熵消息并比较其摘要。

项目用这一结构直接复现了攻击；改成每叶独立随机数后，“拿已打开叶随机数去匹配未打开叶”的那一种猜测没有匹配项。这只是负对照。尤其演示中的固定 A、B 字节随机数是公开测试夹具，绝不能用该负对照来声称它本身就是安全承诺。

### 14.3 随机数熵不足的影响

弱随机数示例把随机数缩成 1 字节，真值为 19，并按随机数在外层、成绩在内层的顺序枚举。前 19 个随机数各试 101 个消息，再在随机数 19 时试到成绩 73，共 `19×101+74=1993` 次查询，成功恢复秘密。

这解释了为什么不能用很短的随机数、日期或固定编号代替独立高熵随机字节。真实方案使用 32 字节随机数；它的选择与模型中的猜测难度有关，不是根据这个小实验直接测出了 256 位安全性。

### 14.4 末尾复制的结构歧义

朴素树对三叶 `[A,B,C]` 将最后一个叶子 C 复制，再合并。四叶 `[A,B,C,C]` 本来就有这四个叶子。两边进入上一层的输入完全相同，因此根相同。这不是发现了哈希碰撞，而是两个不同列表进入了同一个结构计算。

MTC1 用专用填充叶，不把填充当成 C，并将 n 编入叶子和最终封装；相同的演示中两个根不同。Bitcoin Core 的实际历史问题和防护要以其源码说明为准，本项目的 `naive_root` 只是独立编写的结构问题演示，不是 Bitcoin 实现。（[R2](#ref-r2)）

### 14.5 这些实验的实际输出

| 结果键 | 保存值 | 解释 |
| --- | --- | --- |
| unsalted_dictionary.recovered | 73 | 无随机数时恢复成绩 |
| public_salt_dictionary.recovered | 73 | 公开随机数不能消除枚举 |
| shared_salt_after_one_opening.recovered | 73 | 共享随机数打开后泄露其他低熵叶子 |
| weak_8_bit_salt.hash_queries | 1993 | 小随机数空间可以穷举 |
| duplicate_tail_naive_roots_equal | true | 朴素末尾复制有结构歧义 |
| duplicate_tail_mtc1_roots_equal | false | 本方案这两组输入的根不同 |

`valid_opening_accepted=true` 与 `modified_message_accepted=false` 分别表示诚实开口通过、被修改的消息被拒绝。一个 false 结果只说明具体输入被拒绝，不能证明任意攻击都失败。

### 14.6 Binding 与 hiding 的论证应分开表述

Binding 的直觉是：若同一位置打开为两个不同消息而最终摘要相同，那么两条计算路径必然在某个地方出现“不同输入得到相同输出”。若叶摘要已经相同，直接构成叶哈希碰撞；若中途第一次相同，构成内部节点碰撞；若只在最终封装相同，构成封装哈希碰撞。因此可以将成功双开归约到抗碰撞假设。

Hiding 的论证额外使用随机预言机模型：只要没有查询到含正确秘密随机数的叶子输入，该叶摘要可视作与候选消息无关的随机值。后续树只是对这些值和公共结构的计算。对多项式查询的经典攻击者、独立秘密 256 位随机数，可以给出随猜测查询数增长的可忽略优势界。实际 SHA 函数替代理想预言机是建模假设，不能省略。

能够公开知道的信息包括 n、套件、打开位置、被打开消息及其随机数。若两条消息本身通过业务关系互相推导，打开一条也可能揭示另一条；树无法消除数据本身的相关性。正式报告对这种部分打开保证的适用范围有更严格的说明。

## 15 性能结果与适用范围

### 15.1 测量对象与计时范围

| 环境项 | 保存值 |
| --- | --- |
| CPU | 12th Gen Intel(R) Core(TM) i5-12500H |
| Python | 3.11.7 / packaged by Anaconda, Inc. / (main, Dec 15 2023, 18:05:47) [MSC v.1916 64 bit (AMD64)] |
| 系统平台标识 | Windows-10-10.0.26200-SP0 |
| 基准时间 UTC | 2026-09-20T04:54:47.211816+00:00 |
| 重复次数 | 5 |

微基准直接测本地两个哈希函数在指定输入长度上的成本。树基准使用同一批 32 字节消息。Commit 包括新随机数、哈希与对象分配；Open 只测已经缓存树上的取路径；Verify 包括消息哈希、每一层组合和最终封装。计时不包含 JSON 文件读写和命令行启动。

每个案例预热一次，再做 5 轮。`perf_counter_ns` 记录经过时间，每轮除以循环次数换算为单次毫秒，然后报告中位数。Open 表格为便于阅读转成微秒：1 ms=1000 μs，不能把两列直接按数字比较。

计时期间关闭的是 Python 循环垃圾回收；普通引用计数与对象销毁并未消失。没有进行 CPU 绑核、恒定频率控制或调度跟踪，也没有做跨机器统计推断，因此这些数值是该实现当时的观测。

### 15.2 代表性结果

![实际节点长度下的两种手写哈希耗时](figures/hash_node_cost.png)

图 15-1 实际节点的哈希成本。柱高为五轮中位数，误差线为最小值至最大值，数据来自主基准记录。

| 套件 | n | Commit ms | Open μs | Verify ms | 开口 B |
| --- | --- | --- | --- | --- | --- |
| sha256 | 256 | 282.761 | 5.064 | 5.511 | 337 |
| sha3-256 | 256 | 444.697 | 4.382 | 8.663 | 337 |
| sha256 | 257 | 495.700 | 5.499 | 6.242 | 369 |
| sha3-256 | 257 | 921.526 | 2.823 | 5.339 | 369 |
| sha256 | 1024 | 1117.725 | 5.340 | 6.279 | 401 |
| sha3-256 | 1024 | 1701.962 | 4.927 | 10.040 | 401 |
| sha256 | 4096 | 4298.484 | 5.360 | 7.196 | 465 |
| sha3-256 | 4096 | 6861.847 | 5.314 | 11.667 | 465 |

两套算法输出都是 32 字节，所以同样 n 和消息长度下，证明大小相同。4096 叶子时，路径为 384 字节，含 32 字节消息的紧凑开口为 465 字节。SHA-256 在本次建树观测中快于 SHA3-256，但不能推广成所有语言、库、CPU 和输入场景下的绝对排名。

### 15.3 二次幂填充与性能台阶

n=256 时容量 p=256；n=257 时容量 p=512。建树哈希调用从 2p=512 次增至 1024 次，虽然真实消息只增加一条，填充叶和内部节点却明显增加。因此建树成本出现上升是该树形的可解释现象。

但它不是严格“耗时翻倍”：填充叶只有 22 字节，真实叶更长；不同类型的哈希分组数和 Python 开销不同。单点验证只增加一层，哈希调用从 10 次变成 11 次，也不应从结构上突然翻倍。

### 15.4 测量波动与异常点复测

原始数据中，SHA3-256 在 n=256 时验证中位数为 8.663 ms，n=257 时反而为 5.339 ms。另一次局部复测分别得到 5.143 ms 和 9.577 ms。模型上的调用次数是 10→11，并没有减少，因此不能从主基准的下降点推导出 257 叶子更容易验证。主基准和复测分别存放，保留了不稳定性的证据。

同一次循环中的最小值至最大值只描述那几轮的波动范围，不是跨所有运行的置信区间。复测明显变化说明稳定性不足；因为没有频率和调度证据，不能断言某个具体系统机制就是原因，更不能把所有异常都解释为算法性质。

![既有建树与验证计时](figures/merkle_scaling.png)

图 15-2 正式报告使用的主基准曲线。中位数及最小至最大区间均来自保存的结果，局部复测没有替换其中的点。

### 15.5 内存负载的统计口径

4096 叶子的满二叉树有 8191 个节点，摘要数据占 `8191×32=262112` 字节；随机数占 131072 字节；32 字节消息占 131072 字节，三者合计 524256 字节。

这只统计有效字节数据，不包括 Python 对象头、元组、列表、引用、摘要封装对象、哈希临时状态和填充缓冲区，也不是测得的峰值 RSS。报告没有进行实际内存峰值分析，应称“字节负载计算”，不能称“程序只占用约 512 KiB”。

### 15.6 性能记录的常用字段

`benchmark.json` 顶层 `environment` 记录环境，`method` 记录测量方法；`hashes` 每项对应套件和输入字节数；`trees` 每项对应套件和 n。每个耗时对象都包含 `samples_ms`、`median_ms`、`min_ms`、`max_ms` 和 `iterations_per_repeat`。

`commit_hash_calls` 与 `verify_hash_calls` 是根据树结构计算出的调用次数，不是对压缩轮逐次采样得到的性能计数器。`mib_per_s` 是按该输入字节数除以中位耗时计算的吞吐，零长度输入时这个指标为 0，不能据此说空输入“不能哈希”。

## 16 常见问题与排查顺序

| 现象 | 常见原因 | 建议操作 |
| --- | --- | --- |
| 找不到 python | 解释器未安装或命令未配置 | 检查 `py -3` 或使用已安装解释器完整路径 |
| `No module named src` | 未在项目根目录启动 | 先 Set-Location 到包含 src 的目录 |
| 相对导入报错 | 直接执行了 `src/cli.py` | 使用 `python -m src.cli` |
| `output already exists` | CLI 保护已有承诺和状态 | 新建演示目录或改用新输出名 |
| `index outside real leaves` | 索引从 1 开始数或访问填充位置 | 使用 0≤index<n，三条消息只有 0、1、2 |
| 验证结果 false | 根、套件、消息、随机数或路径不属于同一次承诺 | 成对使用该次 public 与 opening，检查预期位置和消息 |
| 同一输入根不同 | 新承诺使用新随机数 | 属于预期；用原 private-state 恢复旧承诺 |
| fixed 样例与 CLI 摘要不一致 | 一个使用公开固定随机数，一个使用新随机数 | 比较结构与验证结果，不比较这两类根 |
| SHA3 与在线 Keccak 摘要不同 | 算法后缀不同 | 确认比较对象是 SHA3-256，使用随附 NIST 数据 |
| 中文或 JSON 解码错误 | 文件不是 UTF-8 或语法不合法 | 用 UTF-8 保存字符串数组；检查引号和逗号 |
| `serialized JSON exceeds 16 MiB limit` | hex、字段和私有随机数使文件增大 | 缩小输入，或另行设计并验证大文件存储接口 |
| build_report 拒绝基准数据 | 运行了 3 轮或最大 n 不到 4096 的短基准 | 保存短基准另作分析，恢复默认完整基准再建正式报告 |
| 缺少 markdown 或 matplotlib | 未安装可选文档依赖 | 直接看现成文档，或仅在重建时安装对应包 |
| 实测速度与报告差异大 | 硬件、解释器、频率、后台负载等不同 | 核对方法和原始样本，不把差异立即判断为计算错误 |

如果只有某条测试失败，优先保留完整报错与对应向量。若哈希已知答案未通过，暂停解释性能结果；速度快但摘要不正确的实现不能作为有效比较。

## 17 方案展示与关键问题说明

### 17.1 建议的展示顺序

先用三条消息说明向量、承诺根和一条认证路径，再展示普通根的低熵枚举问题，解释为什么每叶需要独立私有随机数。接着演示 commit、open、verify 的成功和失败，再打开 `hashes.py` 说明两种手写算法的结构差异，最后展示已知答案测试和性能数据。

展示应先明确承诺对象与验证语句，再说明实现细节和实验依据，使设计原因、代码行为及结果解释相互对应。

### 17.2 应能独立回答的问题

1. 为什么一个安全哈希的确定性根仍可能泄露成绩？因为候选空间很小，可逐个计算比较；这不需要攻破一般原像抵抗。
2. 为什么随机数应保密？若提前公开，接收者仍可对当前承诺枚举候选；本方案把它作为开口材料。
3. 为什么不用一个全局随机数？打开一叶会公开它，结合其他叶摘要可能破坏剩余消息隐藏。
4. 为什么 256 位输出不等于 256 位 binding？通用碰撞搜索有生日界，理想量级约 2¹²⁸。
5. 为什么必须标记叶子和内部节点？避免把不同语义对象编码为相同类型输入空间中的歧义。
6. 为什么保存 n 和 i？固定真实向量长度与位置语义，并明确填充边界与重复消息行为。
7. 为什么路径里不传左右标记？左右方向可由目标索引逐层最低位恢复，减少重复且可能矛盾的信息。
8. 为什么 CLI 打开比 API 慢？CLI 先从消息和随机数恢复整棵树，API 示例使用已经缓存的各层。
9. 为什么用了标准常量仍是自行实现？常量是算法定义，摘要运算和控制流程由本项目代码完成，未调用第三方实现。
10. 为什么测试通过还不能证明安全？已知答案和负例验证程序行为，密码安全性仍依赖模型、假设和完整论证。

### 17.3 结论的适用前提

实验表明，两种自行实现的密码哈希通过指定已知答案测试，随机化 Merkle 承诺通过功能与篡改测试。binding 与 hiding 的结论分别建立在抗碰撞假设和随机预言机模型等条件下；性能结果适用于所记录的实现与测量环境。

这些结果不构成 NIST 认证或对全部攻击的排除。消息被打开后按协议公开，根本身不提供来源认证；统计的字节负载也不包含 Python 对象和临时内存。

## 18 查阅原始材料与继续修改

### 18.1 按问题寻找文件

想检查公式，读正式报告；想理解函数，读本说明第 7 至 10 章并对照 src；想重现结果，读第 11、12 章；想核对数值，直接查看 `results/*.json`；想核查来源，查看 `research/references-verified.json` 的查看范围和访问日期。

后续若修改叶子编码、随机数长度、树形或套件编号，就不再只是性能优化：它会改变根和证明协议，需重新考虑版本、兼容性及安全论证。若仅优化某个标准哈希的循环，应保持全部已知答案不变，再比较新旧性能。

### 18.2 来源索引

本说明中的 R 编号对应下表，也对应既有核验清单的 id。标准和设计资料用于解释已有方案；本项目的新编码、算例和数据分析由本次作业独立给出。

<a id="ref-r1"></a>

**R1** Ben Laurie, Eran Messeri, Rob Stradling. [RFC 9162 Certificate Transparency Version 2.0](https://www.rfc-editor.org/rfc/rfc9162.html). 查看范围：2.1.1–2.1.4。访问日期：2026-09-20。

<a id="ref-r2"></a>

**R2** Bitcoin Core developers. [Bitcoin Core src/consensus/merkle.cpp](https://github.com/bitcoin/bitcoin/blob/master/src/consensus/merkle.cpp). 查看范围：ComputeMerkleRoot and CVE-2012-2459 explanatory comments。访问日期：2026-09-20。

<a id="ref-r3"></a>

**R3** OpenZeppelin. [OpenZeppelin merkle-tree](https://github.com/OpenZeppelin/merkle-tree). 查看范围：Standard Merkle Trees, Leaf Hash, Leaf ordering; also inspected src/core.ts。访问日期：2026-09-20。

<a id="ref-r4"></a>

**R4** pymerkle project. [pymerkle 6.1.0 documentation](https://pymerkle.readthedocs.io/en/latest/). 查看范围：Security, Topology, Inclusion proof, Consistency proof。访问日期：2026-09-20。

<a id="ref-r5"></a>

**R5** ethereum.org contributors. [Merkle Patricia Trie](https://ethereum.org/developers/docs/data-structures-and-encoding/patricia-merkle-trie/). 查看范围：Trie structure and node encoding overview。访问日期：2026-09-20。

<a id="ref-r6"></a>

**R6** Dario Catalano, Dario Fiore. [Vector Commitments and their Applications](https://eprint.iacr.org/2011/495). 查看范围：Abstract and publication metadata。访问日期：2026-09-20。

<a id="ref-r7"></a>

**R7** NIST. [FIPS PUB 180-4 Secure Hash Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf). 查看范围：4.1.2, 4.2.2, 5.1.1, 5.3.3, 6.2; SHA-512/256 overview。访问日期：2026-09-20。

<a id="ref-r8"></a>

**R8** NIST. [FIPS PUB 202 SHA-3 Standard Permutation-Based Hash and Extendable-Output Functions](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf). 查看范围：Keccak-p, sponge, padding and SHA3-256 definition。访问日期：2026-09-20。

<a id="ref-r9"></a>

**R9** NIST CSRC. [Hash Functions](https://csrc.nist.gov/projects/hash-functions). 查看范围：Collision resistance strengths and SHA-1 transition discussion。访问日期：2026-09-20。

<a id="ref-r10"></a>

**R10** Markku-Juhani O. Saarinen, Jean-Philippe Aumasson. [RFC 7693 The BLAKE2 Cryptographic Hash and Message Authentication Code](https://www.rfc-editor.org/rfc/rfc7693.html). 查看范围：Algorithm variants, parameters and data organization。访问日期：2026-09-20。

<a id="ref-r11"></a>

**R11** BLAKE3 team. [BLAKE3 specifications and design rationale](https://github.com/BLAKE3-team/BLAKE3-specs). 查看范围：Specification repository and blake3.tex tree and SIMD discussion。访问日期：2026-09-20。

<a id="ref-r12"></a>

**R12** Lorenzo Grassi, Dmitry Khovratovich, Christian Rechberger, Arnab Roy, Markus Schofnegger. [Poseidon A New Hash Function for Zero-Knowledge Proof Systems](https://eprint.iacr.org/2019/458). 查看范围：Abstract and metadata。访问日期：2026-09-20。

<a id="ref-r13"></a>

**R13** Purdue University CS 555 course materials. [CS 555 Topic 14 Random Oracle Model and Hashing Applications](https://www.cs.purdue.edu/homes/jblocki/courses/555_Spring17/slides/Lecture14.pdf). 查看范围：Slides 5–12 and 18–24。访问日期：2026-09-20。

<a id="ref-r14"></a>

**R14** NIST CSRC. [Cryptographic Algorithm Validation Program Secure Hashing](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing). 查看范围：Byte-oriented SHA and SHA-3 response files。访问日期：2026-09-20。

<a id="ref-r15"></a>

**R15** NIST. [SHA-256 worked examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf). 查看范围：One-block abc and two-block example。访问日期：2026-09-20。

<a id="ref-r16"></a>

**R16** NIST. [SHA3-256 sample of 1600-bit message](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_1600.pdf). 查看范围：Input A3 repeated 200 times; final digest on last page。访问日期：2026-09-20。

<a id="ref-r17"></a>

**R17** Keccak Team. [Keccak specifications summary](https://keccak.team/keccak_specs_summary.html). 查看范围：Round constants and rotation offsets。访问日期：2026-09-20。
