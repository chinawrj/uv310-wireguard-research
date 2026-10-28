# ARM926 镜像完整性与装载地址地图

2026-10-28，离线审计已有 UV310 NAND 读取记录；本轮没有访问设备、网络、USB，也没有刷写。机器代码分析另见 ARM926 启动/接口研究。此文只回答**我们实际上拿到了什么、缺什么、如何正确装载分析**。

## 结论

已经取得 `amss.elf` 的**全部 ELF 声明文件范围**：1,880,064 B（`0x1cb000`），13 个 program header 均没有指向文件之外。SHA-256 为 `388dda0d44c9ed391306c8dbd5851a612b0e68c3dc7faec189234dd7a525c9f5`。这足够继续研究这个 AMSS 容器内的内容，但**不能称为“整个 ARM926 固件已完整导出”**，更不代表已恢复全部源码或正常运行时 API。

尚缺已识别 ARM 启动分区 `FSBL`、`OSBL` 的完整镜像、PBL/BootROM 内容，以及正常联网状态的 ARM RAM/页表快照。仅有下载模式 ARM applet 的执行证明，不能据此承诺正常 Wi-Fi 与蜂窝继续工作时可以运行自定义 ARM 程序。

证据：[arm926-inventory.json](../outputs/uv310-wireguard/evidence/arm926-inventory.json)；复现工具：[inventory.py](../work/uv310-wireguard/arm926-audit/inventory.py)。公开文件只包含结构、地址、长度、哈希和读取状态，不包含原始固件、配置或用户标识。

## 1. 文件来源和读取覆盖

AMSS 分区从物理 NAND block 24 开始；历史读取程序使用 2,048 B/page、64 pages/block（131,072 B/block），每页分四次取得 512 B 数据。保存的 `amss.elf` 来自 row **1536–2453**，每 row 的 sector **0–3**，共 **3,672 次读取**。离线工具逐项检查序号，无缺项、重复、乱序；日志中的文件尺寸/哈希和当前文件一致。

历史 reader 的接受条件为：超时字段为 0、每次数据 512 B、`status & 0x110 == 0`、`buffer_status & 0x100 == 0`。全部已保存 sector 满足这些检查。这里复核的是原 reader 使用的控制器检查；没有把非零状态一概解释成错误，也没有未经硬件文档证明就把其低位称为某种 ECC 修正计数。

另一份独立读取的 `amss-first64k.bin` 为 65,536 B（128 次 sector 读取），逐字节等于 `amss.elf` 的前 64 KiB，SHA-256 `59ada579fbab41eb82d37de79087d8d1bd7f762c4eb10ae6e3e163986b9e3709`。这提供了**前缀重复读取的一致性**；不等于整份镜像做过第二遍独立读回。完整读取日志没有逐 sector 保存内容哈希，因此不能拿两份日志的地址顺序相同，推导两次全部数据相同。

关键历史失败也必须保留：更早的 `amss-code-read.json` 原本试图读取整个 AMSS 分区，在第 **3,673** 次读取，即 **row 2454 / sector 0** 失败，返回 `status=0x3030`、`buffer_status=0xff0101`，触发 reader 的错误检查，没有保存 `amss-physical.bin`。这个位置恰好位于 ELF 声明结束之后。后来改为只读 ELF 声明范围才成功。

因此：AMSS 分区共 **3,538,944 B**，现已保存 **1,880,064 B**，其余 **1,658,880 B** 没有成功保存。旧日志 scope 使用了“unused partition tail”措辞，但目前证据不足以证明这些区域全部为空；应改读为**ELF 之外、尚未取得的分区尾部**。这不是全 NAND 克隆，未保留完整 OOB，也没有验证坏块映射。历史脚本按连续物理 row 读取，没有通用坏块跳过算法。

## 2. ELF 结构和逐段地图

ELF32、小端、`EM_ARM`、`ET_EXEC`；`e_entry=0x00100000`，`e_flags=0x202`，OSABI 字节 `0x61`。Program header 从文件 offset 52 开始，13 项，每项 32 B；section header offset/count 都为 0，故不能依靠原始 section/symbol 表完成函数恢复。

所有值为十六进制；`filesz` 表示文件中实际有数据的长度，`memsz` 是 header 声明的内存长度。表中每一段的文件范围均已存在。

| 段 | 类型 | 文件 offset | VA | PA | filesz | memsz | flags |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | PT_NULL | 0x0 | 0x0 | 0x0 | 0x1d4 | 0x0 | 0x07000000 |
| 1 | PT_LOAD | 0x1000 | 0x5a9000 | 0x5a9000 | 0x3e8 | 0x1000 | 0x02200000 |
| 2 | PT_LOAD | 0x8000 | 0xf0000000 | 0x100000 | 0x1ca8c | 0x222c0 | 0x00000007 |
| 3 | PT_LOAD | 0x2c000 | 0xf0024000 | 0x124000 | 0x6000 | 0x6000 | 0x00000006 |
| 4 | PT_LOAD | 0x38000 | 0xb0000000 | 0x190000 | 0x156c7 | 0x156c7 | 0x00000005 |
| 5 | PT_LOAD | 0x50000 | 0xb0060000 | 0x1b0000 | 0x188 | 0x13004 | 0x00000006 |
| 6 | PT_LOAD | 0x52000 | 0x1c4000 | 0x1c4000 | 0x1440fc | 0x3cb000 | 0x81000007 |
| 7 | PT_LOAD | 0x197000 | 0x58f000 | 0x58f000 | 0x0 | 0x6000 | 0x06400006 |
| 8 | PT_LOAD | 0x198000 | 0x595000 | 0x595000 | 0x0 | 0x1000 | 0x0e400006 |
| 9 | PT_LOAD | 0x199000 | 0x596000 | 0x596000 | 0x2000 | 0x2000 | 0x01000006 |
| 10 | PT_LOAD | 0x19c000 | 0x598000 | 0x598000 | 0xb08 | 0xb1c | 0x01000007 |
| 11 | PT_LOAD | 0x19d000 | 0x20000000 | 0x20000000 | 0x24000 | 0x24000 | 0x05300005 |
| 12 | PT_LOAD | 0x1c2000 | 0xb0028000 | 0x5a0000 | 0x9000 | 0x9000 | 0x00000006 |

段 0 的 `0x1d4` 恰好等于 ELF header 52 B + 13 × 32 B program headers，不应当反汇编成入口代码。段 1 的低 R/W/X 权限位均为 0，高位含厂商扩展，不能凭 `PT_LOAD` 就归类为普通程序文本。

段 7、8 的 `filesz=0`，所以没有可从文件中“提取”的代码字节。它们的内存声明存在，并不是读取遗漏；内存用途要结合 vendor loader 解释。其他段的 `memsz > filesz` 也不是缺失文件的直接证据。

### 地址不能用一个统一基址处理

入口 `0x100000` 落在段 2 的**物理地址范围**内，且正好是段起始 PA；它不落在任何 `PT_LOAD` 的 VA 范围内。段 2/3 的 VA 位于 `0xf0000000` 一带，段 4/5/12 位于 `0xb0000000` 一带，其他段还有不同映射。

分析器应保留每个 segment 的 offset、VA、PA，按启动阶段追踪地址转换。若把整份文件简单按 `0x100000` 加载，会把 header/padding 当代码，错接 literal、函数指针和跨段引用。声明 VA/PA 也不是现场 MMU 页表的证明；启动代码对 CP15/MMU 的操作需要单独追踪。

### 压缩、分页和零初始化的边界

段 6 最值得优先研究：文件长度 **1,327,356 B**，声明内存长度 **3,977,216 B**，flags 为 **`0x81000007`**。目前这份结构审计**不解码厂商高位 flags，也不确认压缩算法或分页语义**。尤其不能直接把 2,649,860 B 的差值全部解释为 BSS，再据此宣布有大量空闲 RAM。应以 loader 的搬运/展开/页加载逻辑、容器内部结构及解码后的实际结果为证。

本报告保持原始结构视角。如果后续启动研究能够重放解压，应另外记录“输入段 → 算法/参数 → 输出长度/哈希 → 地址范围”，不要把派生展开文件冒充 NAND 原始读取。没有 section table 也不等于所有内容都可执行；ELF 内可能混有表、元数据或其他处理器的内容，须逐项归属。

## 3. 已知启动分区与缺失范围

以下来自私有 `block-2-partition-table.bin` 的 1,024 B MIBIB 表，与历史 JSON 一致；表 magic 为 `0x55ee73aa/0xe35ebddb`、version 3、10 entries。

| 对象 | 起始 block | 分区长度 | 本轮可确认的材料 |
| --- | --- | --- | --- |
| MIBIB | 0 | 10 blocks / 1,310,720 B | block 0/1/2 的各 512 B header 与 block 2 分区表；不是整个 MIBIB 分区 |
| FSBL | 16 | 3 blocks / 393,216 B | 已确认分区名/范围；审查的 UV310 NAND 集合没有其完整镜像 |
| OSBL | 19 | 5 blocks / 655,360 B | 已确认分区名/范围；审查的 UV310 NAND 集合没有其完整镜像 |
| AMSS | 24 | 27 blocks / 3,538,944 B | 本报告的 1,880,064 B ELF；剩余分区未保存 |
| DSP1 | 51 | 27 blocks / 3,538,944 B | 仅首 65,536 B；不能当完整 DSP1 固件 |
| DSP2 | 78 | 293 blocks / 38,404,096 B | 有独立分段采集/静态研究；其完整性由 DSP2 证据负责，本报告不扩大结论 |
| PBL/BootROM | 不由上述 NAND 分区表确定 | 未确定 | 当前集合没有可核验的完整 ROM dump |
| 正常运行 RAM | 不适用 | 未确定 | 缺少 ARM 正常联网态 RAM/页表/任务快照 |

SIM_SECURE、FTL、EFS 分区仅保留已有表的结构元信息，不为此研究读取或发布其中用户数据。缺少 FSBL/OSBL 说明启动链尚不完整；但即使以后补全这些分区，也不能声称“完全逆向 ARM926”，因为硬件行为、ROM、运行时状态和间接调用仍需分别验证。

## 4. 离线复现与守卫

从 public repo 根目录运行，仅对拥有者合法持有的私有材料使用；两个输入目录应指向**原项目目录**中的位置，而不是 public repo 的同名目录：

```sh
python3 work/uv310-wireguard/arm926-audit/inventory.py \
  --nand /path/to/original-project/work/uv310-wireguard/private/nand \
  --capture-evidence /path/to/original-project/outputs/uv310-wireguard/evidence \
  --out outputs/uv310-wireguard/evidence/arm926-inventory.json
```

只需 Python 标准库。工具不会导入或执行历史 USB 读取脚本，不会加载固件代码运行，也不会上传文件。它检查固定 AMSS 身份、ELF 边界、分区表一致性、完整读取序列、原 reader 的错误位、独立 64 KiB 前缀以及历史边界失败。输出为固定名称文件的脱敏统计；不会输出从固件搜索到的字符串、raw bytes 或绝对私有路径。

本轮真实材料复现通过。另用内存合成 ELF 验证截断 program header、超文件 segment 和 `filesz > memsz` 会被拒绝；用历史日志副本验证删除一次读取、改文件哈希和设置错误位也会被拒绝。**2 项正向对照、6 项错误对照全部通过**，逐项结果与工具哈希见 [arm926-inventory-guards.json](../outputs/uv310-wireguard/evidence/arm926-inventory-guards.json)。错误对照只检查审计工具的防误报能力，不证明固件可运行。

复跑 [test_inventory.py](../work/uv310-wireguard/arm926-audit/test_inventory.py)：

```sh
python3 work/uv310-wireguard/arm926-audit/test_inventory.py \
  --nand /path/to/original-project/work/uv310-wireguard/private/nand \
  --capture-evidence /path/to/original-project/outputs/uv310-wireguard/evidence \
  --out outputs/uv310-wireguard/evidence/arm926-inventory-guards.json
```

测试只在系统临时目录保存日志副本和统计结果，固件始终从原私有路径只读，不复制到仓库。它先要求真实输入基线通过，再检查每次错误都触发预期诊断，避免以无关输入失败冒充错误对照成功。

## 5. 后续推进顺序

1. 离线继续追踪 AMSS 入口和 MMU/搬运代码，明确段 6 的展开/分页逻辑；建立可复现的派生镜像流程。
2. 根据实际启动地址建立每段的代码/数据分类和跨段引用；恢复 ARM↔DSP 控制接口、消息队列与 watchdog 要求。先确认正常运行状态是否有可复用的任务上下文，再评价 WireGuard 放在 ARM 上的收益。
3. 硬件恢复后才考虑有界补读 FSBL/OSBL，保留原始读取日志和至少一次完整独立复读；不需要因此写 NAND。AMSS 尾部的 ECC/空白/坏块原因也需单独验证，不能盲目跳过错误。
4. 最后才讨论正常固件中的最小 hello-world 或消息回显。完成标准是可重复进入和退出、原厂 Wi-Fi/蜂窝保持工作，不能用 loader 模式成功替代。
