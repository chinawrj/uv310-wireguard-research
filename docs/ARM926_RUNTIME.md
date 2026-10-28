# ARM926 正常运行环境：启动、REX/L4 任务和 DPC 回调候选

更新：2026-10-28。**离线静态结果；没有硬件执行验证。**

## 结论与范围

现有 `amss.elf` 中可以追出 ARM 启动、ARM/Thumb 交互、REX-on-L4 任务创建和一个名为 **DPC Task** 的正常任务回调队列。这给“保留原固件，额外执行一个短 Hello World”提供了具体候选机制。它不是已打通的装载器，也不等于已经能在正常 Wi-Fi/蜂窝业务运行时加载程序。

最值得先验证的是一个**有界、无等待、立即返回的 DPC callback**，只向预先确认归属的共享 RAM 写入成功标记。串口打印、文件操作、网络收发应在后续分别确认 ABI 和线程上下文后再加。不要直接把 WireGuard 的加解密或网络循环塞进这个现有 worker。

这轮分析对象是已取得的完整 ELF 文件，不是整颗闪存或完整 ARM 固件集合。完整 ELF 不保证已经识别每一处代码；加载器、其他分区和运行时产生的代码也不由本报告覆盖。此前下载模式执行成功不能证明本报告中的正常运行候选已经成功。

| 项目 | 实际值/状态 |
|---|---|
| 文件 | 私有 `work/uv310-wireguard/private/nand/amss.elf` |
| 字节数 | 1,880,064 |
| SHA256 | `388dda0d44c9ed391306c8dbd5851a612b0e68c3dc7faec189234dd7a525c9f5` |
| 格式 | ELF32 little-endian、EM_ARM、ET_EXEC，无节表/符号表 |
| 内核线索 | 内嵌 OKL4 构建信息；L4/IPC 指令路径；`rexl4.c` 诊断描述符 |
| 代码模式 | ARM 与 Thumb 混合，存在明确 BLX 交互 |
| 正常 runtime 加载自编代码 | 尚未实现 |
| 地址适用性 | 仅适用上述哈希版本，默认 VA；特别标明的启动地址是 PA |

## 1. 启动地址不能混用

ELF `e_entry = 0x00100000` 对应 program header 2 的 **PA**；其文件偏移是 `0x8000`，VA 是 `0xf0000000`。若只按 VA 找 ELF 入口，会误报没有对应段。

可复核的入口链：

1. PA `0x100000` 是 ARM `b 0x100030`。
2. PA `0x100030` 开始计算重定位偏移；`0x100078` 执行 `msr cpsr_fc, #0xd3`。
3. 后续使用 CP15 控制寄存器、cache/TLB 维护指令并建立栈。
4. PA `0x1000b8` 调用 PA `0x11a8d4`；同一文件字节的 VA 为 `0xf001a8d4`。
5. VA `0xf001a8d4` 继续调用 `0xf001a1c0`，其中可见表项清零、地址范围和映射准备工作。

这里只给出了可定位的开头，**没有宣称已证明从重置到所有应用任务的完整执行时序**。代码在 MMU 切换前后何时按 VA 执行仍需继续跟踪。不要将 PA/VA 映射关系当作所有时刻均可直接读写的地址。

应用段 VA `0x1c4000` 的入口桩是 ARM：`0x1c4004` 使用 BLX 调用 Thumb `0x25a342`，`0x1c4014` 使用 BLX 调用 Thumb `0x1c6130`。这是模式切换的直接证据，不是仅凭能反汇编成指令作判断。

部分 PT_LOAD 含诊断字符串，即使有执行标志也不是整段代码。program header 6 的 `p_flags=0x81000007`、`p_filesz=0x1440fc`、`p_memsz=0x3cb000`，**差额不能未经分析就全部标成 BSS 或可用空闲 RAM**；压缩、分页或自定义装载含义需独立核实。

## 2. 正常任务初始化的可核对链

以下名称除 `DPC Task`/`Main Task` 外均为本报告按行为赋予的分析标签，不是恢复出来的厂商符号。

```text
ARM application startup 0x1c4000
  BLX 0x1c6130 (Thumb application initialization)
    BL 0x28af36
      BL 0x229f7c (task subsystem initialization candidate)
        load callback pointer 0x28b033  [Thumb worker 0x28b032]
        prepare TCB 0x309fc8 / stack 0x30a200 / size 0x400
        name "DPC Task" / numeric priority argument 0xf3
        BL 0x28ae86
          BL 0x229dda
            BL 0x229cb0
              BL 0x229b88 (TCB/stack/list setup)
                BL 0x2290ec (L4-backed task construction)
```

关键证据：

- `0x1c6178 → 0x28af36`、`0x28af4e → 0x229f7c` 是直接 Thumb BL。
- `0x229fc2` 从 literal `0x22a120` 读取 `0x28b033`，最低位表明 Thumb 入口。
- `0x229fc4` 读取栈地址 `0x30a200`；`0x229fc8/0x229fca` 构造大小 `1 << 10`；`0x229fcc` 读取 TCB 地址 `0x309fc8`。
- `0x22a114` 是 `DPC Task`；相邻 `0x22a12c` 是 `Main Task`。在初始化调用路径中以 ADR 取得名称，而不只是孤立字符串。
- `0x229b88` 对 TCB/栈参数作非零检查、对栈地址对齐、保存名称片段、设置链表及状态，再调用 `0x2290ec`。
- `0x2290ec` 把 Thumb 包装器 `0x2290bb` 和入口信息写入新栈，随后经 `0x28b876`、`0x28b8ca` 等路径准备底层线程。
- 包装器 `0x2290ba` 最终在 `0x2290e0` 执行 `blx r4`，从 TCB 读取入口参数至 `r0`。
- `rexl4.c` 的断言描述符与该函数簇的 literal 引用关联；例如 `0x229e48 → 0x2001a2a8` 所属描述符携带“Cannot create L4 thread”错误文本。这加强了 REX/L4 任务层归属判断。

`0x1c6130` 初始化任务后还调用 `0x1c7b0c`；该函数具有 L4 IPC 等待/异常消息处理形态和相应错误文本，不能当成用户 main 返回入口。

**尚缺完整任务 ABI**：TCB 总大小、调用约定中的全部额外栈参数、优先级大小关系、任务退出语义、内存所有权、L4 capability/地址空间要求均未完全恢复。不能据这些地址直接写一个“rex_create_task”兼容头文件宣称可用。

## 3. DPC 队列：比新建 task 更小的 Hello 候选

### 数据结构和调用约定（静态推导）

| 对象 | 地址/行为 |
|---|---|
| enqueue 函数 | Thumb `0x22a040`，间接调用指针应为 `0x22a041` |
| 参数 | `r0=callback`、`r1=单个32位参数` |
| 返回值 | `r0=1` 已排队；`r0=0` 参数为空或队列满 |
| 队列基址 | `0x3097c8` |
| 项宽 | 8 字节：callback 指针 + 参数 |
| read index | `0x2eeb18` |
| write index | `0x2eeb1c` |
| 索引 | 8 位回绕，256 个物理项，保留一项判满，最多255个待处理项 |
| worker | Thumb `0x28b032`，运行时函数指针 `0x28b033` |
| worker TCB | `0x309fc8` |
| dequeue/dispatch | Thumb `0x229ff6` |
| dispatch | `0x22a038: movs r0,r5`；`0x22a03a: blx r4` |
| 现有 stack 配置 | `0x400`（1024）字节；实际可用余量未知 |

这里 `0x3097c8 + 256*8 == 0x309fc8` 与相邻 TCB 基址吻合，是边界的额外一致性证据，不是允许覆盖这些地址的授权或空闲证明。

### 队列满与失败

`0x22a048` 检查 callback 是否为零。为零直接返回0。随后令 `next=(write+1)&255`；`0x22a06a/0x22a06c` 比较 `next == read`，相等时跳过入队，不覆盖现有元素，返回0。

成功路径依次写 callback/argument、发布 write index，再调用 `0x2296a0(TCB,1)` 置位通知，最后返回1。**通知函数的返回值没有被 enqueue 检查**；因此1仅代表此函数走了成功排队路径，不保证 worker 已执行、不会断言或硬件状态可用。初次实验必须另设完成标记和超时，不能把 enqueue 成功当 Hello 成功。

### 同步和 callback 是否可以阻塞

队列操作以 `0x2be100`/`0x2be11c` 包围，保存并按原状态恢复控制状态；`0x2be100` 调用 ARM `0x2b0de8`，后者操作从 `0xff000ff0` 得到的上下文结构中的字节。恢复路径存在 `SWPB` 和条件 `UDF` trap。可以确认有临界区和嵌套状态处理；**尚不能把它简化命名为硬件 IRQ 开关或完整多核互斥锁**。

dequeue 在临界区内复制一项、推进 read index，退出自己取得的临界区后才 `blx callback`。callback 执行时这段队列修改的标志已清除；若调用前已有外层控制状态，则函数不会替调用者释放它，不能把所有情况下的callback都解释为中断已开放。但所有 callback 由同一个 worker 顺序调用；任何长计算、阻塞等待或不返回的回调都会延迟后续 DPC，甚至影响系统其他功能。

worker 的循环是：

```text
0x28b034: wait(candidate) for signal 1 via 0x229732
0x28b03a: get current TCB; clear signal 1 via 0x229668
0x28b044: dequeue and invoke one callback
           return 1 -> repeat dequeue
           return 0 -> go back to wait
```

wait 实现 `0x229732` 检查当前上下文和信号位；缺少信号时恢复临界区状态，再经 ARM `0x2e2a6c` 进入等待/IPC样式路径。以上支持它是任务上下文中的事件工作线程；**不构成允许我们在 callback 中任意阻塞的证明**。

### 这是已有使用机制，不只是理论函数

在 Thumb 代码中找到并逐条验证 enqueue 的直接调用点：`0x217c6c`、`0x26f7c8`、`0x2c2db6`。另外 `0x28ae80` 是一条包装路径。该搜索不是全程序控制流覆盖，不能据此声称只有这些 callers。

## 4. Hello World 的分阶段验证门槛

1. 确认硬件恢复后固件版本仍匹配；从正常运行上下文读取少量只读锚点，检查 VA映射、worker TCB和队列状态。不得把下载状态的地址直接复用。
2. 先解决**代码和数据装载**：可访问内存、归属、可执行权限、ARM926 I/D cache一致性、返回上下文，以及合法的一次函数调用入口。这一环当前仍未打通；本轮没有利用空洞、改 boot 或替换 M3。
3. payload 应只做固定字节标记写入并立即返回，遵守调用约定，不使用未知 libc/USB/日志函数，不占用别人的栈或内存。Thumb/ARM函数指针最低位必须匹配实际代码模式。
4. 若能在正确上下文调用 enqueue，观察返回值、完成标记、worker持续处理，以及Wi-Fi/蜂窝和看门狗正常；队列满立即退出，不无限重试。
5. 首次验收包含恢复路径与重启恢复。只有这些通过，才讨论独立低优先级 task、私有栈/heap，以及网络接口。WireGuard必须另做吞吐、调度公平性与网络路径研究。

这个路线降低的是 Hello 的调度接入复杂度，**没有消除代码执行入口和内存权限问题**。函数地址不是可从 USB 自动调用的 RPC 接口。

## 5. 复现与后续分析

公开脚本：`work/uv310-wireguard/arm926-audit/runtime.py`。

公开证据：`outputs/uv310-wireguard/evidence/arm926-runtime.json`，包含46个指令锚点、关键 literal 和少量名称。每个指令给出地址、模式、文件偏移和哈希。它不会输出整段反汇编或固件内容。

在研究工作区根目录运行（将路径按实际私有固件位置调整）：

```sh
python3 outputs/uv310-wireguard-research/work/uv310-wireguard/arm926-audit/runtime.py \
  --image work/uv310-wireguard/private/nand/amss.elf \
  --output outputs/uv310-wireguard-research/outputs/uv310-wireguard/evidence/arm926-runtime.json
```

依赖 Python 3 和 Capstone。脚本先严格校验固件 SHA256，再从 ELF program header 定位 PA/VA，逐条比较指定模式下的指令及 literal；固件不匹配立即退出。它是证据复核器，不是反汇编器覆盖率证明、函数ABI测试或刷机程序。

本轮私有工作产物在 `work/arm926-audit/private/runtime/`：`peek_arm.py` 用于定点查看，`bounded-disassembly.txt` 保存了本轮关键路径的有界反汇编。**本轮没有创建可认定为完整代码覆盖的全镜像反汇编**。全段按 ARM 或 Thumb 线性解码会把文字/literal误认作指令，甚至产生 ARM926 不支持的 Thumb-2/NEON假象；不能把那些结果作为CPU扩展证据。

继续逆向时应从这些实际调用边建立函数边界，再向外传播 ARM/Thumb状态、区分literal和跳转表。优先补齐：底层线程创建/启动ABI、地址空间/capability、缓存维护入口、worker状态读取、装载/调用入口、网络IPC路径。还需要独立确定 ELF 自定义 flags 和所有未覆盖镜像，不应以“文件已经全部读到”替代这些证明。

### 审计器自身的负向校验

追加 `--self-test` 可重跑四个 negative controls：改动一个固件字节、截去一个字节、将入口强行按 Thumb 解码、把 PA 入口误作 VA。四项均被拒绝，原版46条指令锚点通过。结果保存在 `outputs/uv310-wireguard/evidence/arm926-runtime-selftest.json`。

```sh
python3 outputs/uv310-wireguard-research/work/uv310-wireguard/arm926-audit/runtime.py \
  --image work/uv310-wireguard/private/nand/amss.elf --self-test \
  --output outputs/uv310-wireguard-research/outputs/uv310-wireguard/evidence/arm926-runtime-selftest.json
```

这是验证审计器会拒绝错误输入/解释模式，**不属于固件功能模拟，更不是实际 DPC 或线程测试**。结果明确记录 `hardware_tests=0`、`functional_simulations=0`。临时损坏样本只写系统临时目录，结束后自动清理；原固件不被修改。


## 6. 原厂队列指令的离线重放

在上述静态审计之外，新增 [queue_replay.py](../work/uv310-wireguard/arm926-audit/queue_replay.py)，使用 Unicorn 执行原厂 enqueue/dequeue 的有界真实指令；只载入 `0x229ff6..0x22a096`（末端不含）及其 literal pool。结果见 [arm926-queue-replay.json](../outputs/uv310-wireguard/evidence/arm926-queue-replay.json)。

**14组正向场景和3组指令变异对照通过。** 覆盖空callback、空队列、ARM/Thumb callback、两种进入前控制状态、4个索引位置的满队列、从0/254/255开始的255项FIFO填满/排空与环绕。每次调用检查返回值、参数、callee-saved寄存器、栈恢复、临界标志、通知时序；callback返回值设为不同常量，确认dispatcher仍返回自己的出队结果。反转判满条件、破坏callback参数、去掉callback调用均被测试捕获。

```sh
# 在公开仓库根目录；依赖 capstone 和 unicorn，镜像由所有者本地提供。
python3 work/uv310-wireguard/arm926-audit/queue_replay.py \
  --image /absolute/private/path/amss.elf \
  --out /tmp/arm926-queue-replay.json
```

同步入口/恢复、信号通知和callback均为合成替身。测试证明的是这两段指令在指定输入和替身契约下的队列行为；没有执行真实L4、IRQ、cache、MMU、watchdog或worker调度，也没有验证正常代码装载、Wi-Fi或WireGuard。代码变异只发生在模拟器内存，原始镜像不修改、不发布。此次macOS沙箱内Unicorn JIT退出异常，获工具授权后在沙箱外同样纯离线运行通过；这不是设备故障或固件故障。
