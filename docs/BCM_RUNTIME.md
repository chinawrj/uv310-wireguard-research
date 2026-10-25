# BCM43362 runtime：地址、内存与 ABI

所有地址仅适用于 `PLATFORM.md` 指定的 stock 哈希。Thumb 函数指针最低位为1；ROM wrapper 可能再通过 RAM slot 跳转，不能把入口和实际 body 混为一谈。

## 镜像布局与 CRC

| 地址/位置 | 用途 |
|---|---|
| 0x9df8 | post-CRC native probe hook |
| 0x9e18 | 版本字符串指针；指向自有192B状态缓冲 |
| 0x2f340 | 原生补丁 load/link 区域起点 |
| 0x1e840 | heap 起点字，按补丁末端向256B对齐提升 |
| 0x2f28e | CRC 字段，写入此前前缀的 zlib.crc32 |
| 0x2462a | 原有完整性检查代码，保持原字节不变 |
| 0x25fc / 0x1bc64 | 双向 packet hook slot |
| 0x178 / 0x144 / 0x12c | timer / idle / free hook slot |

候选构建只允许改上述明确字位置及新追加的 probe/state/version 区域；逐字节 diff 检查 stock 范围。CRC 验证 `crc32(image[:0x2f292]) == 0x2144df1c`。早期在自检前放置入口失败，后来的 post-CRC 路径才验证正常启动。CRC 是镜像完整性检查，不等于建立了安全启动签名绕过。

最新 memory 候选210352B，code/constants14948B，state1864B，heap start0x33600，reservation17264B。reservation 包含对齐等成本，不等于仅代码大小。镜像含私有材料，不公开。

## ROM / RAM ABI 索引

| ROM入口 / RAM slot | stock target / 作用 | 验证注意 |
|---|---|---|
| 0x80640c / 0x128 | 0x806415，aligned malloc | 入口经slot，先排除递归hook |
| 0x8062d8 / 0x12c | 0x8062e1，free | native 用于观察控制包真实归还 |
| 0x806bc5 | raw packet allocation 路径 | 与普通heap malloc不同 |
| 0x806d80 / 0x628 | 0x806d89，packet allocator | 高层路径有上下文/元数据需求 |
| 0x80aa54 / 0x2b4 | 0x80aa5d，SDPCM packet wrapper | 与 host QDSP packet布局不同 |
| 0x80fc34 / 0x890 | 0x80fc3d，Wi-Fi TX wrapper | caller与ownership需结合live证据 |
| 0x806604 / 0x150 | 0x80660d，clock updater候选 | 运行实现改读cached clock，避免新增更新竞态 |
| RAM0x267c | 原厂维护cached tick | 不是经标定的CPU性能计时器 |

完整静态表见 [rom-runtime-abi.json](../outputs/uv310-wireguard/evidence/rom-runtime-abi.json)。该文件生成较早，`live_dispatch_read=false` 等应按当时范围解释；后续 path/buffer/active-send/rekey 证据增加了实机验证，不能整体把所有静态候选都升级成确认函数。

## Packet 布局与 ownership

BCM packet：`+8 head`、`+12 end`、`+16 data`（32位指针），`+20 len`（u16），`+22 flags`，`+29 refcount`。地址必须在0x2000..0x3c000有效区间，长度必须落在buffer边界。Ethernet头14B，EtherType位于data+12。

两个方向的hook拦截真实Wi-Fi/SDPCM链路；返回“consume”时使用原raw-release路径，不能既交给stock又释放。主动控制包分配512B所需实际payload计账580B，另有8B header；提交后由真实free hook确认释放，不能以submit返回值替代生命周期证明。

free/packet/timer/idle路径的汇编保存寄存器、APSR/标志位和中断掩码。早期忽略APSR导致的失败促成了后续版本。timer侧实测IPSR16、PRIMASK0；crypto worker在idle线程IPSR0、mask0分阶段执行；共享状态claim/publish在短PRIMASK临界区中操作，返回时恢复原mask。

## 堆与栈观测

| RAM地址 | 含义 |
|---|---|
| 0x26c8 | arena总字节 |
| 0x2688 | 当前allocated payload |
| 0x26a4 | 当前allocated headers |
| 0x26cc | 历史payload峰值 |
| 0x2690 | 分配失败次数 |
| 0x26c4 | free-list首节点；节点+0大小，+4 next |
| 0x1c3e8 / 0x1c3ec | stack floor / top 指针 |

memory_snapshot 保存PRIMASK并关中断，最多遍历256个节点；节点对齐、范围、单调无重叠、大小均校验，非法时valid=0。栈区需在RAM内、长度0x1400，扫描0x5354414b sentinel。实测栈floor0x3a96c/top0x3bd6c；sentinel unused是观测下界信息，不是未来调用链安全证明。测试含坏节点、循环、越界大小、坏栈界和mask恢复。

实时小计能满足：arena−payload−allocated_headers−free_nodes×8=free_payload。最大连续块另测。历史peak_payload不能与当前headers混合成“历史最小空闲”；最新 arena−peak_payload=2212B只是尚未扣元数据的上界。详细数值见 [MEMORY_RUN.md](MEMORY_RUN.md)。
