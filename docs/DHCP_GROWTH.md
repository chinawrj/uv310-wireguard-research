# DHCP DNS 有界扩展候选

2026-10-26，`rekey-dns-grow`。解决上一版在没有DNS选项且现有padding不足时直接拒绝OFFER/ACK的问题。**只在合成主机/Cortex-M3验证，未部署；原rekey-dns源码与历史证据保留。** 最终目标仍是设备内Wi-Fi流量通过WireGuard，并非QEMU通过即可完成。

## 行为与协议

新函数 `dhcp_dns_rewrite_grow(frame, &size, capacity, server, resolver)` 先调用原严格解析器。已有DNS或已有充足padding走原路径；只有原解析器确认OFFER/ACK有效、所有DNS选项均缺失、无写入并返回NO_SPACE后才扩展。

1. 找到主options区END（255），最多利用其后6个连续零padding。
2. 缺几个字节就增加几个，范围1–6字节；扩展后frame不得超过2048字节，不能超过调用方证明的尾部容量。
3. 从尾向头搬移重叠区，保留未消耗的DHCP尾部字节及Ethernet尾部字节；写入option6、长度4、resolver IPv4以及END。
4. 更新IPv4总长/头校验和、UDP长度/校验和，计算结果为零的UDP校验和编码为ffff。最后更新输出size。
5. 所有可失败检查在扩展写入前完成；错误时frame和size不变。无heap、无替换packet、无额外线程。

参数size/server/resolver不得与frame或彼此发生有害别名，frame必须连续独占。新native候选沿用链表、flag、refcount、head/end、RAM范围检查，将end-data作为容量；成功后同步stock packet的16位长度字段。单次扩展不启动握手、不消耗RNG、不改变原phase或实验期限。

容量不足时仍然拒绝；没有将DNS旁路当作回退。代码没有改变单客户端、IPv4、固定LAN /24、手动网关DNS被拒绝等已有限制。也没有验证stock上下游是否允许该报文增长，真实部署前必须核对全部长度相关元数据及传递路径。

## 离线证据

- [独立模块](../outputs/uv310-wireguard/evidence/dhcp-growth-local.json)：100个主机向量和100个Cortex-M3向量，7个错误对照。两套运行使用同一批报文，不代表200种独立case。本机只运行UBSan，Linux ASan+UBSan已通过，证据见下。
- [native候选](../outputs/uv310-wireguard/evidence/rekey-dns-grow-tests.json)：67场景/20错误对照。其中62场景继承上一候选，新增5场景覆盖增长、恰好容量、容量少1字节、利用5字节padding、停止状态；新增2个错误对照分别漏提交packet长度和夸大尾部容量。
- 独立向量另覆盖：非零END尾部、Ethernet尾部、IP options、UDP零校验和、不同options偏移、2048上限、超限、原模块所有60个命名case。Golden输出由Python单独生成，比较完整报文；host按声称容量分配，QEMU检查前后哨兵。
- 旧“跳过native边界检查”的负向测试改用head错误场景。新模块自身再次检查capacity >= size，所以只跳过上层tail检查仍会被下层拒绝；不能据此声称整个上层检查无用。

```sh
LLVM_CLANG=/path/to/clang LLVM_LD=/path/to/ld.lld \
QEMU_ARM=/path/to/qemu-system-arm make test-dhcp-growth test-dns-grow
LLVM_CLANG=/path/to/clang python3 tools/stack_audit.py --branch rekey-dns-grow
LLVM_CLANG=/path/to/clang python3 tools/compare_dns_size.py
```

## 资源与剩余验证

[目标文件比较](../outputs/uv310-wireguard/evidence/native-size-dns-grow.json)包括native与两个DHCP编译单元。相对rekey-dns：代码+518B（总8,300B）、可写全局状态+0B（2,014B）、只读allocated section+40B（1,561B）。[栈审计](../outputs/uv310-wireguard/evidence/stack-audit-rekey-dns-grow.json)的intercept可见调用链合计656B，比上一版+8B；worker仍1,060B。这些不是完整IRQ栈上界、最终链接镜像占用或运行时内存峰值。

下一步是可读取的DNS计数器、真实stock链接布局与长度传播分析。设备回来后按 [native DNS验收表](NATIVE_DNS.md#接续开发与硬件验收门槛) 先复原厂基线，再验证租约、查询/回复、续租、换钥、中断无明文回落。随机数、跨重启新鲜度、独立启动、多客户端和长时间稳定性仍未完成。

## Linux独立复现

[运行40252774107](https://github.com/chinawrj/uv310-wireguard-research/actions/runs/40252774107) 对提交 `62ae5a21225b0d676aa5b97e9988326340436229` 全部通过；扩展模块100个host/Cortex-M3向量和7个错误对照、native 67场景/20错误对照均通过。host启用ASan+UBSan，归档ZIP digest与GitHub一致，归档报告的源码哈希逐项与仓库核对。

长期证据：[运行和哈希](../outputs/uv310-wireguard/evidence/ci-dhcp-growth/run.json)、[扩展模块](../outputs/uv310-wireguard/evidence/ci-dhcp-growth/dhcp-growth-tests.json)、[native场景](../outputs/uv310-wireguard/evidence/ci-dhcp-growth/rekey-dns-grow-tests.json)、[代码大小](../outputs/uv310-wireguard/evidence/ci-dhcp-growth/native-size-dns.json)、[栈审计](../outputs/uv310-wireguard/evidence/ci-dhcp-growth/stack-audit-rekey-dns-grow.json)、[环境](../outputs/uv310-wireguard/evidence/ci-dhcp-growth/ci-environment.json)。未访问设备，不是硬件稳定性证明。

原厂长度消费者的后续核对见 [STOCK_PACKET_LENGTH.md](STOCK_PACKET_LENGTH.md)：精确ROM前段离线重放，不是完整发送或实机验收。
