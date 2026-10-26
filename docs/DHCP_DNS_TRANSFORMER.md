# DHCP DNS 改写原型（尚未接入 native hook）

2026-10-26。根据 [固件配置链分析](DNS_ROUTING.md)，原厂 Web handler 没有可用的 DNS 参数，内部函数地址也不是可直接调用的外部 API。本轮新增可在 Cortex-M3 编译运行的纯 C 模块，供后续接入 BCM Wi-Fi 收包路径；**没有修改既有 rekey-pressure/native.c，没有生成或部署固件，DNS 旁路仍未修复。**

源码：[dhcp_dns.c](../work/uv310-wireguard/dhcp-dns/dhcp_dns.c)、[接口契约](../work/uv310-wireguard/dhcp-dns/dhcp_dns.h)。模块不接触 USB、设备内存地址、私钥或网络接口。

## 行为与边界

- 输入完整、连续、可独占修改的 Ethernet IPv4 帧。调用方必须先核对真实 stock → Wi-Fi 方向、buffer 范围、单包布局和所有权；本函数拿到的裸指针不能替代原厂 packet 结构校验。
- 仅处理指定原厂 DHCP 服务器发往 UDP 68 的 UDP 67 报文；IPv4 header、UDP length、有效的已有非零 UDP checksum、BOOTP magic cookie、Ethernet hardware type/length 都先检查。IPv4 UDP checksum 为零允许接收，改写后生成有效 checksum。
- 对 OFFER 和 ACK 改写 DNS 选项6。选项在 main、file、sname 的使用规则由 overload 决定；按 main → file → sname 顺序处理重复片段，允许单片段不是4字节整数倍，但拼接后的 DNS 长度必须非零且为4字节整数倍。依据 [RFC 3396](https://www.rfc-editor.org/rfc/rfc3396.html) 的拼接规则，以及 [RFC 2132](https://www.rfc-editor.org/rfc/rfc2132.html) 的 DNS/overload 定义。
- 将所有 DNS 地址槽都写成配置的同一个隧道 resolver，避免保留备用明文 DNS。这个原型暂不提供多个不同 resolver 的配置接口。
- 缺少选项6时，只在 main END 后有至少6个零填充字节时插入；保持 Ethernet/IP/UDP 长度不变。没有空间则明确返回错误，不申请内存、不移动 packet 边界。
- 对识别范围内报文完整校验后才写入；所有负返回都保证输入逐字节不变。已有DNS分段、未知选项、租期、服务器标识、事务ID、客户地址等非目标字段保留。
- 不递归、不分配堆、不使用可写全局状态。单帧上限2048字节。

该模块不执行完整 DHCP 状态机或身份认证。来源 IP 匹配不是认证；未经信任的 LAN 输入不能仅凭来源地址进入此改写路径。它只允许 IPv4 unicast 类 resolver，且拒绝网关所在固定 `/24`，因为当前 native WireGuard 代码绕过这个网段；调用方仍需验证真实 DNS 可达、peer 路由和配置一致性。

| 返回值 | 含义 | 接入时要求 |
|---|---|---|
| `REWRITTEN` / 1 | 已替换DNS或插入选项，并更新UDP checksum | 仍需确认stock发送链正确接收修改 |
| `UNCHANGED` / 0 | 不属于本模块处理范围，如NAK、其他来源、其他端口 | **不是**“允许通过VPN策略”的判断 |
| `REJECT` / -1 | 识别范围内的结构、checksum或受支持格式不满足 | 由受保护网络策略处理，不可默默旁路 |
| `NO_SPACE` / -2 | 无DNS，且没有足够现有填充空间 | 需要后续有界扩容/原厂配置方案；直接放行会失去DNS保证 |
| `BAD_CONFIG` / -3 | resolver配置不满足当前路由限制 | 配置错误不能降级为默认明文DNS |

协议范围明确：无 VLAN/DHCPv6 支持；没有证明 relay 场景；不做 IPv4 分片重组。为了不能把后续片段错当普通 UDP 放行，指定服务器的所有 UDP IPv4 分片都返回 REJECT，可能影响同一服务器的其他 UDP 服务，接入时必须定义处理策略。DHCP message type 仅接受 main 中唯一的1字节值，overload也仅允许 main 中唯一的合法值；不是任意 DHCP 扩展的通用代理。

## 测试与资源

入口 [tools/test_dhcp_dns.py](../tools/test_dhcp_dns.py) 使用 Python 独立构造输入及期望输出，C 测试程序逐字节比较，而非只检查函数返回值。

- 60个命名用例：OFFER/ACK、多个DNS、1+3及255+1字节分段、跨三个字段拼接、无DNS插入、padding不足、overload异常、截断选项、非零/零checksum、计算结果为零时写成 `0xffff`、IPv4 options、DF/分片、来源/端口范围及配置错误等。
- 基础292字节报文的每个截断长度全部检查；另有1,000次带非零 UDP checksum 的单bit破坏，均应拒绝且不修改输入。合计1,352个主机向量。
- 同一60个命名用例用 Cortex-M3 QEMU 运行，含不同地址对齐及buffer前后保护区，逐字节核对。
- 5个故意错误对照：跳过UDP完整性检查、错误时部分修改、接受坏DNS总长度、每个分段重新开始DNS偏移、写错checksum；测试均须发现错误。

本机结果：[dhcp-dns-prototype-local.json](../outputs/uv310-wireguard/evidence/dhcp-dns-prototype-local.json)。Mac 的 AddressSanitizer 测试进程在进入主程序前超时；普通版本同一首个用例正常结束。故本机只记录 **UBSan** 通过，不声称ASan通过。Linux CI运行 [40247318186](https://github.com/chinawrj/uv310-wireguard-research/actions/runs/40247318186) 已通过 **ASan+UBSan** 的1,352个向量、60个Cortex-M3向量和5个错误对照；原始JSON已核对artifact摘要及源码hash并归档：[Linux结果](../outputs/uv310-wireguard/evidence/dhcp-dns-prototype-linux.json)。被测源码提交为 `fe924fc748c3788f1250bde912b8733416127e77`。

LLVM 18 Cortex-M3 / Thumb / `-Oz` 独立目标文件：代码1,008字节、可写全局数据0字节、只读allocated section 40字节（含展开信息等，不是全部最终镜像开销）。`dhcp_dns_rewrite` frame72字节，`scan/rewrite_options` 各24字节，最长可见直接链约96字节。不是接入原厂IRQ/调用链后的总栈上界，也不是运行时内存峰值或CPU性能数据。

```sh
LLVM_CLANG=/path/to/clang LLVM_LD=/path/to/ld.lld \
QEMU_ARM=/path/to/qemu-system-arm make test-dhcp-dns
```

Linux需要clang sanitizer runtime，CI已配置安装。Mac有SDK选择问题时可指定 `HOST_SDKROOT`；本次本机复现使用Xcode配套SDK和 `HOST_SANITIZERS=undefined`。报告明确记录启用的sanitizer；不能把本机UBSan报告当成Linux ASan结果。

## 到最终目标仍缺什么

1. 在真实 native `intercept()` 的 LAN提前返回之前接入，并保证buffer所有权、调用方向和资源预算；目前还是独立模块。
2. 明确 NAK、无填充空间、异常DHCP、重租约、多个Wi-Fi客户端的策略；不能让“安全失败”变成无法使用的产品。
3. 处理直接向网关/LAN DNS发查询的旁路；DHCP改写无法约束手动DNS设置，也没有覆盖IPv6。完整VPN需要独立的代理/阻断与例外设计。
4. 用真实DHCP ACK、客户端默认设置、对端抓包、隧道断开及跨换钥来证明端到端行为。现在没有硬件验收，不能宣告已实现“Wi-Fi所有流量走WireGuard”。

后续状态：已在新的 [rekey-dns候选](NATIVE_DNS.md) 中完成离线native hook集成；不覆盖本文的历史证据边界，实机未验证。
