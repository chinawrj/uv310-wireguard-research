# native DHCP/DNS 集成候选：rekey-dns

2026-10-26。将 [独立 DHCP DNS 模块](DHCP_DNS_TRANSFORMER.md) 接入新的 `work/uv310-wireguard/rekey-dns/native.c`。原 `rekey-pressure` 保留，源码SHA仍为 `65b9c193117f0fc7818d20d894abcf5fe57750036434d71e17acf51c20a5e562`。**本分支只完成合成QEMU集成验证，未生成匹配stock的真实部署镜像，未写入设备，没有新的实机成功结论。**

## 数据路径变化

原始汇编 `packet1` 以 `dir=1`、`src=dst=0` 调用 `intercept()`，随后交回stock Wi-Fi路径；所以不能直接套用发送控制包的 `context()` 规则来检查这个方向。候选依靠既有hook方向限定改写入口，并复用旧forward路径的packet布局约束。源码方向和合成测试不证明真实DHCP包可见，硬件回来后仍要确认。

1. 在 phase=0、广播目的地址、LAN来源的提前返回**之前**处理指定网关的UDP回复，使首次连接尚未触发WireGuard时也能获取隧道DNS。
2. 改写前要求packet非链表、相关flag未置位、`+29 refcount == 1`，且 `head <= data <= end`、数据长度落在buffer内、整个buffer在已知RAM范围。沿用既有转发约束，不宣称已证明所有stock并发/共享规则。
3. DHCP模块检查并改写 OFFER/ACK，更新checksum。普通非DHCP网关UDP在格式允许时继续走原路径。
4. 对LAN `/24` 内的 UDP/TCP **目的端口53**请求以及**来源端口53**回复单独拦截。检查在会话状态判断之前，phase=0或stopped时仍执行，避免换钥/失败后重开网关DNS旁路。
5. 其他LAN管理流量继续保留原来的本地路径；ARP仍不进入IPv4处理。DHCP改写不启动握手，不消耗随机材料，不改变实验起始时间。

新配置 `TUNNEL_DNS` 当前是公开文档网段的合成地址 `192.0.2.53`，**不能拿去做真实resolver**。未来部署必须从用户实际网络选择经过peer可达的DNS，并验证配置；这个候选没有新增部署器或自动填入真实配置的脚本。

## 当前策略的实际限制

- 为避免后续分片没有端口而绕过检查，当前保守拦截LAN中的IPv4 UDP/TCP分片。它可能影响其他局域网服务，不能称为透明无副作用的DNS处理。
- DHCP缺少DNS且没有现有padding时返回NO_SPACE，候选会丢弃该OFFER/ACK；需要后续在真实packet尾部空间允许时有界扩展，或接通原厂配置。**不能以客户端无法获得租约作为产品完成。**
- 没有DNS透明代理：手工指定网关DNS的客户端会失败，不会自动转到隧道resolver。
- LAN `/24` 仍是硬编码假设；DNS使用其他端口、IPv6、VLAN、relay、多客户端和LAN例外策略不完整。原始单客户端限制没有被这次改动消除。
- stopped之后仍能改写DHCP，而外部DNS仍被隧道/实验期限检查关闭；没有设计“VPN不可用时明文回落”。
- 无新增线程、控制包分配或可重用密钥材料。原来的一次性实验随机池、期限、跨重启新鲜度限制完全保留。

## 遥测与错误码

新增三个32位计数器：`dhcp_rewrites`、`dhcp_rejects`、`lan_dns_drops`。它们目前供合成harness观察；A/E/R/M四页格式未改，**尚无这些计数器的AT状态页**，真实部署前还需补采集方式。

| err | 本分支含义 |
|---|---|
| `0x40` | DHCP模块拒绝结构/完整性/受支持格式 |
| `0x41` | DHCP修改前packet布局或buffer边界不满足 |
| `0x42` | LAN DNS或无法安全判断端口的LAN UDP/TCP包被拦截 |
| `0x43` | DHCP没有DNS选项且现有padding不足 |
| `0x44` | 隧道DNS配置不满足限制 |

沿用 `drop()` 的规则：phase255时不覆盖已有终止错误，所以不能只看最后err判断每一个包的去向。

## 已验证的范围

[QEMU结果](../outputs/uv310-wireguard/evidence/rekey-dns-tests.json)：**62场景、18个故意错误对照通过**。其中45场景与12个对照来自原pressure基线，新增17场景和6个对照；不是62项全新功能。

- 初始、已握手、停止状态的DHCP改写，广播回复和错误方向；改写保持phase、attempts、RNG位置、packet长度/数据指针不变。
- 链表、refcount、flag、head/end边界、坏checksum、无padding拒绝且输入不变。
- UDP/TCP的LAN DNS请求、LAN DNS回复、LAN分片拦截；普通LAN HTTPS管理路径仍逐字节不变。
- 合成DNS查询使用改写得到的resolver，经真实候选WireGuard加密后由合成peer解密；构造带A记录的DNS回复经WireGuard返回，检查客户端地址、端口、事务ID、answer及IP/UDP checksum。**没有访问真实DNS服务器，也不是实机域名解析。**
- 实验期限到达后，外部和LAN DNS保持关闭。
- `packet1` 汇编hook在拒绝坏DHCP时仅调用一次raw free，未把修改了一半的包交回stock路径。
- 6个新增错误对照分别关闭改写、推迟到phase非零、跳过buffer检查、关闭LAN请求/回复检查、忽略DHCP失败；测试均能发现。

```sh
LLVM_CLANG=/path/to/clang LLVM_LD=/path/to/ld.lld \
QEMU_ARM=/path/to/qemu-system-arm make test-dns
LLVM_CLANG=/path/to/clang python3 tools/stack_audit.py --branch rekey-dns
LLVM_CLANG=/path/to/clang python3 tools/compare_dns_size.py
```

## 资源差异

同样的公开配置与Cortex-M3/Thumb/-Oz参数，将 `native.c` **加上DHCP模块**的目标文件相加：

| 指标 | rekey-pressure | rekey-dns | 差值 |
|---|---:|---:|---:|
| 可执行代码 | 6,370 B | 7,782 B | +1,412 B |
| 可写数据 | 2,002 B | 2,014 B | +12 B |
| 只读allocated section | 1,453 B | 1,521 B | +68 B |
| intercept可见调用链frame合计 | 640 B | 648 B | +8 B |
| worker可见调用链frame合计 | 1,060 B | 1,060 B | 0 B |

证据：[目标文件](../outputs/uv310-wireguard/evidence/native-size-dns.json)、[栈分析](../outputs/uv310-wireguard/evidence/stack-audit-rekey-dns.json)。没有做真实stock镜像布局/链接容量验证，也没测IRQ总栈或运行时heap峰值。新增代码也可能占用稀缺的片上RAM，不能用历史free heap减去这些数字就宣布余量够用。

下一步：解决无padding时的有界扩展及观测接口，验证真正部署布局；硬件回来后先恢复原厂基线，再证明DHCP包经过hook、默认客户端DNS请求/回复确实经过隧道。最终Goal仍要求实机Wi-Fi、独立启动、新鲜度、稳定性及完整策略验收。
