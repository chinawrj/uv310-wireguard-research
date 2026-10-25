# 后续开发与验收路线

## P0：恢复和定位，不扩大实验

设备在线后先原厂read-only身份、镜像hash、Wi-Fi/DHCP/ARP/蜂窝基线。改进followup的错误日志：USB不存在、拓扑不符、project mismatch、AT ERROR、主机sourceIP变更都给不同错误和时间；保留原始失败JSON，不覆盖。若有重启counter或watchdog原因入口，先静态确认再只读观察。

内存实验在first renewal附近失联，只是相关性。分别评估crypto临时栈/堆、status遍历IRQ临界区、allocation failure时序、包所有权、设备供电/USB枚举变化。应先QEMU注入失败/边界，再单变量短实机实验。不要一上来延长deadline、增池或增加日志负载。

## P1：独立启动必要条件

- 合格device RNG/reseed或经验证native modem桥；明确失败/健康检查与启动可用条件。
- 跨重启新鲜度与TAI/等效设计；掉电持久化一致性和计数回滚处理。
- heap/stack峰值、最小可分配块、fragmentation和最差并发路径；多次重启/重复换钥内存不持续下降。
- 不复用per-build实验材料；设计真正的私有配置和密钥生命周期，而不是直接把测试镜像设为自启。

## P2：网络行为

多个Wi-Fi客户端的映射和回程隔离；DNS策略；完整IPv6旁路/阻断验证；分片与PMTU/ICMP错误处理；MTU/MSS边界；重拨、网络切换、peer离线和恢复；server initiated与retry jitter等协议覆盖。当前单client demo不具备这些产品级保证。

## P3：验收矩阵

冷启动至少多次、断网重连、跨多次换钥长期运行；验证Wi-Fi客户端外网出口和原生计数，主机不得运行代替设备的VPN。以固定包长/发包速率测试UDP上下行，记录实际吞吐、丢包、jitter、pps、RTT、heap/stack、失败次数和测试环境。每个结果标明样本时长与baseline。

正式完成需：实际独立启动、设备内WireGuard握手/换钥、Wi-Fi流量与策略验证、密钥/新鲜度正确、无累积泄漏、可恢复。离线pass和几分钟ping均不能替代。

DNS配置与旁路的进一步静态分析见 [DNS_ROUTING.md](DNS_ROUTING.md)：找到字段不等于已建立可用配置入口，完整Wi-Fi VPN验收仍未完成。
