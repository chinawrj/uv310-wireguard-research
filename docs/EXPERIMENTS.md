# 实验进展与保留的反例

顺序按研究阶段，不把历史文件mtime当成严格实验时间；精确数值见各JSON。所有结论只对目标样机/固件适用。

| 阶段 | 结果与后续意义 |
|---|---|
| ARM下载模式Hello World | RAM reply applet成功，证明下载执行，不证明Linux正常用户态 |
| Cortex-M3协议移植 | 合成crypto/握手/重放检查通过；继续寻找normal runtime入口 |
| boot/late probe | 早期入口失败，原厂CRC/启动回收区是关键；恢复并保留失败 |
| postcrc/resident | 正常Wi-Fi运行中native marker与常驻状态验证 |
| ROM/path/buffer | ROM trampoline、packet方向与bounds、分配/free ownership逐步确认 |
| native-wg | 真实peer握手与authenticated ICMP，不再仅为QEMU |
| forward-wg | 普通client ICMP、UDP DNS、TCP HTTPS经过native路径，初期仍靠host initializer |
| timer/deferred | 某些timer候选失败；APSR保存、idle线程crypto与IRQ职责分离后推进 |
| auto-wg | 普通client流量触发自主首次握手，initializer退出后仍forward；材料仍per-build |
| active-send/release/emitter | 主动UDP控制包、keepalive、真实free闭环验证 |
| freshness/jent/bridge | DWT可用；多种jitter窗口/内存布局有进展，secure entropy和跨重启freshness仍未成立 |
| rng-provider/failclosed | checked RNG、有限index选择与失败传播，离线负向测试 |
| rekey-lifecycle/layout | 当前/前一个key与重试/并发/到期测试，实际地址布局可链接 |
| rekey-live | 真实首次握手+两次换钥；有早期AT错误及allocation failures，不能抹掉 |
| rekey-memory | 实测heap/stack；首次换钥附近断连，原因未知，不是新成功baseline |

## 已成功的rekey-live细节

191.906 s followup跨两次renewal，共3个不同current key indices、3 initiations/3 responses；88/88 ping、22/22 UDP DNS。RTT min/mean/max=52.345/91.625/232.593ms，**功能样本，不是性能benchmark**。两次换钥后HTTPS 200、22066B、1.730218s，nativeTX+25/RX+37；host DNS可能用stock LAN resolver，因此不证明DNS无旁路。

control提交/回收17/17，到deadline时21/21，pending/error=0；fresh512B pool消耗140B。到期failclosed实测通过。结束时完整stock恢复、Wi-Fi/SIM与host恢复已在该轮验证。

反例保留：第一次candidate启动后的EFS restore超时，后续在流量前成功；bootstrap6ping中先丢3再回3；两个早期collector因AT ERROR退出；followup出现一次查询失败；全局alloc failures0→7→13后稳定。缺少那轮heap峰值，不能从结果无丢包反推内存充足。

## 本机UDP性能状态

真实UDP DNS通路已验证，但截至本快照没有经过受控包长/码率/方向、offered load与实际吞吐、loss/jitter、时间长度、CPU/heap观测的UV310 native WG吞吐测试。旧EC20测得的Mbps不是本机数据，不能移植进来。先解决断连并建立稳定baseline，再测单向/双向64/256/1200B UDP与小包pps。
