# WireGuard放在哪里，以及Wi-Fi怎样保留

用户提出两项架构问题：Cortex-M3原本负责Wi-Fi，增加WireGuard是否破坏它；能否改放ARM926或DSP2。本说明基于已归档实机记录与静态分析，不代表新的硬件验证。

| 落点 | 已有证据 | 关键未解决项 |
|---|---|---|
| BCM43362 Cortex-M3 | 正常Wi-Fi RAM固件补丁；历史首次WG握手及换钥；双向包hook | 与原厂共享CPU/栈/堆和包缓冲；上次失联根因未知，不能保证稳定共存 |
| ARM926 | 下载入口RAM Hello World；正常AMSS为ARM ELF并有控制/通信代码线索 | 尚无正常联网状态下与原厂服务并行的通用代码入口；网络包收发/IPC、调度和可用内存未建立 |
| DSP2固件对应执行环境 | Hexagon v3/QDSP代码；网络、Web和Wi-Fi host driver静态证据 | 正常运行代码入口、任务ABI、包所有权/转发hook、内存边界和可用v3编译工具链尚未完整验证 |

从可移植C实现角度，不能断言ARM926或Hexagon不能运行WireGuard；但普通Linux程序没有现成运行环境。DSP2更贴近已定位的Wi-Fi到蜂窝通路，因此值得优先调查作为替代落点；这只是基于功能位置的工程判断，不是它性能更强或更容易部署的实测结论。DSP2是分区/镜像名称，也不能凭名称断言是一颗独立DSP物理核。详见[硬件事实](HARDWARE.md)与[平台证据](PLATFORM.md)。

## 当前Cortex-M3方案不是替换整个Wi-Fi固件

保留原厂镜像和ROM服务，添加freestanding补丁并改少量入口。共享的[entry.S](../work/uv310-wireguard/control-hardening/entry.S)中，packet0/packet1在intercept不消费包时回到original_sdpcm/original_wl；消费时使用原释放入口。timer和idle钩子调用新增逻辑后返回original_timer_body/original_idle_body。它不是独立Linux进程，没有进程隔离，也没有第二颗M3替原厂干活。

无线关联、MAC/PHY等继续依赖stock；WG计算和拦截会增加CPU时间、栈深和内存压力。保留原入口不证明ABI、中断、延迟、所有权和调度都安全，更不能用合成QEMU成功证明Wi-Fi没受影响。此前失联仍是明确的未解决问题。

## 下一步如何选择

保持已经可复现的M3路线作为对照，避免丢掉已验证入口；替代路线先做DSP2网络收发调用链与正常代码入口调查。ARM926如果找到正常AMSS任务注入和可靠跨核网络接口，也可以重新评估。主机引导能提供seed、配置和控制过程，但不会自动解决任何一条路线的正常执行入口、网络接口或掉电恢复问题。

尚未授权或执行新的基带分区刷写，没有把下载Hello World解释成正常联网的WireGuard执行能力。硬件回来后需要验证原厂基线、短时共存和资源，再谈换执行核或长时间运行。

2026-10-28补充：DSP2的Wi-Fi加载、收发和控制调用链已整理为[DSP2_API.md](DSP2_API.md)；蜂窝代码线索及DSP1片段覆盖范围见[DSP_ROLES.md](DSP_ROLES.md)。DSP2目前是备选，未建立可调用SDK或正常任务内自编代码入口。

2026-10-28 ARM补充：完整AMSS ELF声明范围已核对，正常worker回调与USB ECM包处理已定位。ARM仍缺正常运行的代码装载/触发机制，以及Wi-Fi↔ARM↔蜂窝双向路径和资源实测。不能用USB ECM路径代替Wi-Fi证明。见[ARM926研究总览](ARM926_RESEARCH.md)。
