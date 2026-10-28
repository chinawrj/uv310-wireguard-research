# DSP1、DSP2和modem的职责边界

2026-10-28。本机的`DSP1`、`DSP2`是镜像/分区名称。MDM9600是modem平台，不能把整套modem简单等同于DSP1，也不能由镜像名字推断出一颗空闲CPU。

| 对象 | 本机证据 | 现在能说到哪里 |
|---|---|---|
| AMSS / ARM926路径 | ARM ELF；此前有L4/REX/USB/ONCRPC线索；本轮核对`clkrgm_mpss_q6ss.c`相关QDSP6类型日志 | 参与系统/通信/时钟控制；全部职责与跨核调用仍未映射 |
| DSP2镜像 | 已沿指令定位DHD、SDIO加载器、IPnet收发；rodata另有LTE RRC、MAC、PDCP、ML1及GERAN源文件标记 | 包含网络服务及蜂窝相关软件；不能把它当专门给Web/Wi-Fi使用的独立应用环境 |
| DSP1镜像 | `EM_QDSP6`，入口`0x03c00000`；手头仅65536B；ELF段表声明文件内容延伸至2432784B（约2.32MiB） | 大部分代码/只读数据尚未取得；无法确定具体无线制式、L1/L2分配、任务预算与是否可借用 |
| BCM43362 | 独立Wi-Fi芯片，Cortex-M3运行RAM固件及ROM；历史原生补丁运行过 | Wi-Fi芯片内执行环境，与DSP2主机驱动分开；当前WG主线仍在此 |

本轮证据为[dsp-image-roles.json](../outputs/uv310-wireguard/evidence/dsp-image-roles.json)，[image_roles.py](../work/uv310-wireguard/dsp2-api/image_roles.py)可对所有者的本地切片复核哈希、段表与8个指定字符串。没有发布镜像。rodata标记**不是**每项PHY运算实际在哪个核执行的证据：共享日志、控制消息及跨核驱动都可能带入相关名字。没有用DSP1的64KiB片段未出现某字符串来证明它“不做某功能”。

## 对WireGuard设计的影响

若放DSP2，需要Wi-Fi客户端包的入口/回程接口，另需通过原厂网络栈发送和接收WireGuard外层UDP。优先调查UDP/socket与蜂窝出口、路由绑定；不需要因此重写LTE物理层或直接接管DSP1。Wi-Fi API已经有静态地图，蜂窝UDP API仍未建立，参见[DSP2_API.md](DSP2_API.md)。

DSP1理论上也可运行可移植代码，或作为加解密协处理器。但对本机，这两个方案都缺正常加载入口、任务/内存余量和双向IPC证据。协处理器方案还要付出队列、共享缓冲、cache同步和调度开销，不能据“有DSP”断言有现成WireGuard硬件加速或性能必然更高。

## 当前选择

M3保留为主线，因为已有正常执行入口和历史握手证据；它仍有内存紧张、最新实机运行失联原因未明等问题。DSP2保留为备选，当前只推进有界接口/加载可行性分析，未证明它比M3更有资源或更容易稳定。DSP1暂为待调查对象，不改原厂职责。

硬件重新可用且用户授权继续时，先取得完整DSP1镜像/运行态信息，再对照任务注册、跨核消息和服务调用；当前不轮询USB，不要求重插，不把未知分工当成部署依据。
