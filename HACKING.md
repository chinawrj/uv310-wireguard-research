# 逆向与原生执行思路：从 Hello World 到 Wi-Fi WireGuard

目标是用户这台 UV310 的正常 Wi-Fi 客户端经过设备内部 WireGuard；研究对象和所有地址只适用于已核对的板号、固件哈希。本文说明实际走过的路线、选择理由与证据边界，不把计划写成已实现功能。当前状态先看 [FRESH_START.md](FRESH_START.md)。

## 1. 先区分执行域，避免选错目标

初始问题不是“怎样装一个 Linux 软件包”，而是“这台设备哪些 CPU 在什么环境中执行哪些代码”。USB项目/DIAG、ELF机器类型、固件字符串、RAM探针逐步定位出 ARM926/AMSS、QDSP6固件和BCM43362 Wi-Fi处理器。

ARM下载模式的68B Hello World证明了可控RAM代码执行，却不提供正常Wi-Fi网络栈。直接拿ARM Linux WireGuard二进制塞进去无法完成目标。QDSP2含网络/驱动代码，但Hexagon v3工具支持、任务调用约定、内存与IPC接口较难验证。BCM路径则有可读的独立RAM image、Thumb-2执行环境、ROM服务，以及Wi-Fi帧通路，因此成为已推进到实机WireGuard的主路线。

这不是证明QDSP或ARM永远不能实现目标；只是当前BCM路径有较完整的可验证执行和数据路径。硬件见 [HARDWARE.md](docs/HARDWARE.md)。

## 2. 找可恢复的控制入口，再尝试执行

正常USB提供AT和DIAG/EFS，下载状态提供另一套endpoint协议；同一PID会出现不同拓扑，所以每次先核对全部接口、项目标识和镜像hash。

EFS能够读写指定文件，活动Wi-Fi固件是`/SyFi/brew/mod/rtecdc_new.bin`。这带来一个重要实验机制：保存并校验原厂副本 → stage并校验候选 → 有界重启加载候选 → **在开始流量实验前就恢复存储中的原厂文件**。BCM RAM里的候选本轮仍运行，但后续启动文件已经回滚。最后仍要重启并验证原厂运行态，不能把文件回滚当成运行恢复。

研究用的是所有者设备已有的下载/EFS接口和本地固件分析；没有依靠攻击第三方服务器，也没有把原厂固件、ROM或用户配置推入公开仓库。没有进行raw NAND program/erase。详细事务和失效边界见 [RECOVERY.md](docs/RECOVERY.md)。

## 3. 第一个关键突破：找到正常启动后的常驻代码入口

早期boot/late probe没有在正常Wi-Fi环境得到预期结果。继续分析发现：RAM image有完整性CRC检查，启动段随后会reclaim给heap；看起来“空闲”的启动代码区域并不一定长期可用。

后续采用post-CRC hook，把代码和状态放到明确的追加区，按对齐提升heap起点，保护原有完整性检查，并对原镜像内每个改动字做allowlist核验。通过版本查询返回marker与状态，再验证普通Wi-Fi流量仍能工作，才把它认定为正常运行native入口。

关键定位：hook `0x9df8`、版本指针 `0x9e18`、补丁区 `0x2f340`、heap字 `0x1e840`、CRC `0x2f28e`。这些是本镜像地址，不能用于外观相同但hash不同的设备。CRC修正是本地镜像完整性处理，不能据此宣称绕过了某个已验证的安全启动签名系统。

## 4. 第二个关键突破：把代码执行连接到真实网络路径

仅运行C或返回marker还不够。通过受限ROM读取和静态反汇编定位trampoline/RAM dispatch slot，逐步分析packet布局、allocator、timer和idle入口。最先做计数/观察型双向hook，确认方向、buffer边界和原始转发行为，再做数据修改。

必须分开BCM packet与QDSP host packet：相同字段含义可能位于不同offset。必须确认谁拥有packet、何时交给原函数、何时消费并释放，否则一次正确ping仍可能掩盖泄漏或double-free。主动发送控制包也要等真实free hook确认归还，不能以submit返回当作生命周期结束。

最终把普通Wi-Fi IPv4帧转换成WireGuard内层包，在BCM上加密形成outer UDP，经原厂SDPCM/modem蜂窝路径发出；回程解密、检查重放并恢复客户端地址后回Wi-Fi。Mac仅做配置和观察，不能在Mac上代替设备加密。见 [BCM_RUNTIME.md](docs/BCM_RUNTIME.md)、[WIREGUARD.md](docs/WIREGUARD.md)。

## 5. 第三个关键突破：从触发实验变为设备主动工作

早期原生握手/forwarding仍借助host initializer。之后引入timer发送控制包，idle线程执行昂贵crypto，收包hook负责输入与状态通知。timer/idle/free hook的寄存器、APSR和PRIMASK保存非常关键，早期候选失败与后续修正均保留。

这让首次普通客户端流量触发握手，设备主动发送initiation/keepalive，并在运行中进行换钥；不需要特殊host trigger包持续“推着走”。但“本轮协议自主执行”不等于“设备可安全独立反复启动”：随机池与TAI基值仍由主机每次新生成。

## 6. 每次突破都要求对应层级的证据

| 声称 | 最少需要的证据 | 不能拿什么替代 |
|---|---|---|
| applet可执行 | 实机返回确切Hello World应答 | 编译成功 |
| 正常Wi-Fi native代码可运行 | native状态+原厂Wi-Fi仍工作 | 下载模式执行 |
| WireGuard核心正确 | 合成向量、认证失败、重放、边界与负向控制 | 只跑成功路径 |
| 真peer互通 | 设备native握手与authenticated回程 | 主机VPN握手 |
| Wi-Fi用户流量被转发 | 绑定客户端流量、native计数、真实回程 | 仅状态phase成功 |
| 自动换钥 | 多个不同session index、双向流量跨越换钥 | 时间过去了或单个key仍可用 |
| 独立可靠启动 | 新鲜度/熵源、重复启动、恢复和长时运行 | 一次fresh pool实验通过 |

`rekey-live`已经完成首握手+两次自动换钥，短时ICMP/UDP DNS/HTTPS通过；最新`rekey-memory`虽然得到堆/栈观测，但在第一次换钥附近断连，不能把它标成更稳定版本。完整结果和失败见 [EXPERIMENTS.md](docs/EXPERIMENTS.md)、[MEMORY_RUN.md](docs/MEMORY_RUN.md)。

## 7. 没有走通或不应继续盲试的路线

- 以ARM926/文件树/POSIX字符串推断Linux shell：证据不足，不能按普通OpenWrt系统部署。
- 在启动reclaim区放常驻状态：生命周期不对；必须把heap/stack/packet总成本一起核算。
- 假定`AT+WL`能调用host DHD任意memory IOVAR：已确认路径主要到Wi-Fi firmware IOCTL，不能把host magic选择器忽略。
- 把`wl memuse ERROR`认作OOM：原厂也ERROR，应实测free-list/最大块/stack。
- 把ROM RNG helper返回变化或jitter健康测试通过认作安全随机源：没有建立所需熵与reseed证明。
- 把`asp_get(key,"0")`当通用setter：实际清空已有RAM值；配置commit也未验证掉电原子性。
- 把一次性随机池/时间基值的image留作自启：会产生重用和跨重启freshness问题；旧image不能重放。
- 把Wi-Fi AES硬件卸载等同WireGuard加速：算法与调用入口不同，尚无可用offload证据。

## 8. 下一步研究假设与如何证伪

**最近失联的诊断**：先区分USB消失、拓扑变化、AT返回错误、主机换网和固件重启。旧harness留下空AssertionError，不足以判定根因。新的观察器应保留独立时间戳和具体分类，失败时停止流量而不擅自重启或重部署。

**换钥瞬时资源压力**：最后样本的free/最大块是4636/4444B，payload历史峰值103800B；不能直接断定OOM。可以分析crypto调用栈、控制包分配和关键中断嵌套，在合成环境注入失败，再做单变量实机对照；出现相同断连时间不等于证明同一原因。

**独立启动**：继续验证device RNG或native modem桥，以及跨重启时间/持久化设计；静态地址不是USB命令，不直接把内部消息号发送到外部接口。随后才是多客户端、DNS/IPv6、MTU、重拨和受控UDP性能验收。

本文是路线图。正在运行什么、还欠哪些验证，以 [CURRENT_STATE.json](CURRENT_STATE.json) 为准；源码的历史部署脚本不是可以直接执行的通用安装器。

## 2026-10-28：DSP2备选路线的接口审计

沿原厂IPnet/DHD对象边界逆向，而不是先替换固件。已识别同步复制、两套包释放器、256槽RX环及TX队列淘汰；上层发送包装丢弃底层错误，不能把返回0当实际送达。另接齐DSP2读取EFS中的Wi-Fi镜像并写入BCM RAM的主链，这条链不是DSP2程序加载器。下一步门槛是正常任务入口、资源/上下文及蜂窝UDP出口。M3保留为主线。详细证据与API草案见[接口文档](docs/DSP2_API.md)。

## 2026-10-28：ARM926正常共存路线

三路并行核查AMSS完整性、启动/worker、ECM/IPC。完整ELF不等于完整启动链；AMSS分区尾部读取失败须保留，不能说是已确认空白。优先沿原厂已有callback队列寻找最小共存验证，先解决正常代码装载与触发，再分析专用任务和数据桥。USB ECM收发代码只能证明ARM有USB数据适配职责，不能推导Wi-Fi经过ARM。下一步实验门槛与证据入口见[ARM926_RESEARCH.md](docs/ARM926_RESEARCH.md)。
