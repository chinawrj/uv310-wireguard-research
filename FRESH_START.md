# Fresh start：先读这份，再操作设备

本文件是 2026-10-26 发布时的交接快照，优先于各历史 JSON 中的 `current_*` 字段。老证据中的“已恢复/正在运行”只描述该次实验结束时。

研究路线与关键突破先看 [HACKING.md](HACKING.md)。

## 1. 用户真正要什么

让这只 **UV310 的 Wi-Fi 客户端**通过设备原生 WireGuard 出口上网；USB ECM/RNDIS 是次要路径。不能用 Mac 上的 VPN、QEMU 协议通过、下载模式 Hello World 替代设备内 Wi-Fi 转发。EC20 和华为 E8372h-155 是此前另外两台设备；本仓库只承接 UV310。

## 2. 最近状态（不要猜）

- 用户已明确拿走硬件；Goal已恢复active，当前只推进离线任务，不再要求重插或轮询USB。最新离线工作见 [OFFLINE_PROGRESS.md](docs/OFFLINE_PROGRESS.md)。

- 原厂Wi-Fi发送前段已离线重放32组合，确认选定路径直接读取packet长度/数据指针；不含DMA/无线发送，也未实机验证。见 [STOCK_PACKET_LENGTH.md](docs/STOCK_PACKET_LENGTH.md)。

- 最新候选 `rekey-dns-grow` 已离线接入1–6字节有界DHCP扩展，67场景/20错误对照已在本机和Linux CI通过，独立模块Linux ASan+UBSan通过；尚未部署。见 [DHCP_GROWTH.md](docs/DHCP_GROWTH.md)。

- 上一DNS候选 `rekey-dns` 已离线接入DHCP改写与LAN端口53检查；62场景/18错误对照已在本机和Linux CI通过，未部署。限制与资源增量见 [NATIVE_DNS.md](docs/NATIVE_DNS.md)。

- 独立DHCP DNS改写原型：1,352个主机向量、60个Cortex-M3向量与5个错误对照通过；Linux ASan+UBSan已复现；独立模块历史验收见 [DHCP_DNS_TRANSFORMER.md](docs/DHCP_DNS_TRANSFORMER.md)。

- DNS离线分析：原 `rekey-pressure` 路径的网关DNS仍旁路（最新候选的离线处理见上）；已接上DHCP内部消息到配置写入、服务到配置解析的静态链；仍未建立可用DNS设置/重载入口。见 [DNS_ROUTING.md](docs/DNS_ROUTING.md)。

- 上一离线候选：`rekey-pressure`，控制包分配有限退避重试；45项QEMU场景和12项负向控制通过，未部署、未实机验证。见 [ALLOCATION_RETRY.md](docs/ALLOCATION_RETRY.md) 与 [NONCE_LIFECYCLE.md](docs/NONCE_LIFECYCLE.md)。
- 公开仓库已在干净Linux CI复现：97项QEMU场景、21项负向控制、23项mock观察器测试通过。它不代表新实机成功，见 [CI.md](docs/CI.md)。
- 已成功的分支：`work/uv310-wireguard/rekey-live`，实机首次握手 + 2 次自动换钥。
- 最近实机分支：`rekey-memory`，增加 A/E/R/M 四页状态和有界内存观测。当时25项离线场景、3项负向控制通过；本轮保持native源码不变，测试扩展至32项场景、6项负向控制，见 [ALLOCATOR_FAILURES.md](docs/ALLOCATOR_FAILURES.md)。
- 最近实机运行在约 138.794 s 首次出现整批 ping/DNS 失败，141.797 s 状态查询断言失败，147.812 s 测试结束失败；最后成功快照尚未完成第一次换钥。后续 USB 枚举只见 ASIX 网卡，未见 UV310。不能断言是 OOM、看门狗或用户拔出。
- **断连之前**已把设备 EFS 内的活动 Wi-Fi 镜像恢复为原厂并完整读回校验，SHA-256 `4b86d71b92529034b2b46da7b93402f67c8aef98d2fc1efa91fc67ff7e5fb85a`，193,315 B。
- 此后无法验证原厂运行态，因为设备不在总线上。存储文件已恢复 ≠ 当前 RAM 运行态已验证恢复。
- 电脑 UI 已确认回到原 Wi-Fi，DHCP 回到原网段；未遗留本轮静态 IP/路由修改。没有活跃测试进程。
- 长期独立启动 Goal 未完成。最新报告：`docs/MEMORY_RUN.md`、`CURRENT_STATE.json`。

## 3. 新会话前十分钟

1. 阅读本文件、`docs/HARDWARE.md`、`docs/PLATFORM.md`、`docs/RECOVERY.md`；检查 Git 当前提交和 `MANIFEST.sha256`。
2. `make test` 先离线重放。不运行 `package.py`、`reboot.py`、`efs_*.py`。
3. **以下设备步骤仅在用户确认硬件可用后执行；无硬件时跳过。** 只读列举 USB，核对 VID/PID **和完整接口/endpoint 拓扑**。`05c6:6000` 在正常模式和 DMSS 模式都可能出现。
4. 正常拓扑下查询 `AT^PROJECTNAME?`，应包含 MDM9600 / UV310。随后有界查询 CPIN、WIFI、wl ver/isup。不要打印/上传 IMEI、IMSI、ICCID 或完整配置。
5. 读回 `/SyFi/brew/mod/rtecdc_new.bin` 并验证尺寸和完整哈希。没有匹配的私有 stock 备份时不进行候选镜像部署。
6. 先验证原厂 Wi-Fi 关联、DHCP、网关 ARP、管理页、SIM/蜂窝网络，再考虑新的实验。SIM busy 可能是启动过程，必须记录后续实际状态。
7. 需要物理重插才能恢复时如实记录；不能把软件 RESET 写成物理断电。
8. 根据 `ROADMAP.md` 选择下一项最小实验，先离线测试并预备恢复路径。不要直接把最新 memory 分支称为更稳定的固件。

## 4. 禁止复制的历史假设

- ARM926 是 Linux 用户 CPU → 未成立；下载 applet 与正常固件不是同一入口。
- `wl memuse` ERROR 是 OOM → 原厂也 ERROR，不能这样推断。
- RNG 寄存器有变化 / 健康检查通过就能安全生成密钥 → 未成立。
- 芯片总 RAM / arena 减当前 payload 就是可分配内存 → 未计元数据/碎片，须实测最大块。
- 旧实验 pool/TAI 可以复用或随设备重启 → 不可；会重放随机材料/握手新鲜度。
- `asp_get(key,"0")` 能写任意配置 → 实际会清空已有 RAM 值，不是通用 setter。
- 88 个 ping 的 RTT 是 UDP 吞吐性能 → 只是短时功能样本；没有可引用的本机吞吐基准。

## 5. 私有依赖交接

公开仓库足以跑合成测试、理解补丁和定位后续工作，不能独立生成真实可部署镜像。需要设备所有者本地提供匹配哈希的 stock RAM 镜像；必要时合法读出自己的 ROM/调制解调器固件用于分析；从自己的 WireGuard 管理端新建专用 peer。真实配置和派生头文件只能存入忽略的 `private/` 路径。

不要从对话、历史文件或 Git 历史恢复旧密钥继续部署。任何新 peer 的私钥、PSK、随机池和带这些材料的 image/ELF 都不得进 Git。测试 `native-config.h` 是明确的合成材料，目的仅是可重复离线验证。

## 6. 下一轮优先顺序

先确认设备回到原厂可用；使用新增observer采集具体错误、clock不连续和host变化，诊断工具尚未做新的实机验收；然后调查第一次换钥附近的瞬时内存需求。随机数/跨重启新鲜度、独立重启、策略覆盖与稳定性仍是正式完成条件。
