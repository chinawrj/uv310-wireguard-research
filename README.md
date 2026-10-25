# UV310 native WireGuard reverse engineering

ALEKA UV310-U-5.1 CGWL / MDM9600 / BCM43362 的逆向研究、原生代码与实验交接。目标是让连接随身 Wi-Fi 的客户端通过**设备内部**的 WireGuard 上网。

**先读 [FRESH_START.md](FRESH_START.md)**。截至 2026-10-26：已经验证 BCM43362 上的原生 WireGuard 握手、普通 Wi-Fi IPv4 转发、两次自动换钥及实验到期停止转发；尚未做成能够安全反复独立启动的产品固件。最新内存观测分支中途断连，原因未定。

这台 UV310 的正常运行环境不能当作可 SSH/ADB 进入的 Linux 用户空间。ARM926 的下载模式 Hello World、BCM43362 Cortex-M3 的正常 Wi-Fi 固件执行，以及 QEMU 协议测试，是三个不同的执行环境。

| 证据层级 | 已验证内容 | 边界 |
|---|---|---|
| 实机下载模式 | 68 字节 ARM applet 返回 Hello World | 不能据此推断正常系统可运行 Linux 程序 |
| 实机正常 Wi-Fi 固件 | 原生 C、双向数据包 hook、WireGuard 加解密与转发 | 单 IPv4 客户端，内存很紧 |
| `rekey-live` 实机 | 首次握手 + 2 次换钥，88/88 ping、22/22 UDP DNS、换钥后 HTTPS 200 | 一次性主机生成随机池和 TAI 基值；不是独立启动方案 |
| `rekey-memory` 实机 | 直接测得运行中空闲 payload 4,636 B、最大块 4,444 B | 147.812 s 测试失败；本分支未验证换钥完成 |
| QEMU Cortex-M3 | 32 个测试场景与 6 个负向变异检查通过 | 不模拟 BCM 外设、射频、SDIO、真实熵源 |

## 导航

- [控制包分配失败与包所有权验证](docs/ALLOCATOR_FAILURES.md)
- [无硬件阶段：诊断工具和栈资源对照](docs/OFFLINE_PROGRESS.md)

- **[逆向 / Hack 思路与路线选择](HACKING.md)**

- [当前状态与新会话入口](FRESH_START.md)
- **[硬件架构、芯片、总线与存储](docs/HARDWARE.md)**
- [平台、处理器与固件](docs/PLATFORM.md)
- [USB / AT / DIAG / EFS / 下载协议](docs/PROTOCOLS.md)
- [BCM 地址、镜像格式、内存与 ABI](docs/BCM_RUNTIME.md)
- [WireGuard 数据路径与状态机](docs/WIREGUARD.md)
- [随机数、时间与持久化问题](docs/ENTROPY_TIME.md)
- [离线构建与验证](docs/BUILD.md)
- [部署约束与恢复流程](docs/RECOVERY.md)
- [实验时间线和反例](docs/EXPERIMENTS.md)
- [最新内存实验完整解读](docs/MEMORY_RUN.md)
- [源码和证据索引](docs/INDEX.md)
- [下一步开发与验收](docs/ROADMAP.md)
- [公开数据处理与来源](docs/PUBLICATION.md)、[第三方许可证](THIRD_PARTY_NOTICES.md)

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-test.txt
# clang / ld.lld / qemu-system-arm 须已安装，具体路径见 BUILD.md
make test
```

`make test` 不访问 USB、不连接网络、不生成可部署固件；构建在临时目录执行。保存的历史部署脚本不是安装器：它们依赖未公开的原厂镜像和一次性配置，不能直接照旧重放。

本仓库不包含用户密钥、真实 WireGuard 配置、原厂 ROM/固件镜像、SIM 身份数据或短信。原生代码、测试夹具、分析脚本和脱敏证据已保留。历史路径保持原样，方便对照原研究记录。

English: research handoff for device-native WireGuard on the BCM43362 inside an ALEKA UV310. Real Wi-Fi forwarding and two autonomous rekeys were observed in a bounded, freshly provisioned laboratory session. Restart-safe entropy/freshness and production stability remain unresolved. This is not an installable firmware release.
