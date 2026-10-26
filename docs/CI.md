# 公开仓库的持续集成

新增 [.github/workflows/offline.yml](../.github/workflows/offline.yml)，在main推送、pull request或手动触发时，从干净的GitHub托管Ubuntu 24.04环境构建。固定官方checkout/upload-artifact提交，权限为contents:read，不持久化checkout凭据。

安装LLVM18、QEMU ARM和固定版本Python依赖后，重放rekey-live、rekey-memory、rekey-pressure与rekey-dns四组QEMU测试、独立DHCP模块的主机sanitizer/Cortex-M3测试、mock状态观察器，并编译栈/目标文件大小对照。环境报告仅保存明确列出的工具版本和公开CI运行标识，不转储环境变量。只上传`.test-results/*.json`，保留14天，不上传ELF、镜像、私有配置或整个工作目录。

首次Linux执行已通过：[运行40244587977](https://github.com/chinawrj/uv310-wireguard-research/actions/runs/40244587977)，被验证提交为`1a4735e55998a24067141136e9140e9d58e14520`。三组QEMU共97项场景、21项负向控制，另有23项mock观察器测试全部通过。不能把CI通过当作设备原生Wi-Fi验收。

构建依赖下载和证据上传需要联网；测试本身不连接USB、无线网络、WireGuard对端或管理页面。它仍使用公开合成密钥、模拟allocator和QEMU Cortex-M3，缺少真实ROM/SDIO/射频/IRQ与设备熵源。

定义参考：[GitHub workflow语法](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)、[官方artifact参数](https://github.com/actions/upload-artifact)。

## 已归档证据

- [运行摘要、artifact哈希与日志摘录](../outputs/uv310-wireguard/evidence/ci-linux-run.json)
- [Linux工具版本](../outputs/uv310-wireguard/evidence/ci-linux/ci-environment.json)
- [rekey-live结果](../outputs/uv310-wireguard/evidence/ci-linux/rekey-live-tests.json)：20项/3项
- [rekey-memory结果](../outputs/uv310-wireguard/evidence/ci-linux/rekey-memory-tests.json)：32项/6项
- [rekey-pressure结果](../outputs/uv310-wireguard/evidence/ci-linux/rekey-pressure-tests.json)：45项/12项
- [目标文件大小](../outputs/uv310-wireguard/evidence/ci-linux/native-size-pressure.json)
- [memory栈分析](../outputs/uv310-wireguard/evidence/ci-linux/stack-audit-rekey-memory.json)、[pressure栈分析](../outputs/uv310-wireguard/evidence/ci-linux/stack-audit-rekey-pressure.json)

实际环境为Linux x86_64、Ubuntu clang/LLD 18.1.3、QEMU8.2.2、Python3.12.3；此前本机是macOS arm64、Homebrew LLVM18.1.6、QEMU10.0.0。下载ZIP的SHA-256与GitHub artifact digest一致，三组测试记录内的源码哈希全部与公开文件一致。

这是功能测试跨环境复现，不是二进制逐字节可复现声明。工具版本不同可能改变机器码和资源统计。安装用的Ubuntu软件包没有固定到完整不可变快照，首次证据已记录实际版本；未来变动会由后续运行重新验证。

## DHCP DNS独立模块

新增 `make test-dhcp-dns`：Linux ASan+UBSan 1,352个报文向量、60个Cortex-M3向量和5个故意错误对照已通过，证据见 [DHCP_DNS_TRANSFORMER.md](DHCP_DNS_TRANSFORMER.md)。这些是新增独立模块测试，不改变上述历史核心WireGuard测试数量，也不表示已接入native hook或修复实机DNS旁路。

## native DHCP/DNS集成候选

`make test-dns` 已在 [运行40251534521](https://github.com/chinawrj/uv310-wireguard-research/actions/runs/40251534521) 通过62场景/18错误对照。该分支开始在native hook内调用DHCP模块，属于合成packet集成；仍未部署。运行、源码/ZIP哈希、Linux资源报告已长期归档，见 [NATIVE_DNS.md](NATIVE_DNS.md#linux独立复现)。不要将四个分支重复覆盖的场景相加为独立功能数。

新增 `make test-dhcp-growth` 与 `make test-dns-grow`，分别检验有界扩展模块和native集成；对应证据与限制见 [DHCP_GROWTH.md](DHCP_GROWTH.md)。
