# 公开仓库的持续集成

新增 [.github/workflows/offline.yml](../.github/workflows/offline.yml)，在main推送、pull request或手动触发时，从干净的GitHub托管Ubuntu 24.04环境构建。固定官方checkout/upload-artifact提交，权限为contents:read，不持久化checkout凭据。

安装LLVM18、QEMU ARM和固定版本Python依赖后，重放rekey-live、rekey-memory、rekey-pressure三组QEMU测试、mock状态观察器，并编译栈/目标文件大小对照。环境报告仅保存明确列出的工具版本和公开CI运行标识，不转储环境变量。只上传`.test-results/*.json`，保留14天，不上传ELF、镜像、私有配置或整个工作目录。

工作流配置已经准备，首次Linux执行结果尚待验证。不能把“添加了CI”当作“CI通过”，也不能把CI通过当作设备原生Wi-Fi验收。

构建依赖下载和证据上传需要联网；测试本身不连接USB、无线网络、WireGuard对端或管理页面。它仍使用公开合成密钥、模拟allocator和QEMU Cortex-M3，缺少真实ROM/SDIO/射频/IRQ与设备熵源。

定义参考：[GitHub workflow语法](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)、[官方artifact参数](https://github.com/actions/upload-artifact)。
