# 主机种子驱动的随机流原型

2026-10-28。目标是减少固定随机池耗尽造成的主机干预，不延长WireGuard标准会话过期时间。本轮只实现独立模块，未修改native候选或prepare生成的头文件。

[原型源码](../work/uv310-wireguard/seeded-rng/seeded_rng.c)复用仓库已有ChaCha20函数，不改算法核心。初始输入是独占用途的32B主机新种子，nonce为0；每个非空请求消费一个完整64B块，只返回所需1–64B，舍弃剩余字节。零长度不消费块。总预算65536块，达到预算后清零输出及内部cipher状态并关闭；初始化只能在零初始化对象上进行一次，close后不可重新初始化。调用方必须串行化访问，尚未实现中断重入保护。

[libsodium文档](https://doc.libsodium.org/generating_random_data)也描述了基于ChaCha20的确定性随机输出，并明确主要用于测试、同seed输出相同。这里只用作原理参考，不宣称本包装器等同于libsodium实现、经其审核或是标准化/认证DRBG。其安全性首先依赖新种子保密、不可预测、独立用途、不复用和状态不回退。

## 当前证据

- [40项主机检查](../outputs/uv310-wireguard/evidence/seeded-rng/host-tests.json)：3种合成seed、不同请求长度与独立cryptography ChaCha20输出比对；零长度、重复初始化、非法长度/指针、预算最后一块、耗尽清零、未初始化/关闭拒绝。故意重置counter的错误对照可被独立oracle检出。
- oracle使用零nonce、低于2^32的counter，因此其原始ChaCha20布局与本IETF状态布局在这些向量上重合；不推广到跨越该边界的情况。
- [Cortex-M3包装层对象](../outputs/uv310-wireguard/evidence/seeded-rng/arm-wrapper.json)：text152B，结构体68B；自身静态frame为close0/init16/read24B。不含ChaCha20/memset调用、链接布局、LTO、IRQ，也未在ARM上执行。
- 主机初次构建遇到默认CommandLineTools SDK与链接器不兼容，切换Xcode clang及对应SDK后通过。未修改算法以绕过工具链错误。

复现需已有pyelftools（资源分析）与cryptography（独立oracle）；本轮oracle环境为cryptography46.0.7，未添加到默认CI依赖，也未声称Linux复现。

```sh
HOST_CC=/path/to/host-clang python3 tools/test_seeded_rng.py
```

macOS工具链不匹配时同时指定匹配的SDKROOT。工具只创建临时动态库并载入测试，不访问设备或网络。

## 不可省略的限制

这不是完整的具备回溯抵抗能力的DRBG。cipher状态保留种子密钥，泄露后可推导本次运行过去和未来的输出；即使WireGuard自身删除旧临时私钥，也不能据此宣称完整前向保密。种子若固化在镜像中，镜像泄露同样影响本次运行。尚未实现输出后更新密钥、重播种或状态泄露恢复，不能直接部署。

计数器在内存中，状态复制、快照恢复或复用seed会重放输出。负向测试能发现已知回退，不代表运行时包装器会识别任意状态回退。故意缩小预算用于明确失败边界，不意味着可安全无限运行。

下一步要比较具备状态更新/擦除方案的资源成本，再做Cortex-M3执行、真实native链接、并发/中断与WireGuard回归。主机prepare生成的新种子仍没有被候选消费；当前实际候选继续使用原有限池。

## Cortex-M3执行补充

独立QEMU mps2-an385现已通过31组oracle输出比较、生命周期/输出边界检查和4个故意错误变体（counter重置、去除预算、去除擦除、允许重复初始化）。[原始记录](../outputs/uv310-wireguard/evidence/seeded-rng/arm-tests.json)保存源码与ELF哈希。首次测试链接因测试地址0处ARM异常展开节与向量表重叠而失败；测试链接脚本丢弃不使用的异常展开节后通过，没有修改生产源码。

复现：设置LLVM_CLANG、LLVM_LD、QEMU_ARM后运行`python3 tools/test_seeded_rng_arm.py`；仍需cryptography生成独立向量。这个测试只有随机模块与合成启动代码，不加载原厂Wi-Fi固件、不模拟BCM外设，不能证明Wi-Fi共存或正式布局适配。
