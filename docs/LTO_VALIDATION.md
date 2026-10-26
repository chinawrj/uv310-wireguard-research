# LTO候选功能回归与最终链接栈审计

2026-10-26。延续 [最终布局审计](NATIVE_LAYOUT.md)，本轮不修改native功能源码，给`rekey-dns-grow`增加独立LTO测试模式。**硬件仍不可用，没有部署；256B池LTO仅刚好符合历史布局上限，不能宣称长期可用。**

## 功能结果与配置区别

| 模式 | 场景 | 错误对照 | 证据 |
|---|---:|---:|---|
| 普通编译、1024B公开fixture池 | 67 | 20 | [结果](../outputs/uv310-wireguard/evidence/lto-validation/rekey-dns-grow-tests.json) |
| LTO、1024B公开fixture池 | 67 | 20 | [结果](../outputs/uv310-wireguard/evidence/lto-validation/rekey-dns-grow-lto-tests.json) |
| LTO、256B公开fixture池 | 67 | 21 | [结果](../outputs/uv310-wireguard/evidence/lto-validation/rekey-dns-grow-lto-pool256-tests.json) |

三组是大量重叠的场景，不是201个独立功能。覆盖首次握手、自动换钥、旧会话与nonce、坏MAC/AEAD、分配失败/所有权、期限、DHCP修改/增长、LAN DNS拦截以及合成peer的DNS往返。

256B模式用`POOL_RETRY_EXHAUSTION`替换原`RETRY_LIMIT`场景：较小池不能假定足够完成18次重试。测试实际消耗池直到失败，确认不生成新的握手、旧认证会话在有效期内可用、正常拒绝期限到达后外部数据被关闭；后续worker/timer不循环复用池，也不提交新握手。新增故意“耗尽后把游标归零”的对照被检测。

**耗尽不等于立即销毁仍有效的旧会话。** 本轮没有修改这个既有策略；曾把测试预期写成terminal stop，发现与现有实现不符后，改为检验上述真实协议行为。

## 256B测试的模拟服务器隔离

旧1024B测试里客户端和模拟服务器共用随机provider，这不适合评价设备自身的256B池。初次缩小池时，模拟服务器响应因占用同一池而失败；并非实机证据。

256B模式通过仅测试使用的链接wrapper，让模拟服务器初始化和响应使用独立、确定性的测试数据生成器。额外断言这些操作没有改变客户端rng_pos。设备本身仍调用原checked provider和有限公开fixture池，生产源码不包含模拟服务器生成器。该生成器不是安全RNG，不能用于真实配置。

原fixture不被改写：隔离测试副本中仅取公开池前256B。报告同时记录原fixture源码哈希、派生规则和实际编译fixture哈希。保留1024B旧模式，便于对照历史结果。

## 构建隔离

native、WireGuard、密码模块和DHCP代码使用LTO；runtime.c、汇编和测试harness保留普通编译。runtime的AEABI helper必须留给LTO后端生成的调用使用。harness独立编译，保留故障注入和密码边界的nonce观察wrapper。

LTO使用单独的合成测试链接布局，将test state与候选state隔开；它不同于真实stock地址。报告是**同一功能源码的合成变体回归**，不是实际可部署ELF在ROM/IRQ/无线环境中的验收。BOUNDED_REKEY_LAB最终链接与SYNTHETIC_TEST功能测试仍有差别。

## 最终链接栈结果

新增 [linked_stack.py](../tools/linked_stack.py)，读取最终ELF的`.stack_sizes`，并反汇编可见的直接调用/尾调用。LTO后端需另加`--mllvm=-stack-size-section`；仅在前端设置该选项不能保证LTO函数产生元数据。worker/intercept/snapshot缺少frame记录会报错，不把缺失当作零。

以**256B池、真实native地址、BOUNDED_REKEY_LAB**比较：

| 根函数 | 普通编译可见链frame合计 | LTO可见链frame合计 | 差值 |
|---|---:|---:|---:|
| worker | 1,060B | 1,236B | +176B |
| intercept | 648B | 696B | +48B |
| snapshot | 192B | 184B | −8B |

证据：[普通链接](../outputs/uv310-wireguard/evidence/lto-validation/native-linked-stack-normal.json)、[LTO链接](../outputs/uv310-wireguard/evidence/lto-validation/native-linked-stack-lto.json)。LTO的worker自身frame为568B，包含内联后的工作，不能拿它直接对比普通编译worker单函数而忽略callee。

[无栈元数据的LTO链接](../outputs/uv310-wireguard/evidence/lto-validation/native-lto-without-stack-metadata.json)与有元数据版本的四个分支全部allocated section地址、尺寸、SHA一致，元数据采集没有改变这次实际代码/数据区。

这些合计**不是完整上界或下界**：间接调用、缺失符号、ROM/汇编callee、stock调用者、IRQ嵌套和未识别控制流未被完整建模；尾调用保守相加。不能据此推算设备剩余stack，也不能把历史sentinel余量搬到新镜像上。

## 复现与后续

```sh
LLVM_CLANG=/path/to/clang LLVM_LD=/path/to/ld.lld \
QEMU_ARM=/path/to/qemu-system-arm make test-dns-grow-lto test-dns-grow-lto-compact
LLVM_CLANG=/path/to/clang LLVM_LD=/path/to/ld.lld make audit-linked-stack
```

下一步仍需减少代码/状态以留下部署余量，或取得真实运行峰值证据；新增DNS观测也会占资源，必须计入。最终需新的单次实验材料、实机Wi-Fi/DHCP/DNS验证、随机数与跨启动新鲜度、独立启动、多客户端及长时间稳定性。LTO通过合成回归不解决这些要求。
