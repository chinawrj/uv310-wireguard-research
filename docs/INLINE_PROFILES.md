# LTO内联策略与重复函数合并

2026-10-26。在 [LTO回归](LTO_VALIDATION.md) 基础上尝试取得部署余量、降低worker栈需求。本轮**不修改native或WireGuard协议功能源码、不缩短key、不删除边界检查、不提高历史heap上限**。选择的新实验构建profile为 `control-icf`；尚未部署。

## 选中的组合

- 对native.c及rng-provider/wireguard.c使用`-fno-inline-functions`，其他C单元保留原LTO优化。
- 保留`-flto -Oz`，runtime.c仍`-fno-lto`。
- 链接器启用`--icf=safe`，合并其判定可合并的相同代码。`safe`是链接器模式名称，不是硬件安全/稳定性保证。
- 测试harness和汇编仍单独构建；无新增生产状态、线程、随机池或网络接口。

在256B合成池形状、实际native地址最终链接中，相对默认LTO：probe代码常量区16,368→16,268B（−100B），state维持1,884B；向上256B对齐后的heap起点0x33c00→0x33b00，因此相对历史上限留下256B布局余量。**这256B不是实测可用heap或最大连续块。** 私有配置值与真实编译仍需重新审计。

可见调用链frame合计：worker1,236→1,052B（−184B）；intercept696→712B（+16B）。相对普通256B编译的worker1,060B约少8B，但intercept648B则多64B。不能把一个根函数的改善称为所有路径栈占用都改善。

## 八种布局实验

仅最终链接/栈审计，除选中组合外没有为各实验逐一做新增功能回归。合计均不是完整stack上界，仍缺ROM/IRQ/间接路径。

| 限制内联范围 | ICF | probe字节 | 对齐heap起点 | 历史上限余量 | worker链 | intercept链 |
|---|---|---:|---|---:|---:|---:|
| 默认 | none | 16368 | 0x33c00 | 0 | 1236 | 696 |
| 默认 | safe | 16280 | 0x33b00 | 256 | 1236 | 696 |
| 所有C函数 | safe | 16672 | 0x33d00 | −256 | 1052 | 688 |
| WireGuard协议单元 | safe | 16440 | 0x33c00 | 0 | 1052 | 688 |
| native控制单元 | safe | 16076 | 0x33b00 | 256 | 1244 | 712 |
| DHCP单元 | safe | 16484 | 0x33c00 | 0 | 1236 | 656 |
| 两个大握手函数 | safe | 16304 | 0x33c00 | 0 | 1356 | 696 |
| native + WireGuard协议单元 | safe | 16268 | 0x33b00 | 256 | 1052 | 712 |

[比较摘要](../outputs/uv310-wireguard/evidence/inline-profiles/inline-profile-comparison.json)及同目录8份原始报告记录源码哈希与编译策略。两大握手函数的实验通过 [可选声明头](../work/uv310-wireguard/handshake-noinline.h) 添加noinline属性，仅用于该实验；选中的control-icf不包含这个头。

选择control-icf是当前代码空间与worker可见栈链之间的折中，并非已证明吞吐或延迟最佳。没有实机性能数据。

## 功能验证

- [256B池](../outputs/uv310-wireguard/evidence/inline-profiles/rekey-dns-grow-lto-pool256-control-icf-tests.json)：67场景/21错误对照。
- [1024B池](../outputs/uv310-wireguard/evidence/inline-profiles/rekey-dns-grow-lto-control-icf-tests.json)：67场景/20错误对照。

涵盖握手/换钥、nonce、坏MAC/AEAD、分配失败/所有权、DNS往返、DHCP扩展、截止时间。256B模式保持模拟服务器随机源独立，并验证设备池实际耗尽后不复用；旧认证会话只在有效期内继续，过期关闭。1024B模式覆盖原18次重试预算行为。两组有大量重叠，不相加为新功能数。1024B池的合成回归不表示该容量能放进相同原厂布局；上述空间结论只适用于256B形状。

候选与所有故意错误变体都采用同一profile编译/链接。故障harness仍是合成环境，不能替代实际stock链接ELF在真实硬件上的执行。更改内联策略还可能改变时序和中断响应，这里没有验证。

## 复现与下一步

```sh
LLVM_CLANG=/path/to/clang LLVM_LD=/path/to/ld.lld \
QEMU_ARM=/path/to/qemu-system-arm make test-control-icf
LLVM_CLANG=/path/to/clang LLVM_LD=/path/to/ld.lld make audit-inline-profiles
```

`test-control-icf`分别运行两种池，保存独立结果；默认测试模式仍可复现旧profile。`audit-inline-profiles`明确记录超限实验，不因为一个实验超限就把它隐藏；CI执行成功不代表每种实验都可部署。

下一步可在这点余量中评估只读DNS诊断页的成本，并继续核对stock长度传递/真实布局。部署前仍需全新单次材料、原厂基线、实际heap/stack峰值与Wi-Fi验收；独立启动所需熵源和跨启动新鲜度、IPv6/多客户端、长时间稳定性尚未完成。
