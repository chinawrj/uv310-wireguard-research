# 内存压力下的控制包重试候选

2026-10-26，离线候选 `work/uv310-wireguard/rekey-pressure`。未访问设备、未制作可部署镜像、未实机验证。它以 `rekey-memory` 为对照；原实机源码及其失败记录保留，详见[上一轮故障实验](ALLOCATOR_FAILURES.md)。

## 改动解决什么

旧版本中，首次握手、更新会话或保活的控制包只要一次分配失败，就会永久停止本轮转发。候选版本将**分配返回0**改为有限重试；packet布局或上下文异常仍终止。WireGuard的密钥生命周期没有放宽，也没有修改加密算法或协议。

每条已生成的控制消息最多尝试分配3次，失败后的间隔至少250个缓存时钟tick。该参数是适配层策略，不是WireGuard的重试定时常量；目前不能把tick换算成新的实机性能结论。第一次在t尝试，后续最早t+250、t+500，实际执行还受timer调度影响。

第三次仍失败时丢弃本条控制消息：握手回到现有等待/重试流程，下一次握手生成仍受原5000 tick间隔和周期尝试上限约束；保活回到原20000 tick调度。新消息重置分配次数。已经提交给stock的包继续等待真实释放观察点，不超时强行free或复用。

分配重试不再次生成随机数、不重做握手、不重新加密保活消息、不回退发送counter。消息过期、密钥过期和实验总期限优先于退避检查；分配调用返回后再次检查期限。仍有有效会话时可继续加密转发；没有有效会话时，所测试的客户端外网IPv4被拒绝。

## 验证

```sh
# 和make test相同的LLVM/QEMU依赖，见BUILD.md
make test-pressure
LLVM_CLANG=/opt/homebrew/opt/llvm/bin/clang python3 tools/stack_audit.py --branch rekey-pressure
LLVM_CLANG=/opt/homebrew/opt/llvm/bin/clang python3 tools/compare_native_size.py
```

初始41项QEMU场景、9项负向变异检查通过。后续加入独立nonce记录器与交错场景，共45项场景、12项负向控制通过，见 [NONCE_LIFECYCLE.md](NONCE_LIFECYCLE.md)。继承的ALLOC_NULL_FIRST/REKEY/KEEPALIVE现在验证恢复而不是终止；畸形packet仍验证释放并终止。覆盖两次失败后第三次成功、持续失败达到次数限制、新控制消息重新获得次数预算、32bit时钟回绕、队列过期、密钥过期、实验期限、分配调用中时间推进、延迟释放与包所有权。

恢复场景实际完成合成对端握手及双向加解密UDP校验，并检查随机池位置、握手序号、发送counter和内存记账。没有有效会话的退避期间另行验证外网IPv4不被放行。负向变异包含删除退避、删除次数上限、恢复旧版一次失败就终止、遗漏每条消息的预算重置，均被捕获。测试使用模拟ROM allocator与显式时间推进，不模拟真实SDIO/USB/射频/中断调度。

| 相同编译参数下的对照 | rekey-memory | rekey-pressure | 说明 |
|---|---:|---:|---|
| native.c目标文件可执行段 | 6258 B | 6370 B | 增加112 B |
| native.c目标文件可写分配段 | 1994 B | 2002 B | 增加8 B；编译器优化后的段计数 |
| native.c目标文件只读分配段 | 1453 B | 1453 B | 无增量 |
| worker可见调用链frame和 | 1060 B | 1060 B | 不含所有间接调用/ROM/中断 |
| emit_control可见调用链frame和 | 48 B | 48 B | 不含raw_alloc/free/submit实现 |

目标文件比较使用`BOUNDED_REKEY_LAB`、Cortex-M3/Thumb/-Oz和公开合成配置，没有链接或部署。它未考虑最终链接裁剪、对齐与整体镜像位置，不等同于最终RAM占用或heap余量。静态调用链也不是完整栈上界或实机峰值。

证据：[QEMU结果](../outputs/uv310-wireguard/evidence/rekey-pressure-tests.json)、[栈分析](../outputs/uv310-wireguard/evidence/stack-audit-rekey-pressure.json)、[目标文件大小](../outputs/uv310-wireguard/evidence/native-size-pressure.json)。

## 未完成项与下一步

本改动只改善适配层遇到临时控制包分配不足的行为，**没有证明上次USB消失的原因已经找到或解决**。真实allocator失败语义、stock包所有权、IRQ上下文与计时仍需硬件对照。也未解决独立启动熵源/跨重启新鲜度、完整多客户端/DNS/IPv6策略、长时间内存稳定性或UDP性能。

候选目录刻意没有附带历史部署脚本。不能拿它替换原厂文件或沿用旧随机材料。硬件回来后先做原厂基线和身份/hash检查，再评估链接布局及新鲜材料，最后进行单变量短时实验；保持已恢复的原厂备份和回滚路径。
