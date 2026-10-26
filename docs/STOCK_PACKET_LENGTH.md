# 原厂Wi-Fi发送前段的packet长度重放

2026-10-26。为了缩小 [DHCP有界扩展](DHCP_GROWTH.md) 与原厂驱动之间的证据缺口，对用户此前保存的精确ROM和stock RAM镜像进行了离线Unicorn重放。**没有访问硬件，没有修改或输出固件，没有验证无线发送完成。**

## 找到的实际调用路径

| 原厂位置 | 本次证据 |
|---|---|
| `0x80fc34`，dispatch槽`0x890` | stock指向`0x80fc3d`，执行普通Wi-Fi发送包装函数 |
| `0x806d5c`，槽`0x618` | stock指向`0x806d65`；遍历packet链并按flag更新计数，返回原packet指针 |
| `0x80f7a0`，槽`0x88c` | stock指向`0x80f7a9`；本次构造上下文关闭可选分支 |
| `0x80fcc8` | 调用Ethernet发送入口`0x8281a4` |
| `0x8281a4`，槽`0x11f4` | stock指向`0x8281ad` |
| `0x8281b2` | 执行`ldrh r0, [r1, #0x14]`，直接读取packet的16位长度 |
| `0x8281c2` | 执行`ldr r5, [r1, #0x10]`，直接读取数据指针 |
| `0x8281c6`之前 | 停止重放，不继续推断后面的封装/队列/无线发送 |

6个短指令锚点与4个dispatch槽均针对精确哈希校验。**在这条选定前段没有观察到另一个必须同步的长度副本**，因此候选更新`packet+0x14`与这个消费者匹配；不能推广为所有原厂消费者都匹配。

## 重放结果

[完整脱敏报告](../outputs/uv310-wireguard/evidence/stock-packet-length.json)：

- 32个正向组合：长度286–292及2048字节 × 原厂可选`0x80` packet flag开/关 × 原`0x200`计数flag开/关。使用相同的真实指令，不是重新实现这些ROM函数。
- 到达停止点时核对寄存器读到的长度、数据指针、packet指针；核对整个packet元数据与payload未发生意外变化，以及计数行为。
- 3个输入故障对照：增长后的payload仍携带旧长度、长度少1、数据指针偏移1。消费者观察值检查均能发现。**它们是fixture故障，不是修改ROM代码，也不是新的固件漏洞。**
- 2个镜像哈希门槛检查：错误ROM和错误stock均在模拟前拒绝，不产生结果文件。
- Unicorn2.1.4、Capstone5.0.7。首次在沙箱内模拟时进程以132退出；同一脚本在本地授权环境通过。不把这次工具执行失败记作设备崩溃，也未据此修改ROM。

## 复现与私有依赖

工具：[replay_stock_packet_length.py](../tools/replay_stock_packet_length.py)。只接受用户自己的以下精确镜像：

- ROM SHA-256：`f96f3e5f1dd2352a71b777ce4fc586cefdc2c62977eae3cef0a82461a8ae5bb4`
- stock SHA-256：`4b86d71b92529034b2b46da7b93402f67c8aef98d2fc1efa91fc67ff7e5fb85a`

```sh
python3 tools/replay_stock_packet_length.py \
  --rom /private/owner-provided-bcm43362-rom.bin \
  --stock /private/owner-provided-stock-rtecdc_new.bin \
  --out .test-results/stock-packet-length.json
```

需要本地可用的Unicorn/Capstone。输出必须不存在，避免覆盖证据。工具不执行USB、AT、网络、部署或复位操作；没有包含固件字节。GitHub普通CI没有这些私有镜像，因此本项不是公共CI可自行复现的测试；合成候选的CI证据仍单独保留。

## 能得出的结论及剩余工作

这项结果提高了“修改packet长度能传到原厂Ethernet入口”的可信度，但上下文、feature flags、packet内存和payload均由测试构造。native扩展函数和ROM前段仍分别测试，尚未在一个真实链接镜像中联跑。没有证明DHCP实际经过hook，也未覆盖可选过滤/加速器、DMA、IRQ、队列、headroom、全部生命周期与后续封装路径。

下一步需继续检查实际Ethernet路径如何使用长度及是否重分配，验证真实stock链接布局与RAM余量，补可读取的DNS统计。硬件回来后必须采集真实flags/路径并完成租约、DNS往返、Wi-Fi路由和稳定性验收。

最终链接空间审计发现当前候选超出历史无LTO打包上限，见 [NATIVE_LAYOUT.md](NATIVE_LAYOUT.md)。此前功能/ROM前段通过不证明可部署。
