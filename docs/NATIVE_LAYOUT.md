# Native最终链接布局：DNS候选的部署空间缺口

2026-10-26。本轮没有修改native功能源码，新增 [audit_native_layout.py](../tools/audit_native_layout.py)，用实际native链接脚本、真实ROM入口地址和公开合成配置做最终链接。临时ELF在结束时删除，不合成stock覆盖镜像、不生成新密钥、不部署。

**结论：最新`rekey-dns-grow`在历史256B随机池形状、普通编译方式下，超过原打包器的heap起点上限512B。当前不能按旧打包规则部署。** LTO可以让该形状刚好落到上限，但功能/时序尚未测试，没有新增布局余量，不能据此宣布内存足够。

## 为什么目标文件统计与QEMU通过不够

QEMU使用不同的测试布局；目标文件大小是输入文件统计，缺少最终链接的GC、对齐和全部密码库。本轮使用原 [layout.ld](../work/uv310-wireguard/rekey-layout/layout.ld)：hook固定`0x9df8`（4B），追加区从`0x2f340`开始，随后state/version，heap起点为image_end向上256B对齐。

历史打包规则要求heap起点不超过`0x33c00`。这只是既有实验策略，不是证明该地址以下一定安全，也不是当前实测最大可分配块。本工具发现超限会记录`fits_historical_ceiling:false`，**审计命令/CI成功仅表示完整产生报告，不表示所有候选满足空间限制**。

## 本机最终链接矩阵

格内为heap起点（相对历史上限的余量；负值为超限）：

| 候选 | 1024B池，无LTO | 1024B池，LTO | 256B池，无LTO | 256B池，LTO |
|---|---|---|---|---|
| rekey-memory | 0x33900（+768B） | 0x33700（+1280B） | 0x33600（+1536B） | 0x33400（+2048B） |
| rekey-pressure | 0x33a00（+512B） | 0x33800（+1024B） | 0x33700（+1280B） | 0x33500（+1792B） |
| rekey-dns | 0x33f00（−768B） | 0x33d00（−256B） | 0x33c00（0B） | 0x33a00（+512B） |
| rekey-dns-grow | 0x34100（−1280B） | 0x33f00（−768B） | 0x33e00（−512B） | 0x33c00（0B） |

[1024B无LTO](../outputs/uv310-wireguard/evidence/native-layout/native-layout-pool1024.json)、[1024B LTO](../outputs/uv310-wireguard/evidence/native-layout/native-layout-pool1024-lto.json)、[256B无LTO](../outputs/uv310-wireguard/evidence/native-layout/native-layout-pool256.json)、[256B LTO](../outputs/uv310-wireguard/evidence/native-layout/native-layout-pool256-lto.json)。

公开测试fixture原来含1024B随机池，历史单次实机实验使用256B。本工具仅截取公开合成池以模拟容量形状，不修改仓库fixture，也不是生成安全随机材料。**减少池容量会影响可进行的握手/重试次数，不能作为长期随机源方案。** 正式配置的数据值可能进一步改变优化/链接结果，仍需全新私有配置独立复核。

## 历史基线与stock交叉核对

[本地stock核对](../outputs/uv310-wireguard/evidence/native-layout/native-layout-stock.json)读取了用户自己的精确哈希镜像，确认长度193315B、追加起点在文件之后；不修改文件。

256B无LTO下，`rekey-memory`的probe14,948B、state1,864B、version192B、heap0x33600，与 [历史实机打包结果](../outputs/uv310-wireguard/evidence/rekey-memory-build.json) 的相应尺寸一致。这提高了布局模型的可信度，不是相同二进制或再次实机成功的证明。

工具检查所有allocated sections仅为hook/probe/state/version、彼此不重叠、无fixture/fake符号、无未解析符号，并记录参与源码哈希和有效合成配置哈希。它没有检查真实启动过程中每一处RAM占用，也没有测堆碎片、最大连续块、IRQ栈和峰值。

## LTO的边界

LTO是链接时跨编译单元优化。本轮仅在审计工具启用，不改正式候选默认构建。初次全部启用时，编译器后端生成的`__aeabi_memcpy`等helper缺失；将既有runtime.c单独以`-fno-lto`编译后可链接。不通过删除功能、缩短key、跳过校验或抬高heap上限获取结果。

**LTO候选尚无QEMU功能回归、实际机器码栈审计、时序、ROM联跑或设备验收。** 不能将既有普通编译的67场景/20错误对照结果转移给LTO版本。布局恰好满足上限也不是足够的部署依据。

## 复现与下一步

```sh
LLVM_CLANG=/path/to/clang LLVM_LD=/path/to/ld.lld make audit-layout
# 可选：本地只读核对owner提供的stock，结果不包含镜像字节
LLVM_CLANG=/path/to/clang LLVM_LD=/path/to/ld.lld \
python3 tools/audit_native_layout.py --pool-bytes 256 \
  --stock /private/owner-provided-stock.bin --out .test-results/native-layout-stock.json
```

公开CI可复现四组矩阵，不需要私有stock。首先为LTO建立有效的独立功能/栈验证，或在保留协议功能与边界检查的前提下减少代码；还需记录DNS计数器、核对原厂后续长度传递。设备回来后先恢复原厂基线，重新测最大块和运行峰值，再讨论部署。硬件Wi-Fi、独立启动、随机数/跨启动新鲜度、多客户端与长时间稳定性仍未完成。

## Linux复现

[运行40254309179](https://github.com/chinawrj/uv310-wireguard-research/actions/runs/40254309179) 已完成。四组矩阵的section地址/尺寸与heap起点逐项等于本机结果，超限结论同样成立。ZIP digest和报告源码哈希已核对；本轮没有执行LTO功能测试。

证据：[运行摘要](../outputs/uv310-wireguard/evidence/ci-native-layout/run.json)、[1024B普通](../outputs/uv310-wireguard/evidence/ci-native-layout/native-layout-pool1024.json)、[1024B LTO](../outputs/uv310-wireguard/evidence/ci-native-layout/native-layout-pool1024-lto.json)、[256B普通](../outputs/uv310-wireguard/evidence/ci-native-layout/native-layout-pool256.json)、[256B LTO](../outputs/uv310-wireguard/evidence/ci-native-layout/native-layout-pool256-lto.json)、[Linux工具版本](../outputs/uv310-wireguard/evidence/ci-native-layout/ci-environment.json)。
