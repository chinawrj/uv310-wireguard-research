# DNS诊断页预算与计数语义

2026-10-26。硬件不可用，仅对公开合成配置的隔离副本做最终地址链接。当前`rekey-dns-grow/native.c`没有修改，上一轮control-icf候选仍然保留。

## 为什么需要诊断

当前A/E/R/M页不包含已有的`dhcp_rewrites`、`dhcp_rejects`、`lan_dns_drops`。单看总转发量或最后错误码，无法判断DHCP改写是否发生，更不能证明DNS请求已通过隧道。最后错误码会被后续错误覆盖。

检查native intercept后，三个字段应准确解释为：

| 内部字段 | 实际含义 | 不能推出什么 |
|---|---|---|
| dhcp_rewrites | 改写器返回REWRITTEN且packet长度已更新的次数 | 客户端收到/接受新的DNS配置 |
| dhcp_rejects | 来自精确网关地址的入站UDP因packet不可写，或改写器返回负值而被拒绝 | 每次都是DHCP报文；不可写检查发生在改写器识别DHCP之前 |
| lan_dns_drops | LAN DNS guard拦截次数，包括无法分类的畸形/分片TCP、UDP | 所有被拦截的都是已确认的53端口DNS |

现有计数为32位且会回绕。全零可能是没有相关流量、未经过hook、或刚重启；没有观察到的计数不能当成hook未执行的证据。A页f_tx/f_rx也是总量，不是DNS专属计数。此轮没有新增流量可见性或修正这些语义。

## 最小D页实验

保持16个8位十六进制字、逗号分隔、192B version缓冲区。提出A→E→R→M→D轮转；D布局为：0格式版本1，1改写次数，2网关UDP拒绝次数，3LAN DNS guard次数，4–14保留0，15原厂cached clock。仅读取已有计数，不重置计数、不输出密钥、地址或报文内容。它只是提案，不是已经支持的协议。

| 最终链接项目 | control-icf基线 | D页隔离副本 |
|---|---:|---:|
| probe代码常量区 | 16268B | 16324B |
| state | 1884B | 1884B |
| 对齐heap起点 | 0x33b00 | 0x33c00 |
| 相对历史上限余量 | 256B | 0B |
| 可见worker / intercept栈链 | 1052 / 712B | 1052 / 712B |
| 可见snapshot栈链 | 192B | 192B |

仅增加56B代码却跨过256B对齐边界。余量是链接布局差值，不能称为实测可用内存；可见frame合计也不是完整栈上界。该提案没有重新执行功能测试、轮转/序列化错误对照或实机测试，不能据此部署。

[完整原始报告](../outputs/uv310-wireguard/evidence/dns-telemetry/budget.json)包含隔离副本patch、派生native哈希、基线/提案两份链接报告与工具版本。嵌套提案报告的native哈希对应patch后的隔离文件，顶层source_sha256对应公开仓库原始输入。

## 可复现步骤与下一步

```sh
LLVM_CLANG=/path/to/clang LLVM_LD=/path/to/ld.lld \
python3 tools/evaluate_dns_telemetry.py
```

[评估工具](../tools/evaluate_dns_telemetry.py)只复制公开work和tools到临时目录，临时更改native源文件，链接并删除临时ELF；不会生成组合固件、读取私有配置或访问硬件。结果写入`.test-results/dns-telemetry-budget.json`。本轮为本机实验，未声称Linux CI复现。

接入前需决定是否为诊断再腾出空间、是否需要更精确的分类计数，并增加D页格式、轮转、保留字段、计数回绕及故意错位字段的验证。旧observer只要求A/E/R/M：即使固件多出D页，它也可能在收齐旧四页后提前返回；必须显式选择需要D页的协议版本，不能把“旧observer成功”当成D页验收。

最终仍需实机确认DHCP hook覆盖、客户端DNS配置和DNS请求/应答经过隧道。离线代码布局不能替代这些证据。
