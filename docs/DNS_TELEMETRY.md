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

## N页布局优化（后续隔离实验）

保留前述D页失败预算作为历史证据，追加三种实现比较：

| 方案 | probe字节 | 历史布局余量 |
|---|---:|---:|
| 原始无新页基线 | 16268 | 256B |
| 原D页，清空保留字段 | 16324 | 0B |
| 复用A页字段、显式轮转、保留版本字段 | 16296 | 0B |
| 独立N标签标识格式，省去重复版本字段 | 16292 | 0B |
| N格式 + 互斥页分支使用else-if | 16280 | 256B |

最后方案增加12B代码，state仍1884B；heap起点0x33b00，可见worker/intercept/snapshot仍1052/712/192B。仅适用于报告中的合成配置与工具链。独立N标签明确区别于未接入的D提案，不能用D解析器解读N。

N页字段索引固定为：0 dhcp_rewrites、1 gateway_udp_rejects、2 lan_dns_guard_drops、3 rx_count、4 rng_pos、5 init_time、6 response_time、7 receive_len、8 worker_count、9 f_tx、10 f_rx、11 f_drop、12 f_out_bytes、13 f_in_bytes、14 allocation_failures、15 clock。索引3–15继承A页语义。`N`本身标识这份固定schema，后续不兼容修改需要新标签或显式协议协商，不能悄悄复用N。

轮转改为A/E/R/M/N，查询不提供跨页原子性。多个查询者会共同推进轮转，客户端应按标签收集并使用有界查询次数。尚无boot identity，单靠计数回落不能区分回绕与重启。没有新增已观察报文计数；N仍不能单独证明DNS客户端可用。

`tools/evaluate_dns_telemetry.py`现在复现五种布局；最新结果为[追加预算](../outputs/uv310-wireguard/evidence/dns-telemetry/optimized-budget.json)，旧budget.json保持不变。它仍是纯资源测试，功能验证由独立的`tools/test_dns_telemetry.py`执行：按资源报告中的patch及哈希，在临时副本中重建N候选，公开native源码保持原样。

### N页合成回归结果

[本机QEMU结果](../outputs/uv310-wireguard/evidence/dns-telemetry/n-page-tests.json)：256B池control-icf隔离候选通过原67个集成场景；每个场景前执行三轮共15次snapshot，检查标签、16字段的十六进制/分隔符、N计数、继承A字段、NUL与缓冲尾部、零值与uint32最大值表示，以及不清计数、不消耗随机池、不分配/释放packet、不改phase。后三者是该合成初始状态内的观察，不证明任意并发下无副作用。

原21个错误对照与新增5个对照均检出：交换计数、轮转提前回零、错误标签、读取时清零计数、错误NUL。不是26个独立功能，也不是硬件验证。最大值测试检查编码，不是一次真实计数器溢出或host差值算法验证。

```sh
LLVM_CLANG=/path/to/clang LLVM_LD=/path/to/ld.lld \
python3 tools/evaluate_dns_telemetry.py
LLVM_CLANG=/path/to/clang LLVM_LD=/path/to/ld.lld \
QEMU_ARM=/path/to/qemu-system-arm python3 tools/test_dns_telemetry.py
```

测试工具要求先生成当前源码对应的预算报告，并核对候选哈希。报告derived_source_sha256是隔离派生源码；顶层source_sha256是公开原始输入。该隔离固件测试未新增Linux独立复现，也未修改原native.c。后续host协议支持见下节；不能直接部署。

## 主机观察器已支持N1（离线验证）

`rekey-observe/observe.py`新增显式`--protocol n1`，必须在最多12次状态查询中收齐A/E/R/M/N；如果设备仍只有旧四页，会报`MISSING_STATUS_PAGES`并列出缺少N，不能自动降级为成功。默认`--protocol aerm`维持旧四页要求，遇到额外N页时忽略，适合原候选。未运行任何实机查询。

将来使用已核对的N固件时，查询命令为：

```sh
python3 work/uv310-wireguard/rekey-observe/observe.py \
  --protocol n1 --out /path/to/new-observation.json
```

这是真实USB读取命令，不属于离线测试；硬件缺席时不要执行。输出文件必须不存在，防止覆盖旧证据。仅使用原有身份与版本AT查询，没有新增设备写配置或重启命令。

解析器现在要求完整状态行、准确16个小写十六进制字段与分隔符，可接收固定版本前缀。包含多个已识别页的同一回复拒绝为`AMBIGUOUS_STATUS_REPLY`；畸形已识别页报`INVALID_STATUS_PAGE`，不保存原始回复正文。任意嵌入文本中的类似页字符串不会被识别。

N字段映射已逐项与隔离QEMU提案报告核对一致。[36项mock测试记录](../outputs/uv310-wireguard/evidence/dns-telemetry/observer-tests.json)涵盖原有故障行为，以及五页收集、不同轮转起点、旧固件缺N、重复N不能替代别的页、字段映射、非法字段/多字段/缺字段、时钟回绕/倒退、异常清理与错误内容脱敏。纯离线复现使用`make test-observer`。此前23项是旧版本结果，不覆盖N。

观察器记录协议选择，并明确`dns_path_verified=false`。五页不是跨页原子快照；无boot identity，部分重启时钟变化仍可能不可区分。原生固件仍未正式接入N页，这个host工具通过mock不代表设备已提供该协议，也不代表DNS经隧道验收完成。

## 2026-10-28：独立候选与统一入口

N页源码现已保存为 [rekey-dns-observe/native.c](../work/uv310-wireguard/rekey-dns-observe/native.c)，与此前通过QEMU验证的exclusive-n-page派生源码逐字节一致；原rekey-dns-grow保持不变作为对照。原源码注释保留以维持哈希一致，目录README标识新候选身份。

统一离线入口是`make test-dns-observe`，先重做五种布局比较、验证候选与对照转换一致，再直接读取该候选进入隔离构建，并执行67场景/26错误对照及观察器mock测试。配置和测试harness仍共享原分支，避免复制后漂移。GitHub工作流已接入这个入口；加入CI步骤本身不是已通过CI的证据。

“独立候选”只表示源码、测试入口和host协议已经连接，不是已生成真实配置镜像，也未证明固件启动或Wi-Fi链路。在恢复硬件前继续保留这些验收边界；不增加自动刷写入口。
