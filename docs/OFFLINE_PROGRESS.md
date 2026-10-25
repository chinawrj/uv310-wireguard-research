# 无硬件阶段：诊断工具与换钥资源分析

2026-10-26，用户明确已拿走UV310，Goal恢复active并允许推进离线工作。本轮没有枚举或访问USB，没有访问WireGuard管理端、发送测试网络流量、重启或部署设备。没有新的实机成功结论。

## 有界状态观察器

新增`work/uv310-wireguard/rekey-observe/observe.py`，入口是单次只读状态采样。它与历史`rekey-memory/followup.py`并列保留，**没有覆盖原始失败harness或证据**；后续实机collector可调用`collect()`接收结构化错误。

- 核对完整USB拓扑，未匹配前不发命令；身份验证前只允许项目查询。
- 只发`AT^PROJECTNAME?`与`AT+WL=wl ver`；不发送RESET、模式切换、EFS或NV写入。
- stale输入最多8次read；每条命令5s截止、64次read和8192B上限；最多12次状态页查询。
- 错误分类包含DEVICE_ABSENT、TOPOLOGY_MISMATCH、USB_IO_ERROR（保留数字errno）、AT_ERROR、AT_TIMEOUT、SHORT_WRITE、REPLY_LIMIT、IDENTITY_MISMATCH、MISSING_STATUS_PAGES和MEMORY_SNAPSHOT_INVALID。
- clock倒退单独标为CLOCK_DISCONTINUITY，正常32bit回绕允许；该错误是观察不连续，不足以单独证明重启。
- host采样分别记录接口IP和网关route，区分主机换网、lab client条件不满足与USB/AT错误。当前host接口为macOS en0固定实验配置，不能直接泛化到其他平台或DHCP地址。
- finally释放interface/USB资源；cleanup错误附加到原始错误，不掩盖最初失败。
- 输出文件独占创建，已有证据不覆盖；不记录任意AT响应文本、serial或后端私密错误字符串。

```sh
# 离线，USB发现与操作全部mock
make test-observer

# 仅在硬件回来、确认合适正常固件后使用；本轮没有运行该命令
python3 work/uv310-wireguard/rekey-observe/observe.py --out /tmp/uv310-status-new.json
```

23项故障注入通过，含断连errno、拓扑、身份、分片回复、超时/超量、释放失败、错误优先级、clock倒退/回绕、主机换网、已有证据不覆盖。见[测试结果](../outputs/uv310-wireguard/evidence/observer-offline-tests.json)。`status_read_ok`仅表示遥测读取成功，不证明WireGuard握手、转发或换钥；`vpn_or_rekey_verified_by_this_tool`始终为false。stock固件没有A/E/R/M页时应报告缺页，不能把它解释为硬件损坏。

## 编译器可见的栈资源

新增`tools/stack_audit.py`，用公开合成配置、`BOUNDED_REKEY_LAB`实际代码分支、Cortex-M3/Thumb/-Oz编译参数生成`.su`与汇编，提取单函数frame和可见直接调用路径。临时编译产物结束后删除，仅JSON留在`.test-results/`；不链接或生成设备镜像。

```sh
LLVM_CLANG=/opt/homebrew/opt/llvm/bin/clang make stack-audit
LLVM_CLANG=/opt/homebrew/opt/llvm/bin/clang python3 tools/stack_audit.py --branch rekey-live
```

| 入口 | 成功的rekey-live | 后续rekey-memory | 单位/范围 |
|---|---:|---:|---|
| worker | 1060 | 1060 | 可见直接调用链frame相加，字节 |
| intercept | 640 | 640 | 同上 |
| emit_control | 48 | 48 | 不含raw_alloc/submit/ROM路径 |
| snapshot | 176 | 192 | 同上；memory版本多出16B |
| memory_snapshot单函数 | 不存在 | 32 | compiler frame |

memory版本编译得到131个函数，live为130。最大单函数frame为`wireguard_process_handshake_response`360B；`wireguard_start_session`280B。这次没有看到新内存观测分支引入明显的**可见静态栈增长**。

**这不是完整栈上界，也不是实机峰值。** 还有编译器产生的寄存器间接调用、汇编hook frame、exception stacking、IRQ嵌套、stock调用者与ROM callee未计入；tail call被保守相加，因此不能把数值简单称为上界或下界。两次编译使用公开合成材料，不是此前私有部署binary的逐字节重建。报告明确列出未解析项，不能用1060B与实测unused2272B相减来宣告“安全余量”。

编译可见函数未发现直接标准`malloc/calloc/realloc/free`调用；这不排除`raw_alloc`、ROM或stock driver分配，更不能排除OOM。当前证据不足以给上次断连定因。

原始报告：[live](../outputs/uv310-wireguard/evidence/stack-audit-rekey-live.json)、[memory](../outputs/uv310-wireguard/evidence/stack-audit-rekey-memory.json)。

## 下一步

离线继续：解析间接调用并补栈模型、增加中断/分配失败对照、建立持续集成和更完整的协议/转发异常测试。硬件恢复后：先原厂身份/hash/网络基线，再独立诊断采样，最后以新材料做最小实机实验。不要重新使用旧keyed image；熵源、跨重启freshness、长期运行与UDP性能仍需实机证据。
