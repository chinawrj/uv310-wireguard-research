# USB、AT、DIAG、EFS 与下载协议

以下为这台样机与这份固件的已用协议，不是通用刷机配方。USB endpoint 地址含方向位，所有长度、超时和响应都要校验。

## USB 模式识别

| 模式 | VID:PID | interface → endpoints |
|---|---|---|
| 正常运行 | 05c6:6000 | 0→01/81/82；1→02/83；2→03/84；3→04/85；4→05/86 |
| DMSS 下载模式 | 05c6:6000 | 0→01/81；1→02/82；2→03/83；3→04/84 |
| 光盘 | 05c6:f000 | 单接口；须另外核对只读光盘属性 |
| RAM loader | 1bbb:f000 | 单接口 0→01/81；这是历史 loader 实验状态 |

相同 VID/PID 不代表同一协议，尤其正常/DMSS 的 interface 3 IN endpoint 不同。现有恢复代码检查整个配置，不仅检查 interface 数量。光盘退出只对唯一匹配的 USB `4G MMC Storage Media`、`CD_partition_scheme`、15052800 B、只读设备操作。

## AT

正常模式 interface 1 OUT02 / IN83，ASCII 命令以 `\r` 结束，响应持续读取至 `\r\nOK\r\n` 或 `\r\nERROR\r\n`，限制总长度和截止时间。先有界清理旧输入，避免把上一条回复当成下一条。

只读基线：`AT^PROJECTNAME?`、`AT+CPIN?`、`AT+WIFI?`、`AT+WL=wl ver`、`AT+WL=wl isup`。`AT+WL` 是通向 Wi-Fi driver 的控制入口，native 补丁借 `wl ver` 返回 A/E/R/M 状态；stock 的 `wl memuse` 在已测环境也返回 ERROR，所以不把它作为堆内存 API。

## DIAG HDLC-like framing

正常模式 interface 3 OUT04 / IN85。payload 后附 CRC-16/X25（初值 ffff、反射多项式 8408、末尾 xor ffff，小端两个字节）。然后转义：7d→7d5d，7e→7d5e，帧尾7e。某些下载交换在帧前也加7e。接收按7e切帧、反转义并校验CRC，丢弃不匹配的异步帧。实现见 [list_efs_root.py](../outputs/new-dongle-hello/tools/list_efs_root.py)。

空口协议、USB bulk 边界、DIAG frame 边界不能混为一谈；一次 USB read 可含半帧或多帧。所有解析需累积缓冲和截止时间。

## EFS2 子系统 19

请求 payload：`4b 13 <command:u16 LE> <body>`；返回以相同四字节头开始，随后为操作响应。下表均指去掉四字节头后的 body。路径 UTF-8/ASCII NUL 结尾，不能含嵌入 NUL；现有脚本使用精确路径 allowlist。

| cmd | 操作 | 请求 body | 返回 body |
|---|---|---|---|
| 2 | open | flags:u32, mode:u32, path\0 | fd:i32, errno:i32 |
| 3 | close | fd:i32 | errno:i32 |
| 4 | read | fd:i32, count:u32, offset:u32 | fd:i32, offset:u32, actual:i32, errno:i32, data |
| 5 | write | fd:i32, offset:u32, data | fd:i32, offset:u32, actual:i32, errno:i32 |
| 8 | unlink | path\0 | errno:i32 |
| 11 | opendir | path\0 | handle:u32, errno:i32 |
| 12 | readdir | handle:u32, seq:u32（从1开始） | handle:u32, seq:i32, errno:i32, kind/mode/size/at/mt/ct:i32, name\0 |
| 13 | closedir | handle:u32 | errno:i32 |
| 14 | rename | old\0new\0 | errno:i32 |
| 15 | stat | path\0 | 7 个 i32；前3项 errno/mode/size |

读取分块1024B并检查 fd、offset、返回实际长度和总大小；最后关闭句柄。独占创建用已验证的 flags `0o301`，沿用目标模式；rename/readback 校验后才切换活动文件。errno=2 被当作不存在。写入脚本不提供任意 EFS/NV 写入口。源自 QCSuper 协议资料并在本机验证的实现见 [efs_probe_io.py](../work/uv310-wireguard/efs_probe_io.py) 和 [efs_rekey.py](../work/uv310-wireguard/rekey-memory/efs_rekey.py)。

历史 read-only PEEKB 收到 BAD_CMD；不要把任意地址读写假定成正常 DIAG 可用能力。

## 已验证的软件恢复链

在精确正常身份和 stock 活动镜像校验后，DIAG payload `3a` 请求下载状态；等待 DMSS 四接口拓扑，然后在 OUT04/IN84：`06`→`02`，`07`→`0807014000000000`，校验通过才发送 `0a` RESET。随后等待光盘、严格匹配并 eject，等待五接口正常模式，最后 AT 与完整 EFS readback。每一步都可能失败，不能跳过状态判定或向另一只网卡发送。

`reboot.py` 的命名沿用了历史 cold 字样，但证据明确写 `software_restart=true`、`physical_power_removal=false`。它不是物理断电测试。

## 下载模式 Hello World

历史 loader 通过 streaming HELLO `01 + "QCOM fast download protocol host" + 03 23 23 23 20` 确认协议，返回 opcode02 且含QCOM字符串。随后 `11 00 + 68B applet`，期望 `12 + "Hello World from UV310 ARM RAM!\n"`。

Applet ABI：R0代码指针，R1应答缓冲，返回 R4应答长度；ARMv5TE、ARM状态，位置无关，无 flash/MMIO访问。源码和构建脚本公开；专用 loader 本体未公开。本段不意味着可以向未识别的正常接口发送 EXEC。见 [hello-ram.S](../outputs/new-dongle-hello/hello-ram.S)。
