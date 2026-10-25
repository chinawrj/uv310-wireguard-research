# 分配重试、业务流量与会话计数器

2026-10-26。对`rekey-pressure`追加离线验证，native源码未变：`65b9c193117f0fc7818d20d894abcf5fe57750036434d71e17acf51c20a5e562`。候选依然没有部署。

## 为什么需要独立检查

WireGuard传输数据使用会话密钥和发送计数器构造AEAD nonce。同一密钥下再次执行加密，不能复用已经用过的计数器。已经生成的密文被延迟发送，与再次调用加密不是一回事。[官方协议](https://www.wireguard.com/protocol/)。

保活消息在worker中完成加密，然后等待timer分配控制包。这段时间普通业务包仍可能使用同一会话继续加密。分配失败或丢弃保活时，已经使用的计数器必须留作空缺，不能退回；之后成功发送旧保活，也不能拿当前计数器重标其报文头。

## 独立记录器

测试通过链接器`--wrap=wireguard_encrypt_packet`，在加密API边界记录设备发送方向的密钥和counter。以密钥字节为身份，在每次实际加密前要求counter严格递增；新密钥可从零开始。最多8种密钥，记录容量不足也报失败，不静默跳过。

它不依赖接收端是否成功解密，也不依赖packet提交次数。场景返回成功后还有统一检查，防止记录器的错误被吞掉。额外的负向probe主动将初始保活已使用的counter恢复为0并调用加密，随后不做任何解密或包检查，独立记录器仍必须使整项测试失败。此probe已验证有效。

记录器只在测试ELF中存在；观察范围是设备peer的current/previous/next keypair，不记录合成server侧加密。使用公开固定测试密钥，不输出密钥内容；不链接进设备候选，不增加其代码、RAM或运行时日志。

## 新增交错场景

| 场景 | 检查 |
|---|---|
| NONCE_DELAYED_KEEPALIVE | 保活加密后分配失败；两次业务往返先完成；恢复容量后用原counter发送保活并通过认证/重放检查，没有再次加密保活 |
| NONCE_DISCARDED_KEEPALIVE | 业务流量穿插，保活分配三次失败后丢弃；下一保活跳过已使用counter，不回退、不复用 |
| NONCE_REKEY_PRESSURE | 上述延迟场景后再次更新会话，握手分配遭遇压力并恢复；确认发送密钥改变、新密钥从counter0保活开始，随后双向UDP校验通过 |
| NONCE_WRAP_INTERLEAVE | 同样的延迟发送与业务交错跨过32bit时钟回绕，nonce顺序与退避逻辑保持正确 |

全部45项QEMU场景通过，12项负向控制被检测：11项源码变异加1项fixture主动复用counter的独立probe。新增两项源码变异是在丢弃保活时回退counter、在业务包加密前回退counter，均被捕获。此前分配次数、退避、所有权、队列/密钥/实验期限测试继续通过。

最新机器可读证据：[nonce-lifecycle-tests.json](../outputs/uv310-wireguard/evidence/nonce-lifecycle-tests.json)。初始41项/9项结果仍保留在[rekey-pressure-tests.json](../outputs/uv310-wireguard/evidence/rekey-pressure-tests.json)。复现入口仍为`make test-pressure`，依赖见[BUILD.md](BUILD.md)。

## 结论范围

在这些合成序列中未发现分配重试导致的同密钥nonce复用；原生候选无需为此修改。它不是完整协议验证、并发证明或密码学审计，也不证明跨重启安全。真实IRQ/ROM/SDIO时序、长期运行、合格熵源与跨重启新鲜度仍待解决；不能把固定随机池的离线通过当作独立启动许可。
