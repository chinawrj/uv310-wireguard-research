# 原生 WireGuard 数据路径与状态机

## 代码分层

- `wg-port/upstream/src`：wireguard-lwIP及其crypto源与许可证。
- `rng-provider/wireguard.c/.h`、`checked-random.h`：本地checked RNG失败传播、有限index选择等修改。
- `control-hardening/entry.S`：设备ABI hook及fixture入口。
- `rekey-lifecycle/native.c`：换钥状态机基础。
- `rekey-live/native.c`：已完成两次实机换钥的一次性有界实验。
- `rekey-memory/native.c`：增加内存观测的后续分支，本次断连，不应默认替代已成功版本。

## 数据路径

```text
普通 Wi-Fi IPv4 client
    → BCM packet hook → 验证 IPv4/长度/校验与策略
    → 单客户端源地址转换 → WireGuard AEAD → outer IPv4/UDP
    → stock SDPCM/modem → 蜂窝网络 → 对端 WireGuard
回程 → 解密/重放检查 → 还原客户端目的地址/校验和 → Wi-Fi TX
```

测试客户端没有主机WireGuard加密过程；真实原生tx/rx计数随普通ping、UDP DNS、TCP HTTPS变化。主机用于配置一次性材料、观察状态和发普通网络流量，不能因此声称设备已经完全摆脱主机配置。

当前实现仅一个IPv4客户端，检查源客户端MAC/IP并保存单客户端状态；不是多客户端conntrack/NAT。内层MTU1420，TCP SYN MSS限制1380，拒绝IPv4分片、非法TCP选项、非法长度、TTL<2；重算IP/UDP/TCP校验和。ICMP仅实验所需echo路径。LAN/管理/DNS存在旁路；IPv6有阻断策略但尚未完成全面覆盖审计。不能称为全流量无泄漏VPN。

## WireGuard消息

使用标准Noise_IKpsk2 / X25519 / ChaCha20-Poly1305 / BLAKE2s协议核心，不是自定义“类WireGuard”。Initiation148B，Response92B，transport16B header + AEAD ciphertext/tag；代码还要处理outerIP/UDP/Ethernet边界与MTU。协议常量、字段和重放窗口以`rng-provider/wireguard.c/.h`为准。

已实现initiator renewal：120000 cached ticks后换钥，180000 key age拒绝旧key，5000ticks重试，单cycle最多18次。当前/上一key分别保留receive replay state；过期和消息计数超限均拒绝。还没有完整retry jitter、receive-driven early renewal或server-initiated握手支持。

## 并发与主动发包

idle worker完成昂贵crypto；timer负责有界控制包发送和到期检查；收包hook接收response或解密数据。claim_phase在PRIMASK临界区再次确认expected phase，避免刚到的response被retry覆盖；publish_phase再次检查deadline/stopped，避免旧worker结果把失败态改回可用。crypto可变状态阶段会丢弃部分外部包，目前没有完整排队。

控制包kind1是initiation，kind2是keepalive；控制队列还校验排队时间、所属key index与key年龄，过期丢弃不发送。真实free hook记录提交/归还，避免泄漏或double-free。合成负向测试刻意删除这些保护，必须出现FAIL才算测试有辨别力。

## 一次性材料和实验停止

真实实机采用每次由主机新生成的256B或512B随机池、当前TAI基值。checked RNG耗尽时置rng_failed并清零输出/返回失败，不回退到固定字节。TAI随尝试次数递增仅保证本次运行内有序，跨重启不成立。

从第一次外部数据包起360000 cached ticks有硬实验时限；packet/timer/worker/publish均检查，最终phase255。`rekey-live`已实测到期后额外ping0/2、nativeTX/control不再增加、drop增加。该时限是限制研究运行，不是产品设计；不能延长时限就宣布解决熵/新鲜度。

## 遥测协议

通过`AT+WL=wl ver`读取192B版本缓冲，轮转A/E/R（memory版本另有M）页，每页16个u32字段。A=执行phase、错误、handshake与数据计数、时钟；E=control queue/ownership；R=renewals、RNG/key年龄、deadline；M=堆与栈。准确字段顺序见`rekey-memory/live.py`。页面分别采样，四页组合不是同一瞬时的原子快照，比较时要看各自clock。

状态中的`err`可能记录最后一次非致命drop，比如最后memory快照err50（十进制）不等于握手失败；需结合phase、计数与源码对应分支。切勿只看单一错误数字判断成功/失败。
