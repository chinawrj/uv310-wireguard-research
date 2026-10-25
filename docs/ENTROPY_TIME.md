# 随机数、时间和跨重启新鲜度

这是独立启动的核心未完成项；已完成实验使用主机fresh pool/TAI，不能按开机服务直接持久化部署。

## BCM随机helper

静态定位ROM helper `0x822715 → 0x82271d`，通过对象链wl `0x38d3c` / pub `0x2e90c` / WLC `0x2e9cc` / register base `0x18001000`，读取`0x1800165a`。曾返回32×16bit，共64诊断字节。证明调用/返回路径可用；没有证明最小熵、独立性、重启行为、偏差或硬件设计用途。GF(2)预测训练结果变化也不能当作密码学熵证明。

## DWT与jitterentropy路线

DWT cycle counter可读；固定循环显著确定，不能直接当随机数。已做jitter采样、多个collector内存布局、cooperative启动、window/预算控制、两次boot原始delta与冻结预测模型分析。部分startup health test通过，但没有完成可论证的熵源质量与安全reseed方案。完整WG+collector朴素组合reservation达30576B，内存压力显著；不能只看未链接的core对象大小。

公开原始时间delta CSV不包含密钥；它们支持重新分析，不是可用于生成密钥的随机池。相关分析源码与JSON被保留，完整第三方collector及私有firmware/ROM未包含，参见索引。

## 调制解调器 secure RNG 与桥接

静态路径 `0x12c4b48 → 0x1727f18 → 0x172ece0 → 0x172f720 → 0x1738a38`；secrnd task47，内部消息0x470001/2/3。这些是固件内部指针/消息，**不是可以直接发送的USB命令**。任务所有权、回包、生命周期和跨核传递仍需验证；NV4184 seed没有读取。现有ASP/AT/Wi-Fi控制桥尚未提供已验证的native安全seed注入途径。

## 时间

AT CCLK曾可用，但没有实现BCM native→modem时间桥；ASP时间为空、HTTP Date1970不能作为可靠当前时间。当前TAI64N使用每次build私有基值加attempt计数，只保证同一run，不保证重启后WireGuard对端接受或防止材料重用。不能靠给时间戳任意加大来替代持久化设计。

## 配置数据库与持久化

静态定位：getter0x182fc98、setter0x182fc08，共用request0x254c2c8。request+8 key指针、+12 op字节（0读/1RAM更新/2commit）、+16 value/output、+20 completion/task、+32 status。dispatch0x182daa0，RAM setter0x182d268只更新已有key、最多1499B且拒绝CR/LF。

`asp_get`第二参数字符串`"0"`实际调用空值setter，不能当作任意键值写接口。commit0x182d9d8使用5120B序列化buffer写`/web/userseting_nvconfig.txt`；未证明原子rename、掉电durability或全部失败检查。因此没有采用用户配置文件作为WG boot counter。`0x18362d8`对应`/web/update_skip`，并非通用commit，旧猜测已纠正。

下一步需要：受证据支持的seed/reseed与健康检测、失败即关闭、跨重启freshness状态、掉电一致性和密钥生命周期。完成前不宣称standalone startup。
