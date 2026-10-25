# 最新实机内存观测：成功测量，运行中断

此记录与此前成功的 `rekey-live` 分开。memory分支加入有界free-list/sentinel观测，25项合成测试和3项负向控制通过，随后部署了单次fresh材料候选。

| 指标（字节，计数另注明） | 首次流量前 | 最后成功快照 |
|---|---:|---:|
| arena | 106012 | 106012 |
| 当前allocated payload | 95072 | 99544 |
| 当前allocated headers | 1672 | 1768 |
| 历史payload peak | 98832 | 103800 |
| free payload | 9212 | 4636 |
| 最大free block | 8808 | 4444 |
| free nodes（个） | 7 | 8 |
| allocation failures（次） | 0 | 1 |
| stack sentinel unused | 2596 | 2272 |

两次free-list valid/stack bounds valid均为1；last样本在followup125.773秒，key age119320 cached ticks，renewals仍为0。累计control submitted/freed7/7、error0，rng_pos68/256、rng_failed0，native f_tx/f_rx62/62。观察期allocation failure从0到1后保持；仅凭它不能确定失联原因。

后续138.794秒一批ping0/4、DNS timeout；141.797秒status AssertionError；147.812秒外层AssertionError结束，`passed=false`。随后独立USB枚举没有UV310，电脑已自动/实际回到原Wi-Fi（UI确认）。日志不能区分设备重启、供电/拔出、固件故障等原因；本分支**未证明第一次换钥完成**。

arena−peak_payload=2212B仅为未扣除元数据时的历史空闲上界。不能把当前headers1768B减到历史peak上来声称得到精确最小空闲，也不能把snapshot剩余4636B等同于最差时刻可用量。

本轮原厂控制对照：36/36 `wl ver`查询（12快速、12间隔250ms、12快速）均成功；`wl memuse`原厂也ERROR。说明单纯memuseERROR不是OOM证据，快速查询本身也未在stock复现故障。

断连之前已恢复存储stock并readback完整hash；首次restore超时，第二次成功，早于Wi-Fi流量。断连之后无法再次验证stock运行态。恢复状态详见 [CURRENT_STATE.json](../CURRENT_STATE.json)。

证据：[初始状态](../outputs/uv310-wireguard/evidence/rekey-memory-status.json)、[全部followup及失败](../outputs/uv310-wireguard/evidence/rekey-memory-followup.json)、[存储恢复](../outputs/uv310-wireguard/evidence/rekey-memory-efs-restore.json)、[原厂查询对照](../outputs/uv310-wireguard/evidence/query-reliability-stock.json)、[测试](../outputs/uv310-wireguard/evidence/rekey-memory-tests.json)。
