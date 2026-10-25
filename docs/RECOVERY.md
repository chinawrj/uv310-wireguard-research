# 实机部署与恢复交接

这是已验证机制的说明；公开仓库不附可刷镜像，也不提供一键安装。必须使用所有者的设备和匹配哈希的stock备份。当前设备不在线，不要假装已完成本轮运行态恢复。

## 部署前不变量

- 完整正常USB拓扑、AT项目、stock文件尺寸/哈希都匹配。
- 原厂Wi-Fi、DHCP、SIM及蜂窝连接基线可用，主机原网络可恢复。
- 候选native源与通过的测试源hash一致，真实build无fixture符号。
- 新生成私有材料；生成后≤1200s才允许stage/activate，已存在candidate boot记录则拒绝重放。
- 只允许active、stock backup、candidate stage三个精确EFS路径，backup/stage只在不存在或字节完全相同时使用。
- 不修改raw NAND、分区表、bootloader、QDSP固件、SIM或用户NV配置。

## 已用事务式流程（非掉电原子性保证）

1. stage：active必须stock，独占创建stock backup/candidate stage，全部readback验证。
2. activate：确认backup的stock hash和stage候选hash；rename stage→active；完整readback候选。
3. 通过校验过的DIAG→DMSS→RESET→光盘eject→正常模式加载候选。
4. **在任何Wi-Fi流量测试前**立即rename stock backup→active并完整校验。候选继续在RAM中运行，存储上的下次启动文件已经回滚。
5. 只运行有界一次性实验；不把含旧pool/TAI的文件留作长期启动镜像。
6. 停止后确认主机回原网络；在设备可访问时验证stock active，software restart，再确认stock wl ver/isup/SIM和网络。

latest memory首次restore超时，第二次restore成功且早于client traffic，证据保留两次结果。`package.py`的历史生成模板与手动强化后的`reboot.py`存在差异：后者有3次有界restore重试；重新生成可能覆盖这个改动，必须diff审阅，不能盲跑。

## 当前记录

`rekey-memory-efs-restore.json`为成功readback证据；candidate hash `a0dd391a08d715051fdd83c4c70432c2ee37c653ae296c89c105b98386bac56e` → stock hash。测试后来失败且USB消失，所以没有新的`rekey-memory-final-status`成功记录，不能把上一轮`rekey-live-final-status`拿来顶替。

如果设备回来：只读识别→readback stock→查询版本/服务。如果活动文件不是已知stock/candidate，停止写入并保存新证据；如果没有设备，只能记“不可访问”，不要对ASIX/其他dongle试同一命令。完整断电必须由实际物理断开确认；软件模式切换不等同于完全断电。

## 重要失败模式

- 重启后临时SIM busy / wl ERROR：可能初始化未完，要有界等待和后续证据。
- CarPlay可关联但DHCP/ARP管理页失效：关联成功不能说明系统网络可用。
- wl memuse ERROR：stock也出现，不作为OOM判据。
- native存储文件已回滚但RAM仍运行：两个状态单独记录。
- AT silent、DIAG仍可识别：先用只读身份确定，不用盲目reset。
- 相同PID不同interface拓扑：必须重新判模式/endpoint。

历史代码示例：[efs_rekey.py](../work/uv310-wireguard/rekey-memory/efs_rekey.py)、[reboot.py](../work/uv310-wireguard/rekey-memory/reboot.py)。它们在import时也可能读取私有材料，应读源码，不要为查看帮助直接import执行。
