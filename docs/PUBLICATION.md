# 本次公开发布的数据处理

仓库为独立整理副本，没有把整个历史工作目录或其Git历史推送到远程。公开原生源码、合成测试、分析脚本、参数/地址/协议和经过检查的JSON证据；不包含原厂Wi-Fi/调制解调器/loader二进制、完整ROM、私有配置、keyed image/ELF、抓包、截图、SIM身份或短信。

已从本地私有配置/材料提取123种已知私有值表示做精确匹配（原值、base64、hex、十进制数组等），剩余命中0。检查范围含私钥/PSK/peer key、endpoint、random pool、trigger token及Wi-Fi凭据/标识。结构化identifier额外脱敏、个人工作区绝对路径替换为`${WORKSPACE}`或`${OWNER_HOME}`、原Wi-Fi名称替换为`ORIGINAL_WIFI`、MAC改为标记。长十进制/凭据形状也做了人工类别检查。不能把已知值扫描描述成“所有未知秘密的形式证明”。

保留RFC1918测试网段作为协议/流量路径例子，它们不是可供别人访问的VPN配置。合成`native-config.h`中的固定测试keys是公开fixture，**不能用于真实部署**。实际private header没有复制。

保留失败、原始errno、断连时刻、轮次hash与测试限制。部分JSON因脱敏/规范化格式与原文件字节不同；指标没有为美化结果而修改。源码native/crypto保持原字节；测试驱动的工具路径增加环境变量/PATH适配。具体对照见`SOURCE_PROVENANCE.json`。

`PUBLICATION_QA.json`记录此次公开副本离线测试、语法与上游blob核对；`MANIFEST.sha256`覆盖发布文件（不含自身、Git元数据和忽略的测试结果）。每次后续修改均应更新manifest/新QA并保留旧commit。

仓库不是固件release或长期运行验收。最新版状态只看`FRESH_START.md`与`CURRENT_STATE.json`，不能把早期证据中的current字段当成此刻实机状态。
