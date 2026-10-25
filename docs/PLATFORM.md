# 平台与执行环境

完整硬件框图、芯片标识、内存和NAND分区见 [HARDWARE.md](HARDWARE.md)。

## 硬件/软件定位

目标样机标识 ALEKA UV310-U-5.1 CGWL；AT 项目 MDM9600 UV310；正常固件版本线 MDM9K-ALKU-7.3.2 / ALK5.1，DIAG历史构建标记 2015-11-05 18:20:03；AT^SWVER另报18:21:02，应分别保留。DIAG model 0xfd2、hardware 20460000 用作辅助对照，不能代替完整 USB/项目/镜像验证。

| 部分 | 执行环境 | 已做的工作 |
|---|---|---|
| ARM控制与下载路径 | ARM926（观测 MIDR 0x41069265）；正常AMSS为ARM ELF，包含L4/REX/USB/ONCRPC线索 | 可控入口为RAM-only Hello World；尚无与正常网络并行的通用ARM程序入口 |
| 调制解调器正常运行固件 | Qualcomm MDM9600，Hexagon v3 / QDSP 代码 | AT、EFS、Web ASP 配置、Wi-Fi host driver 静态分析 |
| Wi-Fi 芯片 | BCM43362，Cortex-M3 Thumb-2；活动固件标记a2，live chiprev=1 | 正常运行 RAM 镜像补丁、数据包 hook、原生 WireGuard |
| Mac/QEMU | 主机分析工具、mps2-an385 Cortex-M3 fixture | 构建、协议/竞态测试，不模拟真实 BCM 外设 |

正常 USB 可访问 AT 和 DIAG/EFS；文件树和 ASP 页面不等于 Linux shell。没有据此建立 SSH、ADB、POSIX 用户进程或 Linux 内核模块入口。目标实现目前是嵌入 Wi-Fi 固件的 freestanding C。

## 镜像分工

活动 Wi-Fi RAM image 存在调制解调器 EFS 的 `/SyFi/brew/mod/rtecdc_new.bin`，正常启动时由驱动加载到 BCM。该路径上的文件是持久存储；加载后的代码在 BCM RAM 运行。因此实验可以先加载候选版本，再把存储文件恢复为 stock，同时保留本次 RAM 实验；下次启动应加载 stock，但仍需实测确认。

精确 stock：193315 字节，SHA-256 `4b86d71b92529034b2b46da7b93402f67c8aef98d2fc1efa91fc67ff7e5fb85a`，wl version `5.90.153.52.1`。实机 wl 返回 chipnum `0xa962`、chiprev 1。不要把相同市场名称的其他硬件版本当成匹配设备。

用于 QDSP 静态分析的切片：`dsp2-code.bin` SHA-256 `9bcdfd03028be95c1f6285c299e359d79be8e6e4e2f7e06191293b452dd17076`；`dsp2-rodata.bin` SHA-256 `588fd80ade91170e5a11431f8d21f78f72e62fd5b189f174863f9b21c018b98f`。这些文件不公开。现有 LLVM 对较新 Hexagon ISA 支持较好，对 v3 的解释必须交叉核对；packet 内并行指令读取旧寄存器值，不能按逐条顺序错误传播。

证据入口：[固件识别](../outputs/uv310-wireguard/evidence/wifi-firmware-identification.json)、[host driver ABI](../outputs/uv310-wireguard/evidence/dsp2-driver-abi.json)、[Hello World](../outputs/new-dongle-hello/evidence/hello-ram-live.json)。
