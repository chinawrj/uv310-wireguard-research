# 离线构建与可复现性

## 支持的入口

Python3、pyelftools、LLVM clang（arm-none-eabi目标）/ld.lld、qemu-system-arm。`requirements-test.txt`只列离线测试依赖；`requirements-hardware.txt`另列PyUSB等，默认测试不需要USB权限。

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-test.txt
make test
```

若macOS默认clang/链接器不是所需版本，可明确路径：

```sh
LLVM_CLANG=/opt/homebrew/opt/llvm/bin/clang \
LLVM_LD=/opt/homebrew/opt/llvm/bin/ld.lld \
QEMU_ARM=/opt/homebrew/bin/qemu-system-arm make test
```

Linux可把变量设为已安装工具的绝对路径，或让PATH解析。发布时只在当前Mac环境实际重放，其他系统的可移植性仍需验证。测试驱动从仓库复制工作树到临时目录，不覆盖提交内历史证据，结束后只写`.test-results/`（git忽略）。无需网络、USB、真实配置或stock固件。

memory分支25个场景：BASELINE、REKEY、BAD_MAC、BAD_AEAD、STALE_RESPONSE、RNG_FAIL、QUEUE_EXPIRE、RETRY、RETRY_LIMIT、ALLOC_EXPIRE、COUNT_REKEY、COUNT_REJECT、WRAP、TAI_CARRY、CLAIM_RACE、PUBLISH_EXPIRY、LAB_PACKET、LAB_TIMER、LAB_WORKER、LAB_WRAP、MEMORY、MEMORY_BAD_NODE、MEMORY_CYCLE、MEMORY_SIZE、MEMORY_BAD_STACK。3个负向变异检查：reset_device、lost_response、reject_previous，必须被测试捕获。

`make test-live`重放前一实机成功分支的20项合成suite，仍不接触硬件。QEMU机器为mps2-an385，仅执行Cortex-M3代码与fixture；不会模拟Wi-Fi、SDIO、真实ROM/IRQ/熵源。QEMU通过不是稳定性、带宽或真实硬件执行证据。

## 源码与生成物

保留原`work/uv310-wireguard`相对布局，便于与日志对照。`wg-port/build/wireguard.c/.h`虽在build目录，却是必要的源适配文件，已明确纳入Git；其余`.o/.elf/.bin`构建产物忽略。native/test/config源码保持原样；两个test-build脚本仅增加环境变量/PATH工具发现。

`prepare.py`是历史增量生成器，依赖上一阶段文本补丁；不应作为默认构建入口。`package.py`是历史实机打包记录，会读取私有stock/config并生成新材料、脚本和镜像；不是公开发布安装命令。脚本包含原始Mac工具路径及实验文件名，移植时先审阅依赖、生成覆盖范围和恢复流程。某些静态分析器需要未公开的ROM/固件和反汇编工具；公开的JSON是当时分析结果，不声称这些分析器在无私有输入时能运行。

`make verify`校验发布manifest、JSON语法和Markdown本地文件链接；不等于秘密扫描。发布方另外做私有已知密钥多表示扫描，见PUBLICATION.md。

## Hello World重建

`outputs/new-dongle-hello/tools/build_hello.py`可离线生成68B ARM applet，检查无relocation、固定hash `5f03e8cc08877b82919123b3a94126967a9c415f43b8cab9a270fae7d8d14b58`。此结果只证明重建一致；loader缺省不分发，不能仅clone本仓库就重放历史EXEC实机实验。
