# 源码与证据索引

路径保留历史布局。所有 JSON 是产生时的观测/分析快照；`CURRENT_STATE.json` 和 `FRESH_START.md` 才是本次发布时的状态。以下只索引本仓库已包含的文件，JSON 文本中引用的未发布私有镜像/完整历史路径不承诺存在。

## 主要源码入口

| 路径 | 用途 | 直接可重放程度 |
|---|---|---|
| `tools/test_offline.py` | 临时目录运行选定QEMU suite | `make test` / `make test-live` |
| `work/uv310-wireguard/rekey-live/native.c` | 实机成功两次换钥的native adapter | 合成测试可重放；部署需要新私有材料 |
| `work/uv310-wireguard/rekey-memory/native.c` | 最新内存观测分支 | 合成测试可重放；本次实机中断 |
| `work/uv310-wireguard/rng-provider/wireguard.c` | checked RNG/有限index选择核心 | 被上述测试直接使用 |
| `work/uv310-wireguard/control-hardening/entry.S` | hook、寄存器/标志保存 | 被上述测试直接使用，实机ABI另见证据 |
| `work/uv310-wireguard/rekey-memory/package.py` | 历史私有image生成过程 | 审阅用，不能默认运行 |
| `work/uv310-wireguard/rekey-memory/efs_rekey.py` | identity/hash固定的EFS部署/恢复 | 需要精确私有stock/candidate，import也读文件 |
| `work/uv310-wireguard/rekey-memory/reboot.py` | 原厂文件恢复后有界软件重启 | 有USB/设备副作用，不是测试入口 |
| `work/uv310-wireguard/efs_probe_io.py` | framing、EFS I/O可逆验证 | 历史实验，只允许新建路径 |
| `outputs/new-dongle-hello/hello-ram.S` | ARMv5 reply-only applet | 离线构建可重放，loader不分发 |
| `work/uv310-wireguard/*/analyze.py` | 静态或样本分析 | 各自有私有输入/工具依赖，不统一声明可运行 |

## 导航标签

`summary`为该轮结论；`tests/offline/replay`是合成或静态验证；`live/followup/status`通常是实机采样；`efs/restore/cold`是部署/恢复记录。文件名不能替代内部scope标记。`cold`历史文件可能仅为software restart。

## 公开证据文件


### outputs/new-dongle-hello/evidence

- [download-parameters.json](../outputs/new-dongle-hello/evidence/download-parameters.json)
- [hello-ram-build.json](../outputs/new-dongle-hello/evidence/hello-ram-build.json)
- [hello-ram-live.json](../outputs/new-dongle-hello/evidence/hello-ram-live.json)
- [loader-offline-audit.json](../outputs/new-dongle-hello/evidence/loader-offline-audit.json)
- [project-name-at.json](../outputs/new-dongle-hello/evidence/project-name-at.json)

### outputs/uv310-wireguard/evidence

- [active-release-summary.json](../outputs/uv310-wireguard/evidence/active-release-summary.json) — One real independent DNS packet; not queue saturation, general pooled/clone/chain lifetime, or long-running leak test
- [active-send-summary.json](../outputs/uv310-wireguard/evidence/active-send-summary.json)
- [auto-wg-summary.json](../outputs/uv310-wireguard/evidence/auto-wg-summary.json)
- [autonomous-hooks-summary.json](../outputs/uv310-wireguard/evidence/autonomous-hooks-summary.json)
- [boot-probe-summary.json](../outputs/uv310-wireguard/evidence/boot-probe-summary.json)
- [bridge-control-summary.json](../outputs/uv310-wireguard/evidence/bridge-control-summary.json)
- [bridge-static.json](../outputs/uv310-wireguard/evidence/bridge-static.json) — Exact UV310 ALKU7.3.2 own-device extracted firmware; static analysis plus separate read-only precheck
- [buffer-rom-analysis.json](../outputs/uv310-wireguard/evidence/buffer-rom-analysis.json) — This analysis does not prove safe replacement/drop on every chain, clone, or pooled packet; probe does not release existing traffic packets.
- [buffer-summary.json](../outputs/uv310-wireguard/evidence/buffer-summary.json)
- [cadence-summary.json](../outputs/uv310-wireguard/evidence/cadence-summary.json)
- [combined-memory-summary.json](../outputs/uv310-wireguard/evidence/combined-memory-summary.json)
- [confirmed-cold-final-efs.json](../outputs/uv310-wireguard/evidence/confirmed-cold-final-efs.json)
- [confirmed-cold-summary.json](../outputs/uv310-wireguard/evidence/confirmed-cold-summary.json)
- [deferred-success-summary.json](../outputs/uv310-wireguard/evidence/deferred-success-summary.json)
- [download-path-analysis.json](../outputs/uv310-wireguard/evidence/download-path-analysis.json) — Offline bounded Hexagon disassembly of extracted DSP2; runtime control test separately recorded
- [dsp2-driver-abi.json](../outputs/uv310-wireguard/evidence/dsp2-driver-abi.json)
- [efs-probe-io.json](../outputs/uv310-wireguard/evidence/efs-probe-io.json) — Only two new allowlisted probe files; no active firmware replacement
- [emitter-wg-summary.json](../outputs/uv310-wireguard/evidence/emitter-wg-summary.json)
- [forward-wg-summary.json](../outputs/uv310-wireguard/evidence/forward-wg-summary.json) — One selected Wi-Fi client; short controlled session; LAN and multicast bypass; selected client IPv6 rejected
- [freshness-summary.json](../outputs/uv310-wireguard/evidence/freshness-summary.json)
- [jent-bounded-summary.json](../outputs/uv310-wireguard/evidence/jent-bounded-summary.json)
- [jent-compact-summary.json](../outputs/uv310-wireguard/evidence/jent-compact-summary.json)
- [jent-cooperative-summary.json](../outputs/uv310-wireguard/evidence/jent-cooperative-summary.json)
- [jent-live-summary.json](../outputs/uv310-wireguard/evidence/jent-live-summary.json)
- [jent-port-summary.json](../outputs/uv310-wireguard/evidence/jent-port-summary.json) — Offline Cortex-M3 full-core portability and resource/rejection assessment; read-only device precheck
- [jent-probe-integration-summary.json](../outputs/uv310-wireguard/evidence/jent-probe-integration-summary.json)
- [jent-streaming-summary.json](../outputs/uv310-wireguard/evidence/jent-streaming-summary.json)
- [jent-trace-analysis.json](../outputs/uv310-wireguard/evidence/jent-trace-analysis.json)
- [jent-trace-repeat-analysis.json](../outputs/uv310-wireguard/evidence/jent-trace-repeat-analysis.json)
- [jent-trace-repeat-incomplete-summary.json](../outputs/uv310-wireguard/evidence/jent-trace-repeat-incomplete-summary.json)
- [jent-trace-repeat-summary.json](../outputs/uv310-wireguard/evidence/jent-trace-repeat-summary.json)
- [jent-trace-summary.json](../outputs/uv310-wireguard/evidence/jent-trace-summary.json)
- [jent-window-budget-summary.json](../outputs/uv310-wireguard/evidence/jent-window-budget-summary.json)
- [jent-window-summary.json](../outputs/uv310-wireguard/evidence/jent-window-summary.json)
- [jitter-summary.json](../outputs/uv310-wireguard/evidence/jitter-summary.json)
- [late-probe-summary.json](../outputs/uv310-wireguard/evidence/late-probe-summary.json)
- [modem-entropy-static.json](../outputs/uv310-wireguard/evidence/modem-entropy-static.json) — Own UV310 ALKU7.3.2 extracted DSP2; static analysis only
- [modem-entropy-summary.json](../outputs/uv310-wireguard/evidence/modem-entropy-summary.json)
- [native-wg-summary.json](../outputs/uv310-wireguard/evidence/native-wg-summary.json)
- [path-summary.json](../outputs/uv310-wireguard/evidence/path-summary.json)
- [persistence-audit.json](../outputs/uv310-wireguard/evidence/persistence-audit.json) — Static analysis of exact stock Hexagon code; no runtime file/config writes
- [postcrc-summary.json](../outputs/uv310-wireguard/evidence/postcrc-summary.json)
- [query-reliability-stock.json](../outputs/uv310-wireguard/evidence/query-reliability-stock.json) — Read-only stock UV310 AT command pacing; no Wi-Fi client traffic generated
- [rekey-hardware-layout.json](../outputs/uv310-wireguard/evidence/rekey-hardware-layout.json) — Actual known firmware link addresses with synthetic config and stock cached tick path; no executable image packed or deployed
- [rekey-lifecycle-artifact-qa.json](../outputs/uv310-wireguard/evidence/rekey-lifecycle-artifact-qa.json)
- [rekey-lifecycle-host-restored.json](../outputs/uv310-wireguard/evidence/rekey-lifecycle-host-restored.json)
- [rekey-lifecycle-manual-management.json](../outputs/uv310-wireguard/evidence/rekey-lifecycle-manual-management.json)
- [rekey-lifecycle-static-management.json](../outputs/uv310-wireguard/evidence/rekey-lifecycle-static-management.json)
- [rekey-lifecycle-summary.json](../outputs/uv310-wireguard/evidence/rekey-lifecycle-summary.json)
- [rekey-lifecycle-tests.json](../outputs/uv310-wireguard/evidence/rekey-lifecycle-tests.json) — Synthetic Cortex-M3 integration, no real radio/clock/entropy/device deployment
- [rekey-lifecycle-wifi-recovery.json](../outputs/uv310-wireguard/evidence/rekey-lifecycle-wifi-recovery.json)
- [rekey-lifecycle-wifi-scan.json](../outputs/uv310-wireguard/evidence/rekey-lifecycle-wifi-scan.json)
- [rekey-live-artifact-qa.json](../outputs/uv310-wireguard/evidence/rekey-live-artifact-qa.json)
- [rekey-live-at-after-first.json](../outputs/uv310-wireguard/evidence/rekey-live-at-after-first.json)
- [rekey-live-build.json](../outputs/uv310-wireguard/evidence/rekey-live-build.json)
- [rekey-live-cold-candidate.json](../outputs/uv310-wireguard/evidence/rekey-live-cold-candidate.json)
- [rekey-live-cold-restored.json](../outputs/uv310-wireguard/evidence/rekey-live-cold-restored.json)
- [rekey-live-efs-activate.json](../outputs/uv310-wireguard/evidence/rekey-live-efs-activate.json)
- [rekey-live-efs-restore.json](../outputs/uv310-wireguard/evidence/rekey-live-efs-restore.json)
- [rekey-live-efs-stage.json](../outputs/uv310-wireguard/evidence/rekey-live-efs-stage.json)
- [rekey-live-expiry-followup.json](../outputs/uv310-wireguard/evidence/rekey-live-expiry-followup.json)
- [rekey-live-final-files.json](../outputs/uv310-wireguard/evidence/rekey-live-final-files.json)
- [rekey-live-final-status.json](../outputs/uv310-wireguard/evidence/rekey-live-final-status.json)
- [rekey-live-followup.json](../outputs/uv310-wireguard/evidence/rekey-live-followup.json)
- [rekey-live-host-restored.json](../outputs/uv310-wireguard/evidence/rekey-live-host-restored.json)
- [rekey-live-post-rekey-verified.json](../outputs/uv310-wireguard/evidence/rekey-live-post-rekey-verified.json)
- [rekey-live-post-rekey.json](../outputs/uv310-wireguard/evidence/rekey-live-post-rekey.json)
- [rekey-live-status.json](../outputs/uv310-wireguard/evidence/rekey-live-status.json)
- [rekey-live-summary.json](../outputs/uv310-wireguard/evidence/rekey-live-summary.json)
- [rekey-live-tests.json](../outputs/uv310-wireguard/evidence/rekey-live-tests.json) — Synthetic Cortex-M3 integration, no real radio/clock/entropy/device deployment
- [rekey-live-traffic-attempt1.json](../outputs/uv310-wireguard/evidence/rekey-live-traffic-attempt1.json)
- [rekey-live-traffic-attempt2.json](../outputs/uv310-wireguard/evidence/rekey-live-traffic-attempt2.json)
- [rekey-live-traffic.json](../outputs/uv310-wireguard/evidence/rekey-live-traffic.json)
- [rekey-memory-build.json](../outputs/uv310-wireguard/evidence/rekey-memory-build.json)
- [rekey-memory-cold-candidate.json](../outputs/uv310-wireguard/evidence/rekey-memory-cold-candidate.json)
- [rekey-memory-efs-activate.json](../outputs/uv310-wireguard/evidence/rekey-memory-efs-activate.json)
- [rekey-memory-efs-restore.json](../outputs/uv310-wireguard/evidence/rekey-memory-efs-restore.json)
- [rekey-memory-efs-stage.json](../outputs/uv310-wireguard/evidence/rekey-memory-efs-stage.json)
- [rekey-memory-followup.json](../outputs/uv310-wireguard/evidence/rekey-memory-followup.json)
- [rekey-memory-restore-attempt1.json](../outputs/uv310-wireguard/evidence/rekey-memory-restore-attempt1.json)
- [rekey-memory-restore-attempt2.json](../outputs/uv310-wireguard/evidence/rekey-memory-restore-attempt2.json)
- [rekey-memory-status.json](../outputs/uv310-wireguard/evidence/rekey-memory-status.json)
- [rekey-memory-summary.json](../outputs/uv310-wireguard/evidence/rekey-memory-summary.json)
- [rekey-memory-tests.json](../outputs/uv310-wireguard/evidence/rekey-memory-tests.json) — Synthetic Cortex-M3 integration, no real radio/clock/entropy/device deployment
- [resident-summary.json](../outputs/uv310-wireguard/evidence/resident-summary.json)
- [rng-failclosed-artifact-qa.json](../outputs/uv310-wireguard/evidence/rng-failclosed-artifact-qa.json)
- [rng-failclosed-summary.json](../outputs/uv310-wireguard/evidence/rng-failclosed-summary.json)
- [rng-failclosed-tests.json](../outputs/uv310-wireguard/evidence/rng-failclosed-tests.json) — Synthetic Cortex-M3 native-adapter/core tests, no device deployment
- [rng-provider-artifact-qa.json](../outputs/uv310-wireguard/evidence/rng-provider-artifact-qa.json)
- [rng-provider-summary.json](../outputs/uv310-wireguard/evidence/rng-provider-summary.json)
- [rng-provider-tests.json](../outputs/uv310-wireguard/evidence/rng-provider-tests.json) — Synthetic Cortex-M3 protocol/native-adapter tests; no device runtime claim
- [rng-sample-efs-isolation-first-run-summary.json](../outputs/uv310-wireguard/evidence/rng-sample-efs-isolation-first-run-summary.json) — one USB handle, all checks completed within 0.1s; does not rule out delayed side effects
- [rng-sample-summary.json](../outputs/uv310-wireguard/evidence/rng-sample-summary.json)
- [rng-transport-static.json](../outputs/uv310-wireguard/evidence/rng-transport-static.json) — Own UV310 ALKU7.3.2 exact extracted modem firmware; offline analysis only
- [rng-transport-summary.json](../outputs/uv310-wireguard/evidence/rng-transport-summary.json) — Offline modem RNG transport and secondary pool audit
- [rom-runtime-abi.json](../outputs/uv310-wireguard/evidence/rom-runtime-abi.json) — Real captured ROM first two instructions + exact stock RAM-image word; runtime slot values have not been captured
- [rom-summary.json](../outputs/uv310-wireguard/evidence/rom-summary.json)
- [runtime-bridge-random-helper-replay.json](../outputs/uv310-wireguard/evidence/runtime-bridge-random-helper-replay.json) — Actual ROM dispatch stub and function instructions; synthetic context/MMIO/output buffer in Unicorn
- [runtime-bridge-random-helper-static.json](../outputs/uv310-wireguard/evidence/runtime-bridge-random-helper-static.json) — Exact stock ROM/RAM static locations, linear decoding candidates plus emulated helper control flow
- [runtime-bridge-summary.json](../outputs/uv310-wireguard/evidence/runtime-bridge-summary.json)
- [timer-controls-summary.json](../outputs/uv310-wireguard/evidence/timer-controls-summary.json)
- [timer-rom-abi.json](../outputs/uv310-wireguard/evidence/timer-rom-abi.json) — Own BCM43362 rev1 firmware 5.90.153.52.1; offsets are not portable across firmware
- [timer-summary.json](../outputs/uv310-wireguard/evidence/timer-summary.json)
- [wifi-firmware-identification.json](../outputs/uv310-wireguard/evidence/wifi-firmware-identification.json)
- [wifi-self-crc-analysis.json](../outputs/uv310-wireguard/evidence/wifi-self-crc-analysis.json)
- [wifi-startup-analysis.json](../outputs/uv310-wireguard/evidence/wifi-startup-analysis.json) — Offline static Thumb-2 disassembly; base address 0 consistent with vector and branch/literal cross references

