# Native N1 telemetry candidate

This directory contains the explicit `native.c` for the N1 status candidate. It is byte-identical to the previously validated `exclusive-n-page` proposal. The opening comment is inherited from the DHCP-growth baseline to preserve that identity; this README identifies the distinct candidate.

Run from the repository root:

```sh
LLVM_CLANG=/path/to/clang LLVM_LD=/path/to/ld.lld \
QEMU_ARM=/path/to/qemu-system-arm make test-dns-observe
```

The target audits five layouts, checks this source against the documented transformation of the preserved `rekey-dns-grow` baseline, copies this committed source into an isolated synthetic build, runs 67 integration scenarios and 26 negative controls, then runs the host observer mock tests. The shared baseline harness, synthetic config, DHCP code and cryptographic dependencies are reused instead of duplicating them here. Reports distinguish original input hashes from temporary derived source hashes. The candidate guard intentionally fails if either source drifts unexpectedly; review the actual change before revising that guard.

Native status rotation is A/E/R/M/N. The host observer must explicitly use `--protocol n1` to require all five pages. See [protocol and limitations](../../../docs/DNS_TELEMETRY.md).

This is a source-level offline candidate, not a deployable image. No packaging or flashing entry point is added. Real configuration link, stock overlay, runtime heap/stack, DHCP hook visibility, Wi-Fi traffic and long-duration operation remain unverified. One-boot synthetic randomness and timestamp fixtures cannot provide standalone security or automatic reboot readiness.
