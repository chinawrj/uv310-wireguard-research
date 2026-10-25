# Research handoff instructions

Read FRESH_START.md and CURRENT_STATE.json first. This is the UV310 project, not EC20 or Huawei E8372. Preserve evidence boundaries: synthetic QEMU, loader applet, and native Wi-Fi firmware execution are distinct.

Default to offline tests. Do not run archived package/deploy/reset scripts merely to inspect the repository. Verify full USB topology, project identity, exact stock hash, reversible backup and fresh one-boot material before any hardware write. Never reuse prior per-build RNG/TAI or a previously booted keyed image. Never treat missing USB as authorization to target a different device.

Do not commit private keys, PSKs, real peer configurations, generated keyed images, SIM identifiers, proprietary ROM/firmware dumps or credentials. Keep synthetic fixtures clearly labeled. Do not publish misleading pass results after a failure; add dated evidence and update CURRENT_STATE.json. Historical current_* fields are not current status.

Native Wi-Fi forwarding is the goal; no host-side VPN substitution. Do not claim standalone boot readiness until entropy, cross-boot freshness, memory, recovery, routing and long-duration tests pass. Use make test for the portable offline validation path. No subagents are requested by this file.
