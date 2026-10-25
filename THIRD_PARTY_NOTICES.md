# Third-party source and provenance

The WireGuard C implementation is derived from [smartalock/wireguard-lwip](https://github.com/smartalock/wireguard-lwip). Its source copyright notices and BSD-3-Clause-style license are retained at `work/uv310-wireguard/wg-port/upstream/LICENSE`. The X25519 implementation retains its MIT license at `work/uv310-wireguard/wg-port/upstream/src/crypto/refc/x25519-license.txt`. Individual crypto sources retain their notices. The adapted copies in `rng-provider` and `wg-port/build` remain subject to those upstream terms.

`work/uv310-wireguard/wg-port/upstream-manifest.json` records Git blob SHA provenance from the original download. It is a historical acquisition manifest and lists some files not included in this curated repository; it is not the repository manifest. `MANIFEST.sha256` describes this publication.

Protocol references used by the local analysis/scripts: [QCSuper](https://github.com/P1sec/QCSuper) for Qualcomm DIAG/EFS framing and layouts; [qtools](https://github.com/forth32/qtools) as historical loader ABI research; [Nexmon](https://github.com/seemoo-lab/nexmon) as Wi-Fi firmware patching background. These references do not imply their authors validated or endorse this UV310 experiment. No proprietary loader, stock Wi-Fi image, modem image or full ROM dump is included.

There is deliberately no blanket repository license that overrides third-party terms. Original research notes and original scripts are published by the owner's explicit instruction; no additional license grant for them is inferred here. Add a chosen license in a later commit if desired, preserving upstream terms.
