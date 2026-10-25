"""Reproducible OFFLINE audit of this owner's exact UV310 firmware.

No USB, sockets, NV reads, seed extraction or image modification. Addresses
describe internal Hexagon task memory, never a host-side command protocol.
Run from the original workspace; private firmware inputs are not distributed.
"""
from pathlib import Path
import hashlib
import json
import re
import struct
import subprocess

P = Path('work/uv310-wireguard')
N = P / 'rng-transport'
D = P / 'private/nand'
E = Path('outputs/uv310-wireguard/evidence')
specs = {
    'dsp2-code.bin': (0xc01000, '9bcdfd03028be95c1f6285c299e359d79be8e6e4e2f7e06191293b452dd17076'),
    'dsp2-data.bin': (0x1a1e000, 'b31d062ece0b896b98c33d8359dfad23cb660e17605059afc239eab13f9919c3'),
    'dsp2-rodata.bin': (0x183e000, '588fd80ade91170e5a11431f8d21f78f72e62fd5b189f174863f9b21c018b98f'),
    'dsp2-small-data.bin': (0x3400000, '366ff74c956a4897f124072f967de5ab76f6ec728c6e85aeb7281a5c527a32f4'),
    'dsp2-paged-code.bin': (0xf0000000, 'a9880ae5b3476beca54136d98f2be87bcae2273867f0cfb317b308a339a74460'),
}
blobs = {}
for name, (base, sha) in specs.items():
    b = (D / name).read_bytes()
    assert hashlib.sha256(b).hexdigest() == sha, name
    blobs[name] = b

def read(va, length):
    for name, (base, _) in specs.items():
        b = blobs[name]
        if base <= va and va + length <= base + len(b):
            return b[va-base:va-base+length]
    raise ValueError(hex(va))

def words(va, count):
    return list(struct.unpack('<' + 'I' * count, read(va, count * 4)))

assert words(0x3428ed0, 2) == [0x47, 0x100]
assert words(0x341f6c0, 1) == [0x8d700008]
assert read(0x19a3e3d, len(b'Hardware RNG duplicated output!\n\0')) == b'Hardware RNG duplicated output!\n\0'
assert read(0x19a3e5e, 12) == b'nonblocking\0'
assert read(0x19a3e73, 6) == b'input\0'
nonblocking = words(0x1a8ce3c, 9)
input_pool = words(0x1a8ce60, 9)
assert nonblocking == [0x1a8cdfc, 0x243a5e0, 0x19a3e5e, 0, 0x1a8ce60, 0, 0, 0, 0]
assert input_pool == [0x1a8cde4, 0x243a660, 0x19a3e73, 1, 0, 0, 0, 0, 0]

ranges = [
    ('allocator-wrapper', 0xf03228b4, 0xf0322988),
    ('task-registration', 0xf0322a08, 0xf0322bc8),
    ('receive-wrapper', 0xf0322bc8, 0xf0322cc4),
    ('message-send-receive', 0xf749fc, 0xf74f40),
    ('task-map', 0x12c1c84, 0x12c1d2c),
    ('pool-core', 0x1462474, 0x146293c),
    ('stable-counter-read', 0x134b774, 0x134b794),
    ('counter-wait', 0x13443a4, 0x13445b0),
]
asm = {}
for name, start, end in ranges:
    elf = D / ('dsp2-paged-analysis.elf' if start >= 0xf0000000 else 'dsp2-code-analysis.elf')
    t = subprocess.check_output([
        '/opt/homebrew/opt/llvm/bin/llvm-objdump', '-d',
        '--start-address=' + hex(start), '--stop-address=' + hex(end), str(elf),
    ], text=True)
    asm[name] = t
    (N / (name + '.asm')).write_text(t)
checks = [
    ('allocator-wrapper', 'call 0xf0322918'),
    ('allocator-wrapper', 'r28.l = #0x4d68'),
    ('task-registration', 'call 0xf0322b0c'),
    ('task-registration', 'call 0xf0322b28'),
    ('task-registration', 'r28.l = #0x1ca8'),
    ('receive-wrapper', 'r28.l = #0x4b40'),
    ('message-send-receive', 'call 0x12c1c84'),
    ('message-send-receive', 'call 0xf74a34'),
    ('message-send-receive', 'memw(r16+#0x0) = r19'),
    ('message-send-receive', 'memw(r18+#0x8) = r20'),
    ('message-send-receive', 'memw(r18+#0xc) = r17'),
    ('message-send-receive', 'memw(r18+#0x4) = r19'),
    ('message-send-receive', 'call 0xf750a0'),
    ('message-send-receive', 'call 0xf74df4'),
    ('task-map', 'r1.l = #0xc9e8'),
    ('pool-core', 'call 0x1713540'),
    ('pool-core', 'call 0x1713568'),
    ('pool-core', 'call 0x14628a0'),
    ('pool-core', 'call 0x1462644'),
    ('pool-core', 'jump 0x14627d8'),
    ('stable-counter-read', 'memw(gp+#0x1f6c0)'),
    ('stable-counter-read', 'jump 0x134b780'),
    ('counter-wait', 'memw(gp+#0x1f6c0)'),
]
for name, needle in checks:
    assert needle in asm[name], (name, needle)

# Scan complete extracted code listings, including only explicit branches and
# short r28.h/r28.l tail-call trampolines. This is NOT a full indirect-call graph.
targets = {0x1462474, 0x14625b0, 0x1462920, 0xf74d68, 0xf74c38, 0xf0322b7c}
refs = []
for path in [D / 'dsp2-code.asm', P / 'bridge-audit/paged.asm']:
    pending = None
    for line in path.open():
        m = re.match(r'\s*([0-9a-f]+):.*?\b(call|jump) (0x[0-9a-f]+)', line)
        if m and int(m[3], 16) in targets:
            refs.append({'site': hex(int(m[1], 16)), 'target': m[3], 'kind': 'direct'})
        m = re.match(r'\s*([0-9a-f]+):.*?r28\.h = #(0x[0-9a-f]+)', line)
        if m:
            pending = (int(m[1], 16), int(m[2], 16))
        m = re.match(r'\s*([0-9a-f]+):.*?r28\.l = #(0x[0-9a-f]+)', line)
        if m and pending:
            addr = int(m[1], 16)
            target = pending[1] << 16 | int(m[2], 16)
            if addr - pending[0] == 4 and target in targets:
                refs.append({'site': hex(pending[0]), 'target': hex(target), 'kind': 'r28 halfword trampoline candidate'})
            pending = None

source = N / 'linux-v2.6.32-random.c'
source_text = source.read_text()
assert 'Hardware RNG duplicated output!' in source_text
assert 'extract_entropy(&nonblocking_pool, buf, nbytes, 0, 0);' in source_text
assert 'Redistribution and use in source and binary forms' in source_text
result = {
    'scope': 'Own UV310 ALKU7.3.2 exact extracted modem firmware; offline analysis only',
    'firmware_sha256': {name: sha for name, (_, sha) in specs.items()},
    'static_instruction_assertions': len(checks),
    'static_data_assertions': 7,
    'device_access_this_round': False, 'device_writes_this_round': False,
    'seed_values_read': False, 'secure_entropy_established': False,
    'task_registration': {
        'entry': '0xf0322a08', 'secrnd_id': '0x47', 'secrnd_signal': '0x100',
        'arguments_from': 'GP+0x28ed0 (0x3428ed0)',
        'signal_setter': '0xf749fc writes current task metadata+8',
        'id_registration': '0x12c1ca8 records task pointer in 0x242c9e8[id]',
        'lookup': '0x12c1c84 accepts id<=0x3ff, returns task pointer or zero',
        'live_registration_readback': False,
    },
    'message_contract_inferred': {
        'allocate': '0xf74d68(size,type) -> payload pointer P, or null; uses allocator0xf74df4',
        'prefix': {'P-24': 'allocator pool metadata', 'P-20': 'queue header start H',
                   'H+4': 'current task owner id', 'H+8': 'sender/reply destination',
                   'H+12': 'destination id'},
        'random_payload': {'P+0': 'request0x470001, reply0x470002', 'P+4': 'reply status',
                           'P+8': 'modem-address-space output buffer pointer', 'P+12': 'uint16 length'},
        'send': '0xf74c38(&P,destination): validates ownership and destination; success queues H, zeros P, returns0; ordinary failure returns1 without taking P',
        'receive': '0xf74b40: blocking per-task queue receive; returns H+20 and transfers owner to receiving task',
        'reply_destination': '0xf74af0(P): returns H+8 only for current owner; otherwise0',
        'free': '0xf74ce4(&P): current-owner check, frees via0xf750a0, zeros P',
        'caveat': 'Pool-invalid inputs enter a logging/assert path; do not assume graceful recovery. External pointed-to output-buffer lifetime must cover the asynchronous reply.',
        'transport_to_wifi': 'Not identified; modem pointers are not Cortex-M3 pointers and these are not USB opcodes',
    },
    'secondary_random_pool': {
        'entry_candidate': '0x1462920',
        'inferred_correspondence': {'0x1462474': 'mix_pool_bytes', '0x14625b0': 'credit_entropy_bits',
                                   '0x1462644': 'account', '0x14626f8': 'extract_buf',
                                   '0x14627d8': 'extract_entropy', '0x14628a0': 'xfer_secondary_pool'},
        'basis': 'pool structures, SHA1 extraction/folding/10-byte output, transfer/accounting flow, continuous-output check and wrapper arguments',
        'nonblocking_pool_words': [hex(x) for x in nonblocking],
        'input_pool_words': [hex(x) for x in input_pool],
        'initial_file_entropy_count': 0,
        'hardware_rng_string_meaning': 'continuous output comparison inside extraction, not a demonstrated hardware entropy input',
        'external_input_source_verified': False,
        'call_scan_limit': 'Only explicit calls/jumps and adjacent r28 halfword loads; indirect calls, inline writes, runtime and startup initialization are unresolved',
        'usable_for_wireguard': False,
        'linux_os_proof': False,
    },
    'mmio_0x8d700008': {
        'stable_read': '0x134b774 reads until consecutive 32-bit values agree',
        'wait_on_change': '0x13443a4 contains stable reads and waits for change',
        'inference': 'Consistent with a timing/counter source; exact peripheral identity and frequency unresolved',
        'trng_evidence': False,
    },
    'branch_and_trampoline_references': refs,
    'public_source_comparison': {
        'url': 'https://github.com/torvalds/linux/blob/v2.6.32/drivers/char/random.c',
        'sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
        'license_notice_preserved': True,
        'role': 'Structural comparison, not proof of exact origin, target OS, or secure live seeding',
    },
    'limitations': ['LLVM output is not an execution-validated Hexagon v3 runtime',
                    'Static ownership interpretation is not live message-send acceptance',
                    'No source/seed quality or independence across boots established',
                    'No new handshake, rekey, reboot or performance measurement'],
    'next_required_work': [
        'Find a verified same-modem task caller / host-DHD callback route with correct buffer ownership; never send internal pointer messages through USB',
        'Trace external input, readiness and reseed/error behavior for secrnd; do not use the secondary pool until live secure seeding is established',
        'If no modem bridge is available, reduce full validated M3 entropy-collector memory without weakening health checks and measure it on-device',
        'Integrate fresh entropy and timestamp/persistent-state handling for reusable boot, rekey and reconnect',
        'Deploy separately hardened control code with fresh material, then validate full Wi-Fi routing, DNS/MTU, long-term operation and UDP performance',
    ],
    'goal_complete': False,
}
(E / 'rng-transport-static.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'instruction_assertions': len(checks), 'data_assertions': 7,
                  'references': len(refs), 'secure_entropy_established': False}))
