"""Read-only, exact-firmware DHCP/DNS audit. No USB or network operations.

Requires owner-provided raw DSP2 code and rodata; never writes either to output.
The temporary ELF contains the owner's code and is removed on exit.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

CODE_SHA = '9bcdfd03028be95c1f6285c299e359d79be8e6e4e2f7e06191293b452dd17076'
RO_SHA = '588fd80ade91170e5a11431f8d21f78f72e62fd5b189f174863f9b21c018b98f'
CODE_BASE = 0xc01000
RO_BASE = 0x183e000
STRINGS = {
    0x19c3794: '/etc/udhcpd.conf',
    0x19c3807: 'w+',
    0x19c382f: 'interface br0\n',
    0x19c3850: 'option router %s\n',
    0x19c3862: 'option subnet %s\n',
    0x19c3874: 'option lease  %d\n',
    0x19c3886: 'option dns %s\n',
    0x19c38d6: 'resolv-file=/etc/resolv.conf\n',
    0x19c2181: 'lanIp', 0x19c2188: 'lanNetmask',
    0x19c2193: 'lanDhcpType', 0x19c219f: 'SERVER',
    0x19c21a6: 'dhcpStart', 0x19c21b0: 'dhcpEnd',
    0x19c21b8: 'dhcpLease',
}
RANGES = {
    'writer': (0xf73e60, 0xf73fc8),
    'dns_proxy': (0xf73fe4, 0xf74088),
    'web_handler': (0x1833fc0, 0x1834444),
    'message_builder': (0x182e6cc, 0x182e720),
    'initialization': (0x13cf228, 0x13cf300),
}
# Anchors establish that the reviewed disassembly still matches this exact image.
# They are not an execution proof or an automatic control/data-flow verifier.
ANCHORS = [
    ('writer', 0xf73e78, 'r18.l = #0x3794'),
    ('writer', 0xf73e7c, 'r1.l = #0x3807'),
    ('writer', 0xf73e84, 'call 0xc364e8'),
    ('writer', 0xf73e94, 'r18 = add(r17,#0x8)'),
    ('writer', 0xf73f20, 'r1.l = #0x3850'),
    ('writer', 0xf73f64, 'r2 = add(r17,#0x48)'),
    ('writer', 0xf73f68, 'r0 = memub(r17+#0x48)'),
    ('writer', 0xf73f6c, 'if (r0==#0) jump:t 0xf73f84'),
    ('writer', 0xf73f78, 'r1.l = #0x3886'),
    ('writer', 0xf73f80, 'r0 = #0x1'),
    ('writer', 0xf73f84, 'r1 = memub(r17+#0x58)'),
    ('writer', 0xf73f98, 'if (r0!=#0) jump:t 0xf73fb0'),
    ('writer', 0xf73f9c, 'memw(r29+#0x0) = r18'),
    ('writer', 0xf73fa8, 'r1.l = #0x3886'),
    ('dns_proxy', 0xf74050, 'r1.l = #0x38d6'),
    ('web_handler', 0x1834074, 'r1.l = #0x2181'),
    ('web_handler', 0x1834090, 'r1.l = #0x2188'),
    ('web_handler', 0x18340ac, 'r1.l = #0x2193'),
    ('web_handler', 0x18340c8, 'r1.l = #0x21a6'),
    ('web_handler', 0x18340e4, 'r1.l = #0x21b0'),
    ('web_handler', 0x1834100, 'r1.l = #0x21b8'),
    ('web_handler', 0x18342d0, 'r25 = add(r29,#0x10)'),
    ('web_handler', 0x18342d4, 'r1 = #0x0'),
    ('web_handler', 0x18342d8, 'r2 = #0x68'),
    ('web_handler', 0x18342e4, 'call 0x12eef00'),
    ('web_handler', 0x1834338, 'r0 = add(r29,#0x38)'),
    ('web_handler', 0x183433c, 'r0 = add(r29,#0x48)'),
    ('web_handler', 0x1834360, 'r0 = add(r29,#0x10)'),
    ('web_handler', 0x1834364, 'call 0x182e6cc'),
    ('message_builder', 0x182e6f0, 'r3 = #0x50'),
    ('message_builder', 0x182e700, 'r2 = #0x68'),
    ('message_builder', 0x182e708, 'r0 = add(r0,#0x1f0)'),
    ('message_builder', 0x182e70c, 'memh(r16+#0x8) = r3'),
    ('message_builder', 0x182e714, 'call 0x182e450'),
    ('initialization', 0x13cf250, 'call 0xf73b38'),
    ('initialization', 0x13cf27c, 'r0 = memub(r16+#0x48)'),
    ('initialization', 0x13cf280, 'if (r0!=#0) jump:nt 0x13cf2fc'),
    ('initialization', 0x13cf2d4, 'r0 = add(r29,#0xdc)'),
    ('initialization', 0x13cf2d8, 'r1.l = #0x35dc'),
    ('initialization', 0x13cf2e8, 'call 0xf73e60'),
]

def digest(data):
    return hashlib.sha256(data).hexdigest()


def analysis_elf(code):
    names = b'\0.text\0.shstrtab\0'
    names_offset = 52 + len(code)
    sections_offset = (names_offset + len(names) + 3) & ~3
    ident = b'\x7fELF\x01\x01\x01' + bytes(9)
    header = struct.pack('<16sHHIIIIIHHHHHH', ident, 2, 164, 1,
                         CODE_BASE, 0, sections_offset, 2, 52, 0, 0, 40, 3, 2)
    result = header + code + names
    result += bytes(sections_offset - len(result)) + bytes(40)
    result += struct.pack('<10I', 1, 1, 6, CODE_BASE, 52, len(code), 0, 0, 4, 0)
    result += struct.pack('<10I', 7, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0)
    return result


def audit(code_path, ro_path, objdump):
    code, ro = code_path.read_bytes(), ro_path.read_bytes()
    if digest(code) != CODE_SHA or digest(ro) != RO_SHA:
        raise ValueError('Firmware hash mismatch; no disassembly or interpretation attempted')
    for address, expected in STRINGS.items():
        offset = address - RO_BASE
        if ro[offset:offset+len(expected)+1] != expected.encode() + b'\0':
            raise ValueError(f'String anchor mismatch at {address:#x}')
    with tempfile.TemporaryDirectory(prefix='uv310-dhcp-audit-') as temp:
        elf = Path(temp) / 'private-analysis.elf'
        elf.write_bytes(analysis_elf(code))
        os.chmod(elf, 0o600)
        for name, (start, end) in RANGES.items():
            result = subprocess.run([objdump, '-d', f'--start-address={start}',
                                     f'--stop-address={end}', str(elf)],
                                    text=True, capture_output=True, timeout=30)
            if result.returncode:
                raise ValueError('Disassembler failed; no raw output emitted')
            lines = {}
            for line in result.stdout.splitlines():
                match = re.match(r'\s*([0-9a-f]+):', line)
                if match:
                    lines[int(match[1], 16)] = line
            for group, address, text in ANCHORS:
                if group == name and text not in lines.get(address, ''):
                    raise ValueError(f'Instruction anchor mismatch at {address:#x}')
    return {
        'scope': 'Exact-stock static DHCP/DNS analysis; no device/network operations',
        'source_sha256': {'dsp2-code.bin': CODE_SHA, 'dsp2-rodata.bin': RO_SHA},
        'string_anchors_checked': len(STRINGS),
        'instruction_anchors_checked': len(ANCHORS),
        'ranges': {name: [hex(a), hex(b)] for name, (a, b) in RANGES.items()},
        'dhcp_writer': {
            'entry': '0xf73e60', 'file': '/etc/udhcpd.conf',
            'layout_inferred': {'size': 104, 'router': '0x08', 'subnet': '0x18',
                                'pool_start': '0x28', 'pool_end': '0x38',
                                'dns_primary': '0x48', 'dns_secondary': '0x58'},
            'dns_behavior': 'Emit nonempty DNS strings; both empty falls back to router',
            'live_writer_reachability_verified': False,
        },
        'web_dhcp_set': {
            'entry': '0x1833fc0',
            'fields': ['lanIp', 'lanNetmask', 'lanDhcpType', 'dhcpStart', 'dhcpEnd', 'dhcpLease'],
            'zeroed_payload_bytes': 104,
            'dns_fields_populated_in_reviewed_handler': False,
            'message_builder': '0x182e6cc', 'message_type': '0x50',
            'payload_offset': '0x1f0',
            'consumer_to_writer_chain_proven': False,
        },
        'initialization': {
            'entry': '0x13cf228', 'parser': '0xf73b38',
            'primary_dns_required_by_reviewed_existing_config_branch': True,
            'default_primary_dns': 'router address',
            'actual_boot_execution_verified': False,
        },
        'dns_proxy': {'writer': '0xf73fe4', 'upstream_file': '/etc/resolv.conf',
                      'dhcp_advertisement_equivalent_to_upstream_change': False},
        'next_action': 'Trace message 0x50 consumer before assuming an available config API; test DHCP ACK and tunneled DNS once hardware returns',
        'limitations': [
            'Instruction anchors validate reviewed input, not automatic data-flow correctness',
            'Hexagon packet operands read old values unless .new; no DSP execution test',
            'Compiled file and command strings do not establish a Linux userspace',
            'No public web DNS setter, persistence or running daemon behavior verified',
            'No DNS routing fix or live Wi-Fi VPN acceptance in this audit',
        ],
        'goal_complete': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--code', type=Path, required=True)
    parser.add_argument('--rodata', type=Path, required=True)
    parser.add_argument('--objdump', default=os.environ.get('LLVM_OBJDUMP') or shutil.which('llvm-objdump'))
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if not args.objdump:
        parser.error('Supply --objdump or LLVM_OBJDUMP with Hexagon support')
    if args.out.exists():
        parser.error('Output already exists; choose a new evidence file')
    report = audit(args.code, args.rodata, args.objdump)
    with args.out.open('x') as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False)
        stream.write('\n')
    print(f'Checked {len(STRINGS)} strings and {len(ANCHORS)} instruction anchors; static evidence only')


if __name__ == '__main__':
    main()
