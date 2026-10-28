#!/usr/bin/env python3
"""Read-only, hash-pinned AMSS runtime audit; writes derived metadata only.

Requires Python 3 and capstone. Never communicates with a device or extracts code.
Addresses are virtual unless explicitly marked physical. Symbol labels are ours.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

EXPECTED_SHA256 = '388dda0d44c9ed391306c8dbd5851a612b0e68c3dc7faec189234dd7a525c9f5'
# Independent call/branch/queue guards. Decoding stops at each instruction;
# linear decoding through embedded data would produce spurious instructions.
ANCHORS = [
    (0x100000, 'physical', 'arm', 'b', '#0x100030'),
    (0x100078, 'physical', 'arm', 'msr', 'cpsr_fc, #0xd3'),
    (0x1000b8, 'physical', 'arm', 'bl', '#0x11a8d4'),
    (0xf001a8d4, 'virtual', 'arm', 'bl', '#0xf001a1c0'),
    (0x1c4004, 'virtual', 'arm', 'blx', '#0x25a342'),
    (0x1c4014, 'virtual', 'arm', 'blx', '#0x1c6130'),
    (0x1c6178, 'virtual', 'thumb', 'bl', '#0x28af36'),
    (0x1c617c, 'virtual', 'thumb', 'bl', '#0x1c7b0c'),
    (0x28af4e, 'virtual', 'thumb', 'bl', '#0x229f7c'),
    (0x229fd0, 'virtual', 'thumb', 'bl', '#0x28ae86'),
    (0x28aea4, 'virtual', 'thumb', 'bl', '#0x229dda'),
    (0x229dfe, 'virtual', 'thumb', 'bl', '#0x229cb0'),
    (0x229d06, 'virtual', 'thumb', 'bl', '#0x229b88'),
    (0x229c90, 'virtual', 'thumb', 'bl', '#0x2290ec'),
    (0x22910a, 'virtual', 'thumb', 'bl', '#0x28b876'),
    (0x2291ac, 'virtual', 'thumb', 'bl', '#0x28b8ca'),
    (0x2290e0, 'virtual', 'thumb', 'blx', 'r4'),
    (0x28b036, 'virtual', 'thumb', 'bl', '#0x229732'),
    (0x28b040, 'virtual', 'thumb', 'bl', '#0x229668'),
    (0x28b044, 'virtual', 'thumb', 'bl', '#0x229ff6'),
    (0x28b04a, 'virtual', 'thumb', 'beq', '#0x28b044'),
    (0x28b04c, 'virtual', 'thumb', 'b', '#0x28b034'),
    (0x22a048, 'virtual', 'thumb', 'cmp', 'r4, #0'),
    (0x22a04c, 'virtual', 'thumb', 'movs', 'r0, #0'),
    (0x22a050, 'virtual', 'thumb', 'bl', '#0x2be100'),
    (0x22a068, 'virtual', 'thumb', 'lsrs', 'r0, r0, #0x18'),
    (0x22a06a, 'virtual', 'thumb', 'cmp', 'r0, r2'),
    (0x22a06c, 'virtual', 'thumb', 'beq', '#0x22a084'),
    (0x22a072, 'virtual', 'thumb', 'str', 'r4, [r2, r1]'),
    (0x22a076, 'virtual', 'thumb', 'str', 'r7, [r1, #4]'),
    (0x22a078, 'virtual', 'thumb', 'str', 'r0, [r3, #4]'),
    (0x22a07e, 'virtual', 'thumb', 'bl', '#0x2296a0'),
    (0x22a082, 'virtual', 'thumb', 'movs', 'r5, #1'),
    (0x22a08e, 'virtual', 'thumb', 'bl', '#0x2be11c'),
    (0x22a092, 'virtual', 'thumb', 'movs', 'r0, r5'),
    (0x22a01e, 'virtual', 'thumb', 'str', 'r2, [r3]'),
    (0x22a030, 'virtual', 'thumb', 'bl', '#0x2be11c'),
    (0x22a038, 'virtual', 'thumb', 'movs', 'r0, r5'),
    (0x22a03a, 'virtual', 'thumb', 'blx', 'r4'),
    (0x2297ce, 'virtual', 'thumb', 'bl', '#0x2be11c'),
    (0x2297d4, 'virtual', 'thumb', 'blx', '#0x2e2a6c'),
    (0x2be104, 'virtual', 'thumb', 'blx', '#0x2b0de8'),
    (0x2b0e18, 'virtual', 'arm', 'swpb', 'r0, r2, [r1]'),
    (0x217c6c, 'virtual', 'thumb', 'bl', '#0x22a040'),
    (0x26f7c8, 'virtual', 'thumb', 'bl', '#0x22a040'),
    (0x2c2db6, 'virtual', 'thumb', 'bl', '#0x22a040'),
]
LITERALS = {
    0x22a120: 0x28b033, 0x22a124: 0x30a200, 0x22a128: 0x309fc8,
    0x22a13c: 0x2eeb18, 0x22a140: 0x3097c8,
    0x229208: 0x2290bb, 0x229210: 0x21d700,
    0x229e48: 0x2001a2a8, 0x229e5c: 0x2001a2d8,
}
STRINGS = {0x22a114: 'DPC Task', 0x22a12c: 'Main Task', 0x2b5798: 'rexl4.c'}

def audit(path, anchors=ANCHORS):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError('Firmware SHA256 mismatch; fixed addresses must not be reused')
    if data[:6] != b'\x7fELF\x01\x01':
        raise ValueError('Expected ELF32 little-endian')
    hdr = struct.unpack_from('<HHIIIIIHHHHHH', data, 16)
    machine, entry, phoff, phsize, phnum = hdr[1], hdr[3], hdr[4], hdr[8], hdr[9]
    if machine != 40 or phsize != 32:
        raise ValueError('Expected ARM ELF32 program headers')
    segs = []
    for index in range(phnum):
        fields = struct.unpack_from('<IIIIIIII', data, phoff + index * phsize)
        s = dict(zip(('type', 'offset', 'va', 'pa', 'filesz', 'memsz', 'flags', 'align'), fields))
        if s['type'] == 1:
            s['index'] = index
            segs.append(s)
    def locate(address, space='virtual'):
        k = 'va' if space == 'virtual' else 'pa'
        matches = [s for s in segs if s[k] <= address < s[k] + s['filesz']]
        if len(matches) != 1:
            raise ValueError(f'Address {address:#x} has {len(matches)} file-backed mappings')
        s = matches[0]
        return s['offset'] + address - s[k], s
    checks = []
    for address, space, mode, mnemonic, operands in anchors:
        off, seg = locate(address, space)
        decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM if mode == 'arm' else CS_MODE_THUMB)
        insn = next(decoder.disasm(data[off:off+4], address, count=1))
        if (insn.mnemonic, insn.op_str) != (mnemonic, operands):
            raise ValueError(f'Instruction guard failed at {address:#x}: {insn.mnemonic} {insn.op_str}')
        checks.append(dict(address=hex(address), address_space=space, mode=mode,
                           file_offset=hex(off), segment=seg['index'], size=insn.size,
                           instruction=f'{mnemonic} {operands}',
                           sha256=hashlib.sha256(data[off:off+insn.size]).hexdigest()))
    literals = []
    for address, expected in LITERALS.items():
        off, _ = locate(address)
        actual = struct.unpack_from('<I', data, off)[0]
        if actual != expected:
            raise ValueError(f'Literal guard failed at {address:#x}')
        literals.append(dict(address=hex(address), value=hex(actual)))
    strings = []
    for address, expected in STRINGS.items():
        off, _ = locate(address)
        if data[off:off+len(expected)+1] != expected.encode() + b'\0':
            raise ValueError(f'String guard failed at {address:#x}')
        strings.append(dict(address=hex(address), value=expected))
    return dict(schema_version=1, subject='UV310 ARM926 AMSS normal runtime static audit',
                source_sha256=digest, source_size=len(data), elf_entry=hex(entry),
                scope='Hash-pinned offline observations; no hardware execution or full-image CFG proof',
                instruction_guards=checks, literal_guards=literals, string_guards=strings,
                derived_dpc=dict(enqueue_thumb_entry='0x22a040', dequeue_thumb_entry='0x229ff6',
                                 worker_thumb_entry='0x28b032', call_pointer_thumb_bit_required=True,
                                 ring='0x3097c8', read_index='0x2eeb18', write_index='0x2eeb1c',
                                 slot_bytes=8, index_bits=8, usable_slots=255,
                                 callback_argument_register='r0', enqueue_success=1, enqueue_rejected=0,
                                 observed_stack_allocation_bytes=1024,
                                 normal_runtime_exercised=False, loader_available=False),
                limits=['No full partition dump', 'No complete ARM/Thumb code/data classification',
                        'ELF memsz minus filesz is not classified as BSS',
                        'Function labels and ABI remain inferred, not exported SDK symbols',
                        'Callback execution permission, runtime mapping and cache coherency unverified'])

def self_test(path):
    """Negative controls test the audit guards, never runtime behavior."""
    import tempfile
    positive = audit(path)
    controls = []
    def reject(name, candidate, anchors=ANCHORS):
        try:
            audit(candidate, anchors)
        except (ValueError, StopIteration) as error:
            controls.append(dict(name=name, rejected=True, reason=str(error)))
        else:
            raise AssertionError(f'Negative control unexpectedly accepted: {name}')
    with tempfile.TemporaryDirectory(prefix='arm926-runtime-audit-') as tmp:
        altered = Path(tmp) / 'altered.elf'
        data = bytearray(path.read_bytes())
        data[0x8000] ^= 1
        altered.write_bytes(data)
        reject('single_byte_corruption_sha256_guard', altered)
        altered.write_bytes(path.read_bytes()[:-1])
        reject('truncation_sha256_guard', altered)
    wrong_mode = list(ANCHORS)
    address, space, _, mnemonic, operands = wrong_mode[0]
    wrong_mode[0] = (address, space, 'thumb', mnemonic, operands)
    reject('entry_wrong_instruction_mode', path, wrong_mode)
    wrong_space = list(ANCHORS)
    address, _, mode, mnemonic, operands = wrong_space[0]
    wrong_space[0] = (address, 'virtual', mode, mnemonic, operands)
    reject('entry_wrong_address_space', path, wrong_space)
    return dict(schema_version=1, source_sha256=EXPECTED_SHA256,
                positive_instruction_guards=len(positive['instruction_guards']),
                negative_controls=controls,
                hardware_tests=0, functional_simulations=0,
                conclusion='Audit guards exercised; no callback, task, or firmware execution tested')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--self-test', action='store_true', help='Test offline evidence guards with negative controls')
    args = parser.parse_args()
    result = self_test(args.image) if args.self_test else audit(args.image)
    encoded = json.dumps(result, indent=2, ensure_ascii=False) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded)
    else:
        print(encoded, end='')

if __name__ == '__main__':
    main()
