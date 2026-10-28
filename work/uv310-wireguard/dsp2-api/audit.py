#!/usr/bin/env python3
"""Bounded, read-only analysis of the owner's pinned DSP2 firmware.

Does not load firmware onto a device, make network requests, or export firmware.
Instruction anchors verify the evidence inventory, not the inferred ABI at runtime.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
from elftools.elf.elffile import ELFFile

SOURCES = {
    'dsp2-code.bin': (0xc01000, '9bcdfd03028be95c1f6285c299e359d79be8e6e4e2f7e06191293b452dd17076'),
    'dsp2-rodata.bin': (0x183e000, '588fd80ade91170e5a11431f8d21f78f72e62fd5b189f174863f9b21c018b98f'),
    'dsp2-small-data.bin': (0x3400000, '366ff74c956a4897f124072f967de5ab76f6ec728c6e85aeb7281a5c527a32f4'),
}
RANGES = {
    'tx': (0xcf49f0, 0xcf4b1c),
    'rx': (0xcf4b38, 0xcf4c98),
    'copy': (0x141593c, 0x1415b14),
    'bdc': (0xcfef88, 0xcfeff4),
    'bus': (0xcfd50c, 0xcfd6a4),
    'tx_queue': (0xd01754, 0xd0181c),
    'ipnet': (0xf74344, 0xf74574),
    'ring': (0xf777d4, 0xf77838),
    'drain': (0xf77994, 0xf77a7c),
    'setup': (0xf77a7c, 0xf77c58),
    'deliver': (0xf77fc4, 0xf78054),
    'append': (0x1714844, 0x17148c4),
    'release': (0x1714bb4, 0x1714be8),
    'config_list': (0xcf5754, 0xcf5788),
    'ioctl': (0xcf5788, 0xcf58d8),
    'wl': (0x17f4610, 0x17f469c),
    'task': (0xcf616c, 0xcf61d8),
    'loader': (0xcf84e4, 0xcf8940),
    'load_state': (0xcf7edc, 0xcf84ac),
    'membytes': (0xcf6610, 0xcf67ac),
    'init_load': (0xcf5c84, 0xcf5d70),
    'enable': (0xcf5e18, 0xcf5ea0),
    'chiprev': (0x171c378, 0x171c3b0),
    'sdio_membytes': (0xc569c4, 0xc56a14),
}
# Each mnemonic must occur at this address in a verified ELF .text image.
ANCHORS = {
    0xcf4a30: 'r16 = memw(gp+#0x8170)',
    0xcf4a64: 'call 0x14159c8', 0xcf4a68: 'r0 = memw(r16+#0x0)',
    0xcf4a5c: 'r0 = #0x4', 0xcf4b14: 'r0 = #-0x1',
    0xcf4ac0: 'call 0xcfef88', 0xcf4ac4: 'r1 = #0x0',
    0xcf4ae8: 'call 0xcfd50c', 0xcf4aec: 'r0 = memw(r16+#0x4)',
    0xf7435c: 'call 0xcf49f0', 0xf74360: 'r1 = memw(r16+#0x98)',
    0xf74364: 'r2 = memw(r16+#0x4c)',
    0xf7436c: 'call 0x1714bb4', 0xf74370: 'r0 = #0x0',
    0x1714bbc: 'r2 = memw(r0+#0xa0)', 0x1714bcc: 'r3 = memw_locked(r1)',
    0x1714be0: 'jump 0x1714b18',
    0x14159e0: 'call 0x1415988', 0x1415994: 'r1 = #0x2200',
    0x14159fc: 'r2 = memw(r18+#0x10)', 0x1415a18: 'call 0x1415afc',
    0x1415afc: 'r0 = r2', 0x1415b00: 'r2 = r3', 0x1415b08: 'call 0x12ee8a0',
    0xcfefb8: 'r3 = #0x20', 0xcfefc8: 'r0 = add(r1,#-0x4)',
    0xcfefe0: 'memb(r0+#0x2) = r16', 0xcfefe4: 'r1 = and(r1,#0x7)',
    0xcfefe8: 'memb(r0+#0x3) = r2',
    0xcfd544: 'r1 = add(r1,#-0xc)', 0xcfd5c0: 'call 0xd01754',
    0xcfd5cc: 'if (r0!=#0) jump:t 0xcfd62c',
    0xcfd5d4: 'r20 = #-0x16', 0xcfd624: 'call 0x141593c',
    0xcfd69c: 'r0 = r20', 0xd017f4: 'call 0x141593c',
    0xd01808: 'call 0xc57da0', 0xd0180c: 'r0 = #0x1',
    0xd01814: 'r0 = #0x0',
    0xcf4b90: 'r18 = memw(r0+#0x10)', 0xcf4b94: 'r2 = memw(r0+#0x18)',
    0xcf4c58: 'r1:0 = combine(r2,r18)', 0xcf4c68: 'call 0xf74428',
    0xcf4c90: 'call 0x141593c',
    0xf74438: 'r1.h = #0x19c', 0xf7443c: 'r18 = memw(gp+#0xab84)',
    0xf7445c: 'r19 = add(r18,#0x2c0)', 0xf7455c: 'call 0xf777e4',
    0xf7449c: 'call 0x1714844', 0xf744a8: 'call 0x12ee8a0',
    0xf744ac: 'r2 = #0xc', 0xf744cc: 'p0 = cmp.gt(r17,r0)',
    0xf744f8: 'r17 = sub(r17,r0)', 0xf74508: 'call 0x12ee8a0',
    0xf74514: 'call 0xf777d4', 0xf74530: 'call 0x13cf048',
    0xf7452c: 'r0 = #0x400',
    0xf777d4: 'r1 = memw(r0+#0x30)', 0xf777e0: 'memw(r0+#0x30) = r1',
    0xf777e8: 'r2 = memw(r0+#0x34)', 0xf77828: 'r1 = and(r1,#0xff)',
    0xf77830: 'r0 = memw(r0+#0x38)',
    0xf779c0: 'call 0x1715e50', 0xf779c4: 'r16 = memw(r1+#0x38)',
    0xf77a14: 'memw(r0+#0x38) = r18', 0xf77a20: 'memw(r17+#0x34) = r0',
    0xf77a50: 'memw(r16+#0x30) = r2', 0xf77a5c: 'memw(r17++#0x4) = r0',
    0xf77b20: 'r1.l = #0x4344', 0xf77b24: 'r1 = #0x1',
    0xf77b2c: 'memw(r18+#0x468) = r1',
    0xf77bb4: 'memw(r18+#0x464) = r2',
    0xf77c3c: 'memw(gp+#0xab84) = r0',
    0xf78048: 'call 0xced798',
    0xcf5764: 'call 0xcf4e8c', 0xcf5768: 'if (r0==#0) jump:nt 0xcf5784',
    0xcf577c: 'r16 = add(r16,#0x8)', 0xcf5780: 'r0 = #0x1',
    0x17f4628: 'r2 = #0x1c', 0x17f4640: 'memw(r29+#0x4) = r19',
    0x17f4644: 'memw(r16+#0x4) = r18', 0x17f4648: 'memw(r16+#0x8) = r17',
    0x17f4650: 'memb(r16+#0xc) = r20',
    0x17f4658: 'r0 = mux(p0,#0x0,#-0x2)',
    0x17f4668: 'r28.h = #0xcf', 0x17f466c: 'r28.l = #0x5788',
    0xcf5818: 'r4 = #0x2000', 0xcf5820: 'r4 = minu(r18,r4)',
    0xcf5824: 'r1 = memw(r17+#0x18)', 0xcf583c: 'call 0xd015e4',
    0xcf588c: 'call 0xcffd68', 0xcf58c0: 'memw(r16+#0x98) = r17',
    0xcf58c8: 'r0 = #-0x1', 0xcf58d0: 'r0 = #0x0',
    0xcf61a0: 'call 0xcf5754', 0xcf61a4: 'r1 = memw(r17+#0xc)',
    0xcf61a8: 'r0 = memw(r17+#0x8)', 0xcf61b0: 'memb(r17+#0x18) = r0',
    0xcf61bc: 'r1 = memw(r17+#0x14)', 0xcf61c0: 'call 0x146af58',
    0xcf61cc: 'call 0x12b4b28',
}
ANCHORS.update({
    0xcf5e64: 'call 0xcf5b04', 0xcf5ca8: 'call 0xcf8930',
    0xcf5cac: 'if (r0==#0) jump:t 0xcf5cd8', 0xcf5d0c: 'call 0xcfb774',
    0xcf8938: 'jump 0xcf84e4', 0xcf8500: 'call 0xcf7edc',
    0xcf8504: 'r1 = #0x1', 0xcf852c: 'r0 = memw(gp+#0x8198)',
    0xcf8538: 'r0.l = #0xa0a4', 0xcf8544: 'r0.l = #0xa0c2',
    0xcf854c: 'call 0x117f96c', 0xcf85ac: 'call 0x117f8e4',
    0xcf85b0: 'r2 = #0x800', 0xcf85bc: 'r4 = r0',
    0xcf85c0: 'r3:2 = combine(r20,r19)', 0xcf85d0: 'r1 = #0x1',
    0xcf85f8: 'call 0xcf6610', 0xcf85a4: 'r19 = add(r17,r19)',
    0xcf8670: 'call 0x117f728', 0xcf88d0: 'r17.l = #0xa195',
    0xcf88dc: 'call 0x117f96c', 0xcf8824: 'call 0xcf7e3c',
    0xcf8878: 'call 0xcf7edc', 0xcf887c: 'r1 = #0x0',
    0xcf88c8: 'r0 = and(r17,#0xff)',
    0xcf6624: 'r20 = and(r2,r0)', 0xcf661c: 'r0 = #0x7fff',
    0xcf6654: 'call 0xcf6594', 0xcf66b0: 'call 0xc569c4',
    0xc56a00: 'call 0xc57324',
    0xcf7ee4: 'if (r1==#0) jump:nt 0xcf7fb4',
    0xcf8224: 'r1 = lsr(r2,#0x2)', 0xcf8238: 'r1 = sub(#-0x1,r1)',
    0xcf823c: 'r0 |= asl(r1,#0x10)', 0xcf8278: 'r2 = add(r2,#-0x4)',
    0xcf827c: 'call 0xcf6610', 0xcf83c0: 'call 0xcf8490',
    0xcf8498: 'r28.h = #0x171', 0xcf849c: 'r28.l = #0xb954',
    0x171c384: 'r2 = extractu(r0,#0x4,#0x10)',
    0x171c3ac: 'memw(gp+#0x8198) = r2',
})
STRINGS = {0x1887568: 'dhd_bus_txdata', 0x1889e50: 'dhd_prot_hdrpush',
           0x19aa0a4: '/SyFi/brew/mod/rtecdc_new.bin',
           0x19aa0c2: '/SyFi/brew/mod/rtecdc.bin',
           0x19aa195: '/SyFi/brew/mod/nv.txt',
           0x18877e8: 'dhdsdio_godo_download_firmware',
           0x1887898: 'dhdsdio_membytes',
           0x18877b0: 'dhdsdio_download_state',
           0x1a10e62: 'ath1', 0x1a10e67: 'lan0', 0x1a10e6c: 'wan0'}


def audit(nand, objdump):
    blobs = {}
    for name, (_, digest) in SOURCES.items():
        blob = (nand/name).read_bytes()
        if hashlib.sha256(blob).hexdigest() != digest:
            raise ValueError('source hash mismatch: ' + name)
        blobs[name] = blob
    elf_path = nand/'dsp2-code-analysis.elf'
    with elf_path.open('rb') as stream:
        elf = ELFFile(stream)
        section = elf.get_section_by_name('.text')
        if (elf['e_machine'] != 'EM_QDSP6' or not section or
                section['sh_addr'] != SOURCES['dsp2-code.bin'][0] or
                section.data() != blobs['dsp2-code.bin']):
            raise ValueError('ELF text is not the pinned raw code segment')
    decoded = {}; listings = {}
    for name, (start, end) in RANGES.items():
        s = subprocess.check_output([objdump, '-d', f'--start-address={start}',
                                     f'--stop-address={end}', str(elf_path)], text=True)
        listings[name] = s
        for line in s.splitlines():
            m = re.match(r'\s*([0-9a-f]+):', line)
            if m:
                decoded[int(m[1], 16)] = line
    for addr, mnemonic in ANCHORS.items():
        if mnemonic not in decoded.get(addr, ''):
            raise ValueError(f'instruction anchor mismatch at {addr:#x}')
    ro = blobs['dsp2-rodata.bin']; base = SOURCES['dsp2-rodata.bin'][0]
    for addr, expected in STRINGS.items():
        if ro[addr-base:].split(b'\0', 1)[0] != expected.encode():
            raise ValueError(f'string anchor mismatch at {addr:#x}')
    if struct.unpack_from('<I', blobs['dsp2-small-data.bin'], 0x1f37c)[0] != 0x444944:
        raise ValueError('IOCTL selector magic mismatch')
    # In this packet the store reads old r1 (0xf74344), not new r1 (1).
    packet = '\n'.join(decoded[a] for a in (0xf77b24, 0xf77b28, 0xf77b2c))
    if packet.count('{') != 1 or packet.count('}') != 1 or '.new' in packet:
        raise ValueError('constructor packet boundary mismatch')
    return {
        'scope': 'UV310 ALKU7.3.2, offline static interpretation only',
        'hardware_access': False, 'firmware_executed': False, 'deployable_api': False,
        'source_sha256': {n: h for n, (_, h) in SOURCES.items()},
        'elf_entire_text_matches_raw': True,
        'instruction_anchors_checked': len(ANCHORS),
        'string_anchors_checked': len(STRINGS),
        'data_words_checked': 1,
        'ranges': {n: [hex(a), hex(z)] for n, (a,z) in RANGES.items()},
        'anchors': [{'address': hex(a), 'instruction': s} for a,s in ANCHORS.items()],
        'constructor_packet_checked': True,
        'constructor_interpretation': 'ath1 private+0x468 = 0xf74344, not 1; +0x464 = 0xf74378',
        'rx_ring': {'slots': 256, 'producer_offset': 48, 'consumer_offset': 52,
                    'slots_offset': 56, 'context': 'ath1 netif + 0x2c0',
                    'copy_then_publish': True, 'live_concurrency_verified': False},
        'tx_contract': {'source_frame_borrowed_until_return': True,
                        'dhd_copy_consumed_by_bus_path': True,
                        'ipnet_wrapper_releases_input_reference': True,
                        'ipnet_wrapper_discards_tx_status': True,
                        'queue_acceptance_is_delivery': False,
                        'scope': 'bounded static paths with initialized valid state'},
        'wifi_loader': {
            'orchestrator_image': 'DSP2', 'execution_target': 'BCM43362 RAM plus ROM',
            'enable_to_init_call': '0xcf5e64 -> 0xcf5b04',
            'init_to_loader': '0xcf5ca8 -> 0xcf8930 -> 0xcf84e4',
            'file_selector': 'gp+0x8198; zero: rtecdc.bin, nonzero: rtecdc_new.bin',
            'selector_source': '0x171c384 chip-ID bits16..19, stored at0x171c3ac',
            'files': ['rtecdc.bin', 'rtecdc_new.bin', 'nv.txt'],
            'file_read_max_bytes': 2048,
            'ram_transfer': '0xcf6610(bus, write_flag, bcm_address, host_buffer, count)',
            'write_flag': 1, 'read_flag': 0,
            'backplane_window_bytes': 32768,
            'start_release_chain': ['0xcf8878 -> 0xcf7edc(bus,0)',
                                    '0xcf83c0 -> 0xcf8490 -> 0x171b954'],
            'complete_reset_register_sequence_verified': False,
            'efs_storage_backend_core_identified': False,
            'loader_return_enum_fully_verified': False,
            'this_is_a_dsp2_code_loader': False,
        },
        'control_contract': {'ioctl_size': 28, 'buffer_cap': 8192,
                             'host_magic': '0x00444944',
                             'wl_wrapper_leaves_magic_zero': True,
                             'request_producer_and_timeout_verified': False},
        'limitations': ['Modern LLVM is not a validated Hexagon v3 execution model',
                        'Internal addresses are not SDK exports or a code-loading mechanism',
                        'No cellular UDP API, runtime memory budget or normal code-entry verified',
                        'No runtime return, concurrency, DMA or Wi-Fi acceptance tests'],
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--nand', required=True, type=Path)
    p.add_argument('--objdump', default=shutil.which('llvm-objdump'))
    p.add_argument('--out', required=True, type=Path)
    a = p.parse_args()
    if not a.objdump:
        p.error('supply --objdump with Hexagon-capable LLVM')
    result = audit(a.nand, a.objdump)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k: result[k] for k in ('instruction_anchors_checked',
                     'string_anchors_checked', 'elf_entire_text_matches_raw', 'deployable_api')}))

if __name__ == '__main__':
    main()
