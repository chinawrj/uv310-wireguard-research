#!/usr/bin/env python3
"""Read-only, hash-pinned UV310 AMSS ECM/IPC evidence; never contacts hardware.
Requires capstone for bounded instruction assertions; firmware remains private.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

EXPECTED = '388dda0d44c9ed391306c8dbd5851a612b0e68c3dc7faec189234dd7a525c9f5'

class Image:
    def __init__(self, path):
        self.raw = Path(path).read_bytes()
        if hashlib.sha256(self.raw).hexdigest() != EXPECTED:
            raise ValueError('AMSS SHA256 mismatch; refusing addresses from another image')
        if self.raw[:7] != b'\x7fELF\x01\x01\x01':
            raise ValueError('expected little-endian ELF32')
        po = struct.unpack_from('<I', self.raw, 28)[0]
        psz, pn = struct.unpack_from('<HH', self.raw, 42)
        self.segments = [struct.unpack_from('<8I', self.raw, po + i * psz) for i in range(pn)]
    def read(self, va, count):
        for typ, off, vaddr, paddr, size, memsz, flags, align in self.segments:
            if typ == 1 and vaddr <= va and va + count <= vaddr + size:
                if off + va - vaddr + count > len(self.raw):
                    raise ValueError('truncated segment')
                return self.raw[off + va - vaddr:off + va - vaddr + count]
        raise ValueError(f'VA not file-backed: {va:#x}')
    def word(self, va):
        return struct.unpack('<I', self.read(va, 4))[0]
    def string(self, va):
        out = bytearray()
        for i in range(512):
            b = self.read(va+i, 1)[0]
            if b == 0:
                return out.decode('ascii')
            out.append(b)
        raise ValueError('unterminated string')

# Names are bounded reconstruction, not recovered C symbols or a callable SDK.
INSTRUCTIONS = [
 (0x23c864,'ldr','r0, [pc, #0x130]'),
 (0x23c866,'str','r0, [sp, #0x10]'),
 (0x23c870,'ldr','r0, [pc, #0x130]'),
 (0x23c872,'str','r0, [sp, #0x1c]'),
 (0x23c898,'blx','r4'),
 (0x2d020e,'push','{r0, r1, r2, r3, r4, r5, r6, r7, lr}'),
 (0x2d0366,'ldr','r0, [pc, #0xa8]'),
 (0x2d02fc,'strh','r1, [r0, #0x22]'),
 (0x2d0306,'ldr','r0, [r0, #0x10]'),
 (0x2d037c,'ldr','r0, [r0, #8]'),
 (0x2d0148,'str','r6, [r5, #0x18]'),
 (0x2d014c,'bl','#0x2313f2'),
 (0x2313f2,'push','{r4, lr}'),
 (0x231402,'bl','#0x28a94e'),
 (0x23140a,'bl','#0x2296a0'),
 (0x231380,'bl','#0x2d0188'),
 (0x2d018c,'ldr','r0, [r0, #0x18]'),
 (0x2d0194,'ldr','r1, [r0, #0x20]'),
 (0x2d0196,'ldr','r0, [r0, #0x18]'),
 (0x2d019c,'mov','r0, sp'),
 (0x2d019e,'blx','r1'),
 (0x2d01ac,'bl','#0x2341f2'),
 (0x2d01b8,'bl','#0x291a00'),
 (0x2d0414,'push','{r4, r5, lr}'),
 (0x2d0428,'bl','#0x2d020e'),
 (0x2d0430,'push','{r0, r1, r2, r3, r4, r5, r6, r7, lr}'),
 (0x2d04bc,'ldr','r0, [pc, #0x260]'),
 (0x2d04be,'ldr','r1, [r4, #0x10]'),
 (0x2d052a,'ldr','r0, [r4, #0x18]'),
 (0x2d0530,'bl','#0x2a0356'),
 (0x2d0536,'str','r0, [r4, #0x18]'),
 (0x2d0572,'bl','#0x291a00'),
 (0x2d0576,'str','r4, [r7]'),
 (0x2d0aac,'ldr','r1, [pc, #0xd8]'),
 (0x2d0aae,'str','r1, [r4, #0x18]'),
 (0x2d0ab2,'ldr','r1, [pc, #0xd8]'),
 (0x2d0ab4,'str','r1, [r4, #0x20]'),
 (0x2d11c8,'push','{r4, r5, r6, r7, lr}'),
 (0x2d11d2,'ldr','r0, [pc, #0x35c]'),
 (0x2d1350,'ldr','r1, [r5, #4]'),
 (0x2d1356,'str','r1, [r0, #0x18]'),
 (0x2d1358,'ldr','r1, [r5, #8]'),
 (0x2d135a,'str','r1, [r0, #0x1c]'),
 (0x2d135c,'ldr','r1, [r5, #0x14]'),
 (0x2d135e,'str','r1, [r0, #0x20]'),
 (0x2d15c4,'push','{r0, r1, r2, r4, r5, r6, lr}'),
 (0x2d1640,'ldr','r0, [pc, #0x398]'),
 (0x2d168e,'bl','#0x291a00'),
 (0x2d16ba,'bl','#0x291a00'),
 (0x2d16f2,'bl','#0x2341f2'),
 (0x2d1740,'bl','#0x2d0ee0'),
 (0x23713e,'blx','r3'),
 (0x237156,'ldr','r0, [pc, #0x60]'),
]
DIAGNOSTICS = [
 (0x2e4810,0x1f476c,'hsu_al_ecm.c:_ecm_rx_done_internal: unexpected status %d, i=%d, cur_idx=%d'),
 (0x2e4858,0x1f47b8,'hsu_al_ecm.c:_ecm_tx_done. cur_dsm_item->data_ptr=%x, buffers[i]=%x'),
 (0x2e49d8,0x2ec250,'hsu_al_ecm.c:hsu_al_ecm_data_open(): Enter'),
 (0x2e4b4c,0x256974,'hsu_al_ecm.c:hsu_al_ecm_data_transmit(): Instance state=%d (expected opened) (handle=%d)'),
 (0x2e4b7c,0x285c54,'hsu_al_ecm.c:hsu_al_ecm_data_transmit: sending the chain we got from the application'),
 (0x2e4ffc,0x1f5148,'oncrpc_pacmark.c:unable to write packet'),
]
LITERALS = {
 0x23c998:0x2d11c9, 0x23c9a4:0x2d15c5,
 0x2d0410:0x2e4810, 0x2d0720:0x2e4858,
 0x2d0b88:0x2d0415, 0x2d0b8c:0x2d0431,
 0x2d1530:0x2e49d8, 0x2d19dc:0x2e4b4c,
 0x2371b8:0x2e4ffc, 0x231418:0x441874,
 0x231414:0x440cd4,
}
ASSERT_RECORDS = [
 (0x2001f950,0x20011d00,0x1f1768,'smd_packet_memcpy.c','Assertion (pi->rx_bytes_remaining - bytes_read) <= pi->rx_bytes_remaining failed'),
 (0x2001f960,0x20011d51,0x1f1768,'smd_packet_memcpy.c','smd_packet_memcpy_rx bad state'),
 (0x2001f970,0x20011d70,0x1f1768,'smd_packet_memcpy.c','smd_packet_memcpy_tx bad state'),
 (0x200217a0,0x20018910,0x1f1872,'smd_bridge_server.c','smd_bridge_server_connect_port: invlid smd port id'),
 (0x200217b0,0x20018943,0x1f1872,'smd_bridge_server.c','smd_bridge_receive_cmd: unrecognized command %d'),
]

def analyze(path):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    im = Image(path)
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    checked=[]
    for va,mnemonic,operands in INSTRUCTIONS:
        ins = next(md.disasm(im.read(va,4),va,count=1),None)
        if ins is None or (ins.mnemonic,ins.op_str)!=(mnemonic,operands):
            raise ValueError(f'instruction mismatch at {va:#x}: {ins}')
        checked.append({'va':hex(va),'mode':'Thumb','instruction':f'{mnemonic} {operands}'})
    for va,value in LITERALS.items():
        if im.word(va)!=value:raise ValueError(f'literal mismatch at {va:#x}')
    diagnostics=[]
    for rec,ptr,expected in DIAGNOSTICS:
        if im.word(rec+8)!=ptr or im.string(ptr)!=expected:raise ValueError(f'diagnostic mismatch at {rec:#x}')
        diagnostics.append({'record_va':hex(rec),'string_va':hex(ptr),'text':expected})
    assertions=[]
    for rec,msg,fileptr,filename,expected in ASSERT_RECORDS:
        if (im.word(rec),im.word(rec+4))!=(msg,fileptr) or im.string(msg)!=expected or im.string(fileptr)!=filename:
            raise ValueError(f'assertion metadata mismatch at {rec:#x}')
        assertions.append({'record_va':hex(rec),'source':filename,'message':expected,'classification':'metadata only; no caller/peer established'})
    smem=[]
    for va,expected in [(0x20001b9b,'Bad pointer from smem_alloc.'),(0x20001c72,'SMEM layout mismatch for %d %x != %x'),(0x20011bb6,'Could not allocate Block port SMEM')]:
        if im.string(va)!=expected:raise ValueError(f'SMEM anchor mismatch {va:#x}')
        smem.append({'va':hex(va),'text':expected,'classification':'string anchor only'})
    return {'schema':1,'date':'2026-10-28','scope':'offline static analysis; no hardware contacted',
      'image_sha256':EXPECTED,'checks_passed':len(checked)+len(LITERALS)+len(diagnostics)+len(assertions)+len(smem),
      'instructions':checked,'literals':{hex(k):hex(v) for k,v in LITERALS.items()},
      'diagnostic_anchors':diagnostics,'smd_metadata_anchors':assertions,'smem_anchors':smem,
      'verdict':{'arm_usb_ecm_packet_path':'bounded code and callback registration verified',
                 'smd_peer_mapping':'not established','arm_wifi_packet_path':'not established',
                 'arm_udp_socket_api':'not established','wireguard_arm_deployable':False},
      'limits':['No normal-runtime hook, task budget, writable memory or packet interception was tested.',
                'ECM code presence does not prove active USB mode or routing through ARM on this unit.',
                'ONCRPC packets are RPC transport framing; they do not prove IP/UDP sockets.',
                'Fields are local reconstruction, not complete public ABI or safe ownership contract.']}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--amss',required=True)
    p.add_argument('--output',required=True)
    args=p.parse_args()
    result=analyze(args.amss)
    out=Path(args.output);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'result':'pass','checks':result['checks_passed'],'output':str(out)}))
if __name__=='__main__':main()
