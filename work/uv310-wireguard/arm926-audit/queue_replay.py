#!/usr/bin/env python3
"""Bounded offline DPC instruction replay. Requires capstone and unicorn.

Loads only the audited enqueue/dequeue bytes and their literal pool from a
hash-pinned owner image. Synchronization, signaling and callbacks are fixtures.
No loader, MMU, interrupt, real scheduling, device or network emulation.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
import runtime


def run_suite(blob, mutation=None):
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R4,
        UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_SP,
        UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR)
    u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    for address, size in ((0x220000,0x10000),(0x2be000,0x1000),
                          (0x2ee000,0x2000),(0x309000,0x2000),
                          (0x700000,0x1000),(0x800000,0x2000),
                          (0x900000,0x1000)):
        u.mem_map(address,size)
    start,end = 0x229ff6,0x22a096
    def offset(va):
        return 0x52000 + va - 0x1c4000
    u.mem_write(start,blob[offset(start):offset(end)])
    u.mem_write(0x22a0f0,blob[offset(0x22a0f0):offset(0x22a144)])
    # Synthetic callback returns: BX LR in Thumb and ARM respectively.
    u.mem_write(0x700000,b'\x70\x47')
    u.mem_write(0x700100,bytes.fromhex('1eff2fe1'))
    if mutation:
        address,replacement=mutation
        u.mem_write(address,replacement)
    idx,ring,flag=0x2eeb18,0x3097c8,0x2eeb10
    events=[]
    prior=[0]
    critical=[False]
    returned=[False]
    expected_callbacks=[]
    cases=[]
    def word(address): return struct.unpack('<I',u.mem_read(address,4))[0]
    def setword(address,value): u.mem_write(address,struct.pack('<I',value))
    def ret(value=None):
        if value is not None: u.reg_write(UC_ARM_REG_R0,value)
        u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR))
    def hook(uc,pc,size,unused):
        if pc==0x900000:
            returned[0]=True; u.emu_stop(); return
        if pc==0x2be100:
            events.append(('enter',prior[0])); critical[0]=True
            ret(prior[0]); return
        if pc==0x2be11c:
            assert critical[0] and prior[0]==0 and word(flag)==0
            events.append(('leave',)); critical[0]=False; ret(); return
        if pc==0x2296a0:
            assert critical[0] and word(flag)==1
            assert u.reg_read(UC_ARM_REG_R0)==0x309fc8
            assert u.reg_read(UC_ARM_REG_R1)==1
            events.append(('notify',)); ret(0xdeadbeef); return
        if pc in (0x700000,0x700100):
            assert expected_callbacks,'Unexpected callback'
            want_pc,want_arg=expected_callbacks.pop(0)
            assert pc==want_pc and u.reg_read(UC_ARM_REG_R0)==want_arg
            assert bool(u.reg_read(UC_ARM_REG_CPSR)&0x20)==(pc==0x700000)
            assert word(flag)==0
            assert critical[0]==bool(prior[0])
            events.append(('callback',pc,want_arg))
            # Its return value is ignored by the stock dispatcher.
            u.reg_write(UC_ARM_REG_R0,0xbaadf00d)
            return
        assert start<=pc<end, f'Unexpected execution {pc:#x}'
    u.hook_add(UC_HOOK_CODE,hook)
    saved={UC_ARM_REG_R4:0x44444444,UC_ARM_REG_R5:0x55555555,
           UC_ARM_REG_R6:0x66666666,UC_ARM_REG_R7:0x77777777}
    def call(entry,a=0,b=0,old=0):
        prior[0]=old; critical[0]=bool(old); returned[0]=False
        u.reg_write(UC_ARM_REG_CPSR,0x13)
        u.reg_write(UC_ARM_REG_SP,0x801ff0)
        u.reg_write(UC_ARM_REG_LR,0x900001)
        for r,v in saved.items(): u.reg_write(r,v)
        u.reg_write(UC_ARM_REG_R0,a); u.reg_write(UC_ARM_REG_R1,b)
        u.emu_start(entry|1,0x900004,count=200)
        assert returned[0], 'Instruction budget exhausted'
        assert u.reg_read(UC_ARM_REG_SP)==0x801ff0
        assert all(u.reg_read(r)==v for r,v in saved.items()),'Callee-saved register changed'
        assert word(flag)==0
        assert critical[0]==bool(old)
        return u.reg_read(UC_ARM_REG_R0)
    def enqueue(cb,arg,old=0): return call(0x22a040,cb,arg,old)
    def dequeue(old=0): return call(0x229ff6,old=old)
    def reset(read=0,write=0):
        u.mem_write(ring,b'\0'*2048)
        setword(idx,read); setword(idx+4,write); setword(flag,0)
        events.clear(); expected_callbacks.clear()
    reset()
    assert enqueue(0,0x1234)==0 and events==[]
    assert word(idx)==word(idx+4)==0
    cases.append('null callback rejected without synchronization or notification')
    for old in (0,1):
        reset()
        assert dequeue(old)==0 and word(idx)==word(idx+4)==0
        assert not any(e[0] in ('notify','callback') for e in events)
        assert sum(e[0]=='leave' for e in events)==(old==0)
        cases.append(f'empty queue prior state {old}')
    for cb in (0x700001,0x700100):
        for old in (0,1):
            reset(); arg=0x13579bdf
            assert enqueue(cb,arg,old)==1
            assert events[-1][0]==('leave' if old==0 else 'notify')
            assert not any(e[0]=='callback' for e in events)
            assert word(ring)==cb and word(ring+4)==arg and word(idx+4)==1
            expected_callbacks.append((cb&~1,arg))
            assert dequeue(old)==1 and not expected_callbacks
            assert word(idx)==word(idx+4)==1
            assert dequeue(old)==0
            cases.append(f'callback mode {"thumb" if cb&1 else "arm"}, prior state {old}')
    for read in (0,1,127,255):
        reset(read,(read-1)&255)
        before=bytes(u.mem_read(ring,2048))
        assert enqueue(0x700001,0x12345678)==0
        assert bytes(u.mem_read(ring,2048))==before
        assert word(idx)==read and word(idx+4)==((read-1)&255)
        assert not any(e[0]=='notify' for e in events)
        cases.append(f'full queue rejected at read index {read}')
    for initial in (0,254,255):
        reset(initial,initial)
        for i in range(255):
            cb=0x700001 if i%2==0 else 0x700100
            arg=0xa0000000+i
            assert enqueue(cb,arg)==1
            expected_callbacks.append((cb&~1,arg))
        assert enqueue(0x700001,0)==0
        assert sum(e[0]=='notify' for e in events)==255
        for i in range(255): assert dequeue()==1
        assert dequeue()==0 and not expected_callbacks
        assert word(idx)==word(idx+4)==((initial+255)&255)
        cases.append(f'255-entry FIFO fill/drain and wrap from {initial}')
    return cases


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    runtime.audit(a.image)
    blob=a.image.read_bytes()
    cases=run_suite(blob)
    mutations=[
        ('full condition inverted',0x22a06c,lambda b:bytes([b[0],b[1]^1])),
        ('callback argument register changed',0x22a038,lambda b:bytes([b[0]^8,b[1]])),
        ('callback invocation removed',0x22a03a,lambda b:b'\xc0\x46'),
    ]
    detected=[]
    for name,addr,change in mutations:
        off=0x52000+addr-0x1c4000
        try: run_suite(blob,(addr,change(blob[off:off+2])))
        except AssertionError: detected.append(name)
        else: raise AssertionError(f'Undetected mutation: {name}')
    import unicorn,capstone
    result=dict(schema='uv310-arm926-dpc-replay-v1',date='2026-10-28',
        image_sha256=hashlib.sha256(blob).hexdigest(),
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        emulator='Unicorn',unicorn_version=unicorn.__version__,capstone_version=capstone.__version__,
        firmware_code_ranges=[['0x229ff6','0x22a096']],literal_range=['0x22a0f0','0x22a144'],
        passed=True,cases=cases,positive_cases=len(cases),negative_controls=detected,
        negative_count=len(detected),firmware_bytes_published=False,hardware_access=False,
        stubs=['synchronization entry/restore','task signaling','bounded synthetic ARM/Thumb callbacks'],
        limits=['Only bounded stock DPC functions executed; not the full firmware',
                'No real scheduler, MMU, IRQ, cache, watchdog or IPC execution',
                'No custom-code loader, Wi-Fi forwarding or WireGuard validation',
                'Mutated instruction copies exist only in emulator memory'])
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'passed':True,'positive_cases':len(cases),'negative_controls':len(detected)}))

if __name__=='__main__': main()
