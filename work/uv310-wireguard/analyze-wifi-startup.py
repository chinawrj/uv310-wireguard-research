"""Offline, hash-pinned examination of the user's extracted BCM43362a2 RAM image.
No USB, network, writes to the device, or modification of the firmware input.
"""
from pathlib import Path
import struct,hashlib,json
import capstone
p=Path('work/uv310-wireguard/private/web-assets/rtecdc_new.bin')
b=p.read_bytes()
digest=hashlib.sha256(b).hexdigest()
assert digest=='4b86d71b92529034b2b46da7b93402f67c8aef98d2fc1efa91fc67ff7e5fb85a'
m=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB|capstone.CS_MODE_MCLASS)
m.detail=True
def instructions(a,z):
 out=[]
 for i in m.disasm(b[a:z],a):
  d={'address':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}
  if i.mnemonic=='ldr' and len(i.operands)==2 and i.operands[1].type==capstone.arm.ARM_OP_MEM and i.operands[1].mem.base==capstone.arm.ARM_REG_PC:
   v=((i.address+4)&~3)+i.operands[1].mem.disp
   d.update(literal_address=hex(v),literal_value=hex(struct.unpack_from('<I',b,v)[0]))
  out.append(d)
 return out
def literal(addr):
 d=instructions(addr,addr+4)[0]
 return int(d['literal_value'],16)
assert struct.unpack_from('<I',b,4)[0]==0x8b0d
assert literal(0x8c96)==0x3c000
assert literal(0x8cc4)==0x1c3e4 and literal(0x8cc6)==0x1c7d6
assert b[0x187ae:].split(b'\0',1)[0]==b'reclaim section 1: Returned %d bytes to the heap\n'
ranges=[(literal(0x8de8),literal(0x8dec)),(literal(0x8df0),literal(0x8df4))]
result={
 'method':'Offline static Thumb-2 disassembly; base address 0 consistent with vector and branch/literal cross references',
 'input_sha256':digest,'input_bytes':len(b),'live_chip_revision_confirmed':False,
 'reset_vector':'0x8b0d','startup_stack_top':'0x3c000','stack_top_decimal':0x3c000,
 'initial_zero_range':{'start':'0x1c3e4','end_constant':'0x1c7d6','note':'word stores until r0 >= end; actual final word extends to 0x1c7d8'},
 'startup_call_chain':['0x8cd0 calls 0x18548','0x1854a calls 0x24624','0x18550 calls 0x9128','0x18556 calls 0x806374 (outside extracted RAM image)'],
 'reclaim_function':'0x9128',
 'reclaim_range_constants':[{'start':hex(a),'end':hex(z),'difference_bytes':z-a} for a,z in ranges],
 'reclaim_total_difference_bytes':sum(z-a for a,z in ranges),
 'rom_targets_observed':['0x802040','0x802080','0x806220','0x806374'],
 'inferences':['Startup initializes SP below 240 KiB boundary; agrees with vendor BCM43362 SRAM capacity','Reclaim function clears two startup ranges and passes them to a ROM routine; ranges are not permanently unused space','Calls into 0x80xxxx show the downloaded RAM image is not the complete firmware'],
 'not_proven':['Currently loaded a0/a2 image','Live free heap, peak packet buffers or stack headroom','ROM routine signatures and packet callback ABI','Safe patch location, SDK application loader, or executing custom code alongside Wi-Fi'],
 'next_required_evidence':['Normal-runtime driver access to firmware version/ROM/memory or exact matching SDK symbols','Map SDIO/Wi-Fi packet callbacks and preserve cellular return path','Observe live memory before selecting code reservation'],
 'device_modified':False,
 'selected_disassembly':{'stack_and_zero':instructions(0x8c96,0x8cd6),'main':instructions(0x18548,0x1855c),'memory_layout':instructions(0x8dc4,0x8dfa),'reclaim':instructions(0x9128,0x91a6)},
 'sources':['https://fcc.report/FCC-ID/2akc5smc01/3324607.pdf#page=70','https://github.com/seemoo-lab/nexmon/blob/master/README.md']}
out=Path('outputs/uv310-wireguard/evidence/wifi-startup-analysis.json')
out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k not in ['selected_disassembly']},indent=2))
