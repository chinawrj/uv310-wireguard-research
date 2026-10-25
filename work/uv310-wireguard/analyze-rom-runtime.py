"""Offline ROM analysis. Original disassembly remains private; export findings only."""
from pathlib import Path
import capstone,json,re,hashlib,struct
P=Path('work/uv310-wireguard');f=P/'private/bcm43362-rom.bin'
if f.exists():b=f.read_bytes();complete=True
else:
 d=json.loads((P/'private/wifi-rom-blocks.json').read_text());b=bytearray(0x70000)
 for k,v in d.items():b[int(k)-0x800000:int(k)-0x800000+64]=bytes.fromhex(v)
 complete=False
cs=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB|capstone.CS_MODE_MCLASS)
regions=[('format',0x802518,0x8025b0),('heap_add',0x806220,0x806374),('runtime_loop',0x806374,0x806500),('pkt_alloc',0x806d80,0x806e80),('sdpcm_ops',0x809100,0x80ab00),('wl_ops',0x80f900,0x80fd00)]
for name,a,z in regions:
 rows=[f'{i.address:08x}: {i.mnemonic} {i.op_str}' for i in cs.disasm(b[a-0x800000:z-0x800000],a)]
 (P/'private'/('rom-'+name+'.asm')).write_text('\n'.join(rows)+'\n')
 # Print only short known entry point functions for ongoing analysis.
 if name in ('heap_add','format','runtime_loop','pkt_alloc'):print(name+'\n'+'\n'.join(rows[:60]))
strings=[]
for m in re.finditer(rb'[\x20-\x7e]{5,}',b):
 text=m[0].decode()
 if re.search(r'rand|timer|hndrte|pkt|malloc|sdpcm|reclaim|clock|entropy',text,re.I):strings.append({'address':hex(0x800000+m.start()),'text':text})
# Strings can contain proprietary text: keep the full selection private.
(P/'private/rom-runtime-strings.json').write_text(json.dumps(strings,indent=2))
print('complete',complete,'runtime_related_strings',len(strings))
