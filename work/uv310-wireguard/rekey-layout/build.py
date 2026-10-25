"""Hardware-address link audit using public synthetic material. No image/USB/private reads."""
from pathlib import Path
import subprocess,json,hashlib,io,re
from elftools.elf.elffile import ELFFile
P=Path('work/uv310-wireguard');N=P/'rekey-layout';L=P/'rekey-lifecycle';R=P/'rng-provider';H=P/'control-hardening';W=P/'wg-port';S=W/'upstream/src'
CC='/opt/homebrew/opt/llvm/bin/clang';LD='/opt/homebrew/opt/llvm/bin/ld.lld'
# Permit link-only audit, retain the source branch's explicit deployment guard.
s=(L/'native.c').read_text().replace('#ifndef SYNTHETIC_TEST\n#error This branch is a synthetic integration test, not a deployable image','#ifndef HARDWARE_LAYOUT_AUDIT\n#error Hardware-address layout audit only; not a deployable image')
s=s.replace('extern void fixture_before_claim(u32 expected);','''#ifdef SYNTHETIC_TEST
extern void fixture_before_claim(u32 expected);
#endif''').replace(' fixture_before_claim(expected);','''#ifdef SYNTHETIC_TEST
 fixture_before_claim(expected);
#endif''')
(N/'native.c').write_text(s)
layout='''ENTRY(native_probe)
original_alloc=0x806bc5; original_heap_free_body=0x8062e1; original_timer_body=0x80611d;
original_idle_body=0x80655d; original_raw_free=0x806c4d; original_continuation=0x9dfd;
original_sdpcm=0x80aa55; original_wl=0x80fc35;
SECTIONS {
 .hook 0x9df8 : { KEEP(*(.hook)) }
 .probe 0x2f340 : { KEEP(*(.probe)) *(.text*) *(.rodata*) }
 .state : ALIGN(8) { __state_start=.; *(.data*) *(.bss*) *(COMMON) __state_end=.; }
 .version : ALIGN(4) { KEEP(*(.version)) }
 __image_end=.;
 /DISCARD/ : { *(.ARM.exidx*) *(.comment) }
}'''.replace('=',' = ').replace('= .;','= .;')
(N/'layout.ld').write_text(layout)
rows=[]
for name,native,poolbytes in [('checked_baseline_256',R/'native.c',256),('renewal_256',N/'native.c',256),('renewal_1024',N/'native.c',1024)]:
 B=N/name;B.mkdir(exist_ok=True)
 cfg=(L/'native-config.h').read_text();assert '203,0,113,7' in cfg
 m=re.search(r'RANDOM_POOL\[\]\s*=\{([^}]+)\}',cfg);assert m
 raw=m[1].split(',');assert len(raw)==1024
 cfg=cfg[:m.start(1)]+','.join(raw[:poolbytes])+cfg[m.end(1):]
 (B/'native-config.h').write_text(cfg)
 flags=['--target=arm-none-eabi','-mcpu=cortex-m3','-mthumb','-Oz','-ffreestanding','-fno-builtin','-fno-stack-protector','-ffunction-sections','-fdata-sections','-DBYTE_ORDER=1234','-DLITTLE_ENDIAN=1234','-DHARDWARE_LAYOUT_AUDIT']+['-I'+str(p) for p in [B,R,W/'build',W/'include',W,S]]
 # Copy sources with quoted config includes so only this row's synthetic config is selected.
 (B/'native.c').write_text(native.read_text())
 sources=[B/'native.c',R/'wireguard.c',S/'crypto.c',*sorted((S/'crypto/refc').glob('*.c')),W/'runtime.c',H/'entry.S']
 objects=[]
 for f in sources:
  out=B/(f.stem+'.o');subprocess.run([CC,*flags,'-c',str(f),'-o',str(out)],check=True);objects.append(str(out))
 elf=B/'layout.elf';subprocess.run([LD,'--gc-sections','-T',str(N/'layout.ld'),*objects,'-o',str(elf)],check=True)
 e=ELFFile(io.BytesIO(elf.read_bytes()));sy={x.name:x['st_value'] for x in e.get_section_by_name('.symtab').iter_symbols()};sections={x.name:{'address':hex(x['sh_addr']),'bytes':x['sh_size']} for x in e.iter_sections() if x['sh_flags']&2}
 assert not any(k.startswith('fixture_') for k in sy)
 end=sy['__image_end'];heap=(end+255)&~255;extra=heap-0x2fc00
 rows.append({'variant':name,'synthetic_pool_bytes':poolbytes,'elf_sha256':hashlib.sha256(elf.read_bytes()).hexdigest(),'sections':sections,'heap_start':hex(heap),'reserved_bytes':heap-0x2f290,'extra_vs_historical_passive_probe':extra,'historical_boot_heap_projection':24068-extra,'historical_traffic_heap_projection':19492-extra,'below_original_stack_bottom':heap<0x3a96c,'no_fixture_symbols':True})
 print(json.dumps(rows[-1]),flush=True)
r={'scope':'Actual known firmware link addresses with synthetic config and stock cached tick path; no executable image packed or deployed','source_sha256':{'rekey_native':hashlib.sha256((L/'native.c').read_bytes()).hexdigest(),'layout_variant':hashlib.sha256((N/'native.c').read_bytes()).hexdigest(),'core':hashlib.sha256((R/'wireguard.c').read_bytes()).hexdigest()},'rows':rows,'historical_heap_values_not_new_measurements':True,'current_heap_peak_verified':False,'hardware_abi_execution_this_round':False,'goal_complete':False}
Path('outputs/uv310-wireguard/evidence/rekey-hardware-layout.json').write_text(json.dumps(r,indent=2)+'\n')
