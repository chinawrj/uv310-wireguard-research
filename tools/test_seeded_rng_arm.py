"""Cortex-M3 QEMU tests with independent vectors; never opens USB/network."""
from pathlib import Path
import hashlib,json,os,subprocess,tempfile
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms
ROOT=Path(__file__).resolve().parents[1];W=ROOT/'work/uv310-wireguard';N=W/'seeded-rng';R=W/'wg-port/upstream/src/crypto/refc'
cc=os.environ.get('LLVM_CLANG','clang');ld=os.environ.get('LLVM_LD','ld.lld');q=os.environ.get('QEMU_ARM','qemu-system-arm')
def oracle(seed,counter,n):return Cipher(algorithms.ChaCha20(seed,counter.to_bytes(4,'little')+bytes(12)),mode=None).encryptor().update(bytes(n))
start=''' .syntax unified
.cpu cortex-m3
.thumb
.section .vectors,"a"
.word 0x20010000
.word _start
.section .text.start,"ax"
.global _start
.thumb_func
_start:
 bl test_main
 cmp r0,#0
 ite eq
 ldreq r1,=pass
 ldrne r1,=fail
 movs r0,#4
 bkpt #0xab
 ldr r1,=0x20026
 movs r0,#0x18
 bkpt #0xab
 b .
pass: .asciz "PASS seeded ARM\\n"
fail: .asciz "FAIL seeded ARM\\n"
'''
layout='ENTRY(_start)\nSECTIONS { .vectors 0 : { KEEP(*(.vectors)) } .text 0x100 : { *(.text*) *(.rodata*) } .data 0x20000000 : { *(.data*) } .bss : { *(.bss*) *(COMMON) } /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) } }\n'
original=(N/'seeded_rng.c').read_text()
mutations=[('counter-reset','memset(out,0,n);chacha20','r->cipher.state[12]=0;memset(out,0,n);chacha20'),('no-budget','r->cipher.state[12]>=BLOCK_BUDGET','0'),('no-wipe','p[i]=0;','p[i]=p[i];'),('repeat-init','r->state!=0','0')]
with tempfile.TemporaryDirectory() as td:
 t=Path(td);vectors=[oracle(seed,0,640) for seed in [bytes(32),bytes(range(32)),bytes([255])*32]]
 header='static const unsigned char expected[3][640]={'+','.join('{'+','.join(map(str,v))+'}' for v in vectors)+'};\nstatic const unsigned char last_block[32]={'+','.join(map(str,oracle(bytes(range(32)),65535,32)))+'};\n'
 (t/'vectors.h').write_text(header);(t/'start.S').write_text(start);(t/'layout.ld').write_text(layout)
 flags=['--target=arm-none-eabi','-mcpu=cortex-m3','-mthumb','-Oz','-ffreestanding','-fno-builtin','-ffunction-sections','-fdata-sections','-I'+str(R),'-I'+str(N),'-I'+str(t),'-I'+str(W/'wg-port/include')]
 shared=[]
 for i,p in enumerate([R/'chacha20.c',W/'wg-port/runtime.c',N/'arm-tests.c',t/'start.S']):
  o=t/f'{i}.o';subprocess.run([cc,*flags,'-c',str(p),'-o',str(o)],check=True,capture_output=True);shared.append(str(o))
 rows=[]
 for name,source in [('baseline',original)]+[(name,original.replace(old,new)) for name,old,new in mutations]:
  if name!='baseline':
   old=next(a for n,a,b in mutations if n==name);assert original.count(old)==1
  p=t/'candidate.c';p.write_text(source);o=t/'candidate.o';elf=t/'test.elf'
  subprocess.run([cc,*flags,'-c',str(p),'-o',str(o)],check=True,capture_output=True)
  link=subprocess.run([ld,'--gc-sections','--no-undefined','-T',str(t/'layout.ld'),str(o),*shared,'-o',str(elf)],capture_output=True,text=True)
  if link.returncode:raise SystemExit(link.stderr)
  run=subprocess.run([q,'-M','mps2-an385','-nographic','-semihosting-config','enable=on,target=native','-kernel',str(elf)],capture_output=True,text=True,timeout=20)
  output=run.stdout+run.stderr
  wanted='PASS seeded ARM' if name=='baseline' else 'FAIL seeded ARM'
  assert wanted in output and ('FAIL' if name=='baseline' else 'PASS') not in output,(name,output)
  rows.append({'variant':name,'expected_result_observed':True,'output':output.strip(),'elf_sha256':hashlib.sha256(elf.read_bytes()).hexdigest()})
 result={'scope':'Synthetic Cortex-M3 wrapper only; no native WireGuard or radio integration','independent_vector_comparisons':31,'negative_controls_detected':4,'runs':rows,'source_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [N/'seeded_rng.c',N/'seeded_rng.h',N/'arm-tests.c',R/'chacha20.c',R/'chacha20.h',W/'wg-port/runtime.c',Path(__file__)]},'vectors_sha256':hashlib.sha256(header.encode()).hexdigest(),'compiler':subprocess.check_output([cc,'--version'],text=True).splitlines()[0],'qemu':subprocess.check_output([q,'--version'],text=True).splitlines()[0],'hardware_verified':False,'full_stack_bound_verified':False}
 out=ROOT/'.test-results';out.mkdir(exist_ok=True);(out/'seeded-rng-arm-tests.json').write_text(json.dumps(result,indent=2)+'\n');print('PASS Cortex-M3: 31 oracle comparisons, lifecycle checks, 4 mutants detected')
