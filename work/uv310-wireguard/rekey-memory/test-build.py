"""Bounded synthetic rekey integration tests. No USB, private data or image output."""
from pathlib import Path
import subprocess,hashlib,json,io,os,shutil
from elftools.elf.elffile import ELFFile
P=Path('work/uv310-wireguard');N=P/'rekey-memory';R=P/'rng-provider';H=P/'control-hardening';W=P/'wg-port';S=W/'upstream/src';B=N/'build';B.mkdir(exist_ok=True)
CC=os.environ.get('LLVM_CLANG') or shutil.which('clang');LD=os.environ.get('LLVM_LD') or shutil.which('ld.lld');Q=os.environ.get('QEMU_ARM') or shutil.which('qemu-system-arm')
assert CC and LD and Q, 'Set LLVM_CLANG, LLVM_LD and QEMU_ARM; see docs/BUILD.md'
flags=['--target=arm-none-eabi','-mcpu=cortex-m3','-mthumb','-Oz','-ffreestanding','-fno-builtin','-fno-stack-protector','-ffunction-sections','-fdata-sections','-DBYTE_ORDER=1234','-DLITTLE_ENDIAN=1234','-DSYNTHETIC_TEST']+['-I'+str(p) for p in [N,R,W/'build',W/'include',W,S]]
def obj(p,name,extra=[]):
 out=B/(name+'.o');subprocess.run([CC,*flags,*extra,'-c',str(p),'-o',str(out)],check=True);return str(out)
assert '203,0,113,7' in (N/'native-config.h').read_text()
shared=[obj(p,p.stem) for p in [R/'wireguard.c',S/'crypto.c',*sorted((S/'crypto/refc').glob('*.c')),W/'runtime.c',H/'entry.S']]
start=(H/'start.S').read_text().replace(' ldr r1,=failed',' bl print_fail\n ldr r1,=failed').replace('PASS native adapter: handshake, client packet forwarding, NAT, checksums, bounds, rejection','PASS renewal adapter')
(B/'start.S').write_text(start);shared.append(obj(B/'start.S','start'))
layout=(H/'test.ld').read_text().replace('.probe 0x2f340','.probe 0x28000');(B/'test.ld').write_text(layout)
native=obj(N/'native.c','native')
def link_run(name,adapter,extra=[]):
 t=obj(N/'tests.c','tests',extra);elf=B/(name+'.elf')
 subprocess.run([LD,'--gc-sections','-T',str(B/'test.ld'),adapter,*shared,t,'-o',str(elf)],check=True)
 e=ELFFile(io.BytesIO(elf.read_bytes()));sections={s.name:{'bytes':s['sh_size'],'address':s['sh_addr']} for s in e.iter_sections() if s['sh_flags']&2}
 assert sections['.version']['address']+sections['.version']['bytes']<0x33c00
 assert sections['.teststate']['address']+sections['.teststate']['bytes']<0x3c000
 r=subprocess.run([Q,'-M','mps2-an385','-nographic','-semihosting-config','enable=on,target=native','-kernel',str(elf)],capture_output=True,text=True,timeout=20)
 out=r.stdout+r.stderr;(B/(name+'.txt')).write_text(out)
 return out,sections,hashlib.sha256(elf.read_bytes()).hexdigest()
rows=[]
for name in ['BASELINE','REKEY','BAD_MAC','BAD_AEAD','STALE_RESPONSE','RNG_FAIL','QUEUE_EXPIRE','RETRY','RETRY_LIMIT','ALLOC_EXPIRE','COUNT_REKEY','COUNT_REJECT','WRAP','TAI_CARRY','CLAIM_RACE','PUBLISH_EXPIRY','LAB_PACKET','LAB_TIMER','LAB_WORKER','LAB_WRAP','MEMORY','MEMORY_BAD_NODE','MEMORY_CYCLE','MEMORY_SIZE','MEMORY_BAD_STACK']:
 out,sections,digest=link_run(name,native,[] if name=='REKEY' else ['-DTEST_'+name]);assert out.startswith('PASS renewal adapter'),(name,out)
 rows.append({'name':name,'passed':True,'elf_sha256':digest});print('PASS',name,flush=True)
negative=[]
for name,old,new in [('reset_device','if(!initialized){','if(1){'),('lost_response','int ok=!stopped&&phase==expected','int ok=!stopped'),('reject_previous','if(!k||!key_live(k,now)','if(k!=&dev.peers[0].curr_keypair||!k||!key_live(k,now)')]:
 s=(N/'native.c').read_text();assert s.count(old)==1;s=s.replace(old,new);p=B/(name+'.c');p.write_text(s)
 bad=obj(p,'native');out,_,_=link_run('negative-'+name,bad,['-DTEST_CLAIM_RACE'] if name=='lost_response' else []);assert 'FAIL line=' in out and 'PASS renewal' not in out,(name,out)
 negative.append({'mutation':name,'detected':True});print('PASS negative',name,flush=True)
result={'scope':'Synthetic Cortex-M3 integration, no real radio/clock/entropy/device deployment','suites':rows,'negative_controls':negative,'rekey_after_ms':120000,'reject_at_age_ms':180000,'retry_after_ms':5000,'max_cycle_tries':18,'source_sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [N/'native.c',N/'tests.c',N/'native-config.h',R/'wireguard.c',R/'wireguard.h']},'sections_synthetic_link':sections,'limitations':['Fixed synthetic RNG pool and TAI base are not safe standalone platform services','Worker crypto phases still drop external packets, no packet queue','No retry jitter, receive-driven early renewal or server-initiated handshake support yet','Single IPv4 client, LAN DNS bypass and IPv6 policy not expanded','No live image or throughput result'],'goal_complete':False}
Path('outputs/uv310-wireguard/evidence/rekey-memory-tests.json').write_text(json.dumps(result,indent=2)+'\n');print('Wrote rekey-memory-tests.json',flush=True)
