"""Fresh one-boot lab material and hash-pinned image. No device operations.
Never publishes configuration, firmware image, object files, keys, RNG or TAI base.
"""
from pathlib import Path
import base64,configparser,hashlib,io,ipaddress,json,os,secrets,socket,struct,subprocess,time,zlib
from elftools.elf.elffile import ELFFile
os.umask(0o077)
P=Path('work/uv310-wireguard');N=P/'rekey-memory';R=P/'rng-provider';H=P/'control-hardening';W=P/'wg-port';S=W/'upstream/src'
B=P/'private/rekey-memory';B.mkdir(exist_ok=True,mode=0o700);B.chmod(0o700)
assert not (B/'native-config.h').exists(),'Refuse to replace already-provisioned experiment'
tests=json.loads(Path('outputs/uv310-wireguard/evidence/rekey-memory-tests.json').read_text())
assert len(tests['suites'])==25 and all(r['passed'] for r in tests['suites'])
assert all(r['detected'] for r in tests['negative_controls'])
sha=lambda b:hashlib.sha256(b).hexdigest()
assert tests['source_sha256'][str(N/'native.c')]==sha((N/'native.c').read_bytes())
cfg=configparser.ConfigParser();assert cfg.read(P/'private/uv310-wifi-20261025.conf')
def key(v):
 b=base64.b64decode(v,validate=True);assert len(b)==32;return b
host,port=cfg['Peer']['Endpoint'].rsplit(':',1);port=int(port);assert 0<port<65536
ip=socket.gethostbyname(host);now=time.time_ns()
values={'PRIVATE_KEY':key(cfg['Interface']['PrivateKey']),'PEER_KEY':key(cfg['Peer']['PublicKey']),'PRESHARED_KEY':key(cfg['Peer']['PresharedKey']),
 'RANDOM_POOL':secrets.token_bytes(256),'TAI64N':(0x400000000000000a+now//10**9).to_bytes(8,'big')+(now%10**9).to_bytes(4,'big'),
 'ENDPOINT_IP':ipaddress.ip_address(ip).packed,'INNER_SOURCE':ipaddress.ip_interface(cfg['Interface']['Address']).ip.packed,
 'INNER_DEST':ipaddress.ip_address('192.168.123.1').packed,'LAN_GATEWAY':ipaddress.ip_address('192.168.100.1').packed}
header='/* PRIVATE: single fresh lab boot only. */\n'+''.join('static const unsigned char '+k+'[]={'+','.join(map(str,v))+'};\n' for k,v in values.items())+f'#define ENDPOINT_PORT {port}\n'
(B/'native-config.h').write_text(header)
(B/'native.c').write_bytes((N/'native.c').read_bytes())
(B/'provision.json').write_text(json.dumps({'generated_unix_ns':now,'random_pool_bytes':256,'native_config_sha256':sha(header.encode()),'fresh_one_boot_only':True}))
CC='/opt/homebrew/opt/llvm/bin/clang';LD='/opt/homebrew/opt/llvm/bin/ld.lld'
flags=['--target=arm-none-eabi','-mcpu=cortex-m3','-mthumb','-Oz','-ffreestanding','-fno-builtin','-fno-stack-protector','-ffunction-sections','-fdata-sections','-DBYTE_ORDER=1234','-DLITTLE_ENDIAN=1234','-DBOUNDED_REKEY_LAB']+['-I'+str(p) for p in [B,R,W/'build',W/'include',W,S]]
objects=[]
for f in [B/'native.c',R/'wireguard.c',S/'crypto.c',*sorted((S/'crypto/refc').glob('*.c')),W/'runtime.c',H/'entry.S']:
 o=B/(f.stem+'.o');subprocess.run([CC,*flags,'-c',str(f),'-o',str(o)],check=True);objects.append(str(o))
layout=P/'rekey-layout/layout.ld'
subprocess.run([LD,'--gc-sections','-T',str(layout),*objects,'-o',str(B/'native.elf')],check=True)
elf=ELFFile(io.BytesIO((B/'native.elf').read_bytes()))
sec={s.name:(s['sh_addr'],bytes(s['sh_size']) if s['sh_type']=='SHT_NOBITS' else s.data()) for s in elf.iter_sections()}
sy={x.name:x['st_value'] for x in elf.get_section_by_name('.symtab').iter_symbols()}
assert not any(x.startswith('fixture_') for x in sy)
end=sy['__image_end'];heap=(end+255)&~255;assert heap<=0x33c00
stock=(P/'private/web-assets/rtecdc_new.bin').read_bytes();original='4b86d71b92529034b2b46da7b93402f67c8aef98d2fc1efa91fc67ff7e5fb85a';assert sha(stock)==original
c=bytearray(stock+bytes(end-len(stock)))
for name in ['.hook','.probe','.state','.version']:
 a,b=sec[name];c[a:a+len(b)]=b
for a,v in [(0x9e18,sec['.version'][0]),(0x1e840,heap),(0x25fc,sy['packet1']|1),(0x1bc64,sy['packet0']|1),(0x178,sy['timer_hook']|1),(0x144,sy['idle_hook']|1),(0x12c,sy['free_hook']|1)]:struct.pack_into('<I',c,a,v)
struct.pack_into('<I',c,0x2f28e,zlib.crc32(c[:0x2f28e]));assert zlib.crc32(c[:0x2f292])==0x2144df1c
assert c[0x2462a:0x2462e]==stock[0x2462a:0x2462e]
allowed=[range(a,a+4) for a in [0x9df8,0x9e18,0x1e840,0x25fc,0x1bc64,0x178,0x144,0x12c,0x2f28e]]
assert all(any(i in r for r in allowed) for i in range(len(stock)) if stock[i]!=c[i])
(P/'private/rtecdc_new.rekey-memory.bin').write_bytes(c)
e={'original_sha256':original,'candidate_sha256':sha(c),'candidate_bytes':len(c),'code_constants_bytes':len(sec['.probe'][1]),'state_bytes':len(sec['.state'][1]),'heap_start':hex(heap),'reserved_bytes':heap-0x2f290,
 'historical_traffic_heap_projection':19492-(heap-0x2fc00),'current_runtime_heap_verified':False,'crc_check_unchanged':True,'pool_bytes':256,'no_fixture_symbols':True,'fresh_material_generated':True,'persistent_startup_supported':False,'lab_lifetime_cached_ticks':360000,'goal_complete':False}
(B/'result.json').write_text(json.dumps(e,indent=2)+'\n')
Path('outputs/uv310-wireguard/evidence/rekey-memory-build.json').write_text(json.dumps(e,indent=2)+'\n')
src=(P/'efs_path.py').read_text().replace('wg_path_','wg_rekeymemory_').replace('rtecdc_new.path.bin','rtecdc_new.rekey-memory.bin').replace('e10e9770006b47d6f496f93115b009211584a3fa6310150f0513772e69554167',sha(c)).replace('path-build/result.json','private/rekey-memory/result.json').replace('path-efs-','rekey-memory-efs-')
src=src.replace('import efs_probe_io as fs','import sys\nsys.path.insert(0,"work/uv310-wireguard")\nimport efs_probe_io as fs')
src=src.replace('    c=d.get_active_configuration()', '    c=d.get_active_configuration()\n    assert {i.bInterfaceNumber:sorted(x.bEndpointAddress for x in i) for i in c}=={0:[1,129,130],1:[2,131],2:[3,132],3:[4,133],4:[5,134]}')
src=src.replace("    op=parser.parse_args().operation", "    op=parser.parse_args().operation\n    if op in ('stage','activate'):\n        meta=json.loads((P/'private/rekey-memory/provision.json').read_text())\n        assert 0<time.time_ns()-meta['generated_unix_ns']<1200*10**9,'Fresh material expired'\n        assert not Path('outputs/uv310-wireguard/evidence/rekey-memory-cold-candidate.json').exists(),'One boot only; already attempted'")
(N/'efs_rekey.py').write_text(src)
src=(P/'emitter-wg/reboot.py').read_text().replace('import efs_emitter as p','import efs_rekey as p').replace('emitter-wg-cold-','rekey-memory-cold-')
src=src.replace("'cold_start':True", "'software_restart':True, 'physical_power_removal':False")
src=src.replace("try:\n d=p.verify_device();", "try:\n assert not out.exists(),'Do not repeat a keyed-image boot'\n d=p.verify_device();")
# Verify complete topology in each enumeration, not just PID/interface count.
src=src.replace('if len(list(d.get_active_configuration()))==n:return d', "if len(list(d.get_active_configuration()))==n:\n     top={i.bInterfaceNumber:sorted(x.bEndpointAddress for x in i) for i in d.get_active_configuration()}\n     expected={5:{0:[1,129,130],1:[2,131],2:[3,132],3:[4,133],4:[5,134]},4:{0:[1,129],1:[2,130],2:[3,131],3:[4,132]}}\n     if n in expected:assert top==expected[n]\n     return d")
# After successful enumeration remove stored experiment before any client test.
src=src.replace(" d=p.verify_device();usb.util.claim_interface(d,1);rows=[]", " if phase=='candidate':\n  r=subprocess.run(['python3','work/uv310-wireguard/rekey-memory/efs_rekey.py','restore'],capture_output=True,text=True,timeout=40)\n  assert r.returncode==0,'Immediate stored-stock restoration failed'\n  e['stored_stock_restored_before_client_test']=True\n d=p.verify_device();usb.util.claim_interface(d,1);rows=[]")
src=src.replace('No firmware writes in this script. Only ejects uniquely identified read-only UV310 CD.','Candidate phase calls the verified EFS restoration tool after boot.')
src=src.replace("'file_writes_in_this_script':False","'direct_file_writes':False,'candidate_phase_calls_efs_restore':phase=='candidate'")
(N/'reboot.py').write_text(src)
for f in B.rglob('*'):
 if f.is_file():f.chmod(0o600)
(P/'private/rtecdc_new.rekey-memory.bin').chmod(0o600)
print(json.dumps(e,indent=2))
