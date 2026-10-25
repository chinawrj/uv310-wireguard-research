"""Offline analysis of the owner's exact DSP2 image. No device or network access.
Internal addresses/layouts are hypotheses for this firmware, NOT external commands.
"""
from pathlib import Path
import hashlib,struct,json,re,subprocess
P=Path('work/uv310-wireguard');N=P/'modem-entropy';D=P/'private/nand';E=Path('outputs/uv310-wireguard/evidence')
specs={
'dsp2-code.bin':(0xc01000,'9bcdfd03028be95c1f6285c299e359d79be8e6e4e2f7e06191293b452dd17076'),
'dsp2-data.bin':(0x1a1e000,'b31d062ece0b896b98c33d8359dfad23cb660e17605059afc239eab13f9919c3'),
'dsp2-rodata.bin':(0x183e000,'588fd80ade91170e5a11431f8d21f78f72e62fd5b189f174863f9b21c018b98f'),
'dsp2-small-data.bin':(0x3400000,'366ff74c956a4897f124072f967de5ab76f6ec728c6e85aeb7281a5c527a32f4'),
'dsp2-paged-code.bin':(0xf0000000,'a9880ae5b3476beca54136d98f2be87bcae2273867f0cfb317b308a339a74460')}
blobs={};hashes={}
for name,(base,expected) in specs.items():
 b=(D/name).read_bytes();h=hashlib.sha256(b).hexdigest();assert h==expected,name;blobs[name]=b;hashes[name]=h
def read(va,n):
 for name,(base,_) in specs.items():
  b=blobs[name]
  if base<=va and va+n<=base+len(b):return b[va-base:va-base+n]
 raise ValueError(hex(va))
def word(va):return struct.unpack('<I',read(va,4))[0]
assert read(0x19c6bea,7)==b'secrnd\0'
task=list(struct.unpack('<6I',read(0x1a920d0,24)));assert task==[0x19c6bea,0x2f33cb4,0,0x1000,0x1f,0x172f328]
assert word(0x341f6c0)==0x8d700008
assert [word(a) for a in [0x341f6c4,0x341c43c,0x341f6c8]]==[0x470001,0x470002,0x470003]
ranges=[('ssl-random',0x1744850,0x1744930),('random-selector',0x12c4b48,0x12c4b94),('random-wrapper',0x1727f18,0x1727fac),('random-fill',0x172ece0,0x172ee4c),('random-message',0x172ee4c,0x172ee8c),('seed-save',0x172ee8c,0x172ef34),('random-dispatch',0x172f034,0x172f0dc),('random-task',0x172f328,0x172f678),('generator-output',0x172f720,0x172f774),('nv-wrapper',0x17269b0,0x1726b34),('paged-nv',0xf031ef68,0xf031efe4)]
assembly={}
for name,start,end in ranges:
 elf=D/('dsp2-paged-analysis.elf' if start>=0xf0000000 else 'dsp2-code-analysis.elf')
 t=subprocess.check_output(['/opt/homebrew/opt/llvm/bin/llvm-objdump','-d','--start-address='+hex(start),'--stop-address='+hex(end),str(elf)],text=True)
 assembly[name]=t;(N/(name+'.asm')).write_text(t)
checks=[('ssl-random','call 0x12c4b48'),('random-selector','jump 0x1727f18'),('random-wrapper','jump 0x172ece0'),('random-fill','call 0x172f720'),('generator-output','call 0x1738a38'),('random-task','call 0x172f6b0'),('random-task','call 0x17269b0'),('paged-nv','r0 = #0x1058'),('random-task','r1 = #0xa5'),('random-message','call 0x172ece0'),('random-dispatch','call 0x172ee4c')]
for name,needle in checks:assert needle in assembly[name],(name,needle)
targets={0x12c4b48,0x1727f18,0x172ece0,0x172f720,0x172ee8c}
calls=[]
for line in (D/'dsp2-code.asm').open():
 m=re.match(r'\s*([0-9a-f]+):.*?\b(call|jump) (0x[0-9a-f]+)',line)
 if m and int(m[3],16) in targets:calls.append({'site':hex(int(m[1],16)),'kind':m[2],'destination':m[3]})
from elftools.elf.elffile import ELFFile
amss_path=D/'amss.elf';amss_sha=hashlib.sha256(amss_path.read_bytes()).hexdigest()
assert amss_sha=='388dda0d44c9ed391306c8dbd5851a612b0e68c3dc7faec189234dd7a525c9f5'
amss_hits=[]
with amss_path.open('rb') as f:
 for seg in ELFFile(f).iter_segments():
  if seg['p_type']!='PT_LOAD':continue
  b=seg.data()
  for val in [0x470001,0x470002,0x470003]:
   for off in range(0,len(b)-3,4):
    if struct.unpack_from('<I',b,off)[0]==val:amss_hits.append({'value':hex(val),'va':hex(seg['p_vaddr']+off)})
result={
 'amss_literal_scan':{'sha256':amss_sha,'scope':'aligned uint32 literals in extracted PT_LOAD file bytes only','matches':amss_hits,'absence_is_not_transport_proof':True},
 'scope':'Own UV310 ALKU7.3.2 extracted DSP2; static analysis only',
 'source_sha256':hashes,'execution_performed':False,'device_writes':False,'seed_values_read':False,
 'task_record':{'address':'0x1a920d0','raw_words':[hex(x) for x in task],'name':'secrnd','entry':'0x172f328'},
 'ssl_rng_call':{'site':'0x17448dc','callee':'0x12c4b48','inferred_register_arguments':{'r0':'mode=1','r1':'32-byte stack output buffer','r2':'length=32'},'failure_path':'surrounding SSL routine checks status, bounded retries on code9; failure reports cannot create server random'},
 'same_core_path':['0x12c4b48 (mode selector)','0x1727f18 (pointer/length wrapper)','0x172ece0 (lock/state/ready handling)','0x172f720 (zero output, call generator)','0x1738a38 (stateful generator candidate)'],
 'mode_two':'0x1727f34 calls normal fill and redraws zero bytes; do not treat as uniform random byte API',
 'task_message_layout_inferred':{'request_type':'0x470001','response_type':'0x470002','other_handled_type':'0x470003','handler':'0x172ee4c','offsets':{'0':'message type overwritten to response','4':'random fill return status','8':'output pointer','12':'unsigned16 length'},'dispatch':'0x172f034 compares types loaded from GP slots','external_transport':'NOT established; these are internal task messages, not USB/UDP/AT opcodes'},
 'seed_lifecycle_static':{'candidate_nv_item':'0x1058 (4184)','read_wrapper':'0x1726a48','write_wrapper':'0x17269b0','startup_read':'0x172f3b8 -> 0x172f6b0 -> 0xf031efa8','startup_write':'0x172f5e0 -> 0x17269b0','later_save':'0x172ee8c -> 0x172ef18 -> 0xf031ef70','seed_buffer_bytes':32,'all_zero_buffer_fallback':'0x172f400..0x172f40c fills 32 bytes with 0xa5; subsequent mixing/conditioning still occurs','mmio_input_pointer_slot':'0x341f6c0','mmio_input_address':'0x8d700008','mmio_identity':'unknown; not credited as TRNG','durability_atomicity_powerloss':'unverified','seed_secret_value_inspected':False,'startup_nv_write_failure_path':'0x172f5e8 branches on success; nonzero status reaches log at0x172f608 then task loop0x172f60c. Not proof of fail-closed persistence'},
 'cross_processor_bridge':{'wifi_cpu':'BCM43362 Cortex-M3','rng_cpu':'modem DSP2 Hexagon','direct_call_possible':False,'existing_host_rx':'0xcf4b38: Broadcom event parse at0xd00cd8 or normal Ethernet path0xf74428','rng_request_in_existing_wifi_handler_proven':False},
 'disassembly_checked_edges':len(checks),'direct_call_sites_in_nonpaged_code':calls,
 'limitations':['Modern LLVM disassembly is an analysis aid; Hexagon v3 instruction semantics/ABI are not execution-validated','No complete entropy or cipher audit; names and SSL use do not establish security','No live RNG call, persistent-seed read/write, internal-task-message injection or firmware patch','No modem-to-Wi-Fi entropy/clock/persistent-state bridge exists yet','Public address search did not identify the MMIO source; unrelated SoCs were not used as evidence'],
 'next_required_work':['Trace ownership and sender of internal request0x470001, and any existing authenticated transport to Wi-Fi host driver','Determine0x8d700008 source and seed/reseed readiness/failure semantics before trusting output','If no usable bridge exists, evaluate safe Wi-Fi memory overlays while retaining entropy validation; do not silently reuse fixed per-build material','Finish reusable reboot/rekey/reconnect and full Wi-Fi data-plane acceptance'],
 'goal_complete':False}
(E/'modem-entropy-static.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'task_entry':hex(task[-1]),'checked_static_edges':len(checks),'inbound_sites':len(calls),'seed_item':'0x1058','live_entropy_available':False}))
