"""Own-device offline DHD event-path audit. No injection or device access."""
from pathlib import Path
import hashlib,struct,json,subprocess
P=Path('work/uv310-wireguard'); D=P/'private/nand'; N=P/'bridge-audit'; E=Path('outputs/uv310-wireguard/evidence')
expected=json.loads((E/'modem-entropy-static.json').read_text())['source_sha256']
blobs={}
for name,h in expected.items():
 b=(D/name).read_bytes();assert hashlib.sha256(b).hexdigest()==h;blobs[name]=b
ranges=[('rx',0xcf4b38,0xcf4c98),('event-parser',0xd00cd8,0xd00fb8),('event-host-order',0xd00170,0xd00364),('callback-setter',0xcf45d0,0xcf4604),('driver-init',0xcf5b04,0xcf5da4),('special-command',0xcf4644,0xcf475c),('interface-stubs',0xcf459c,0xcf45b0),('paged-false-hit',0xf01e3bb8,0xf01e3c08)]
asm={}
for name,a,b in ranges:
 elf=D/('dsp2-paged-analysis.elf' if a>=0xf0000000 else 'dsp2-code-analysis.elf')
 s=subprocess.check_output(['/opt/homebrew/opt/llvm/bin/llvm-objdump','-d',f'--start-address={hex(a)}',f'--stop-address={hex(b)}',str(elf)],text=True)
 asm[name]=s;(N/(name+'.asm')).write_text(s)
checks=[('rx','call 0xd00cd8'),('rx','r24 = add(r19,#0x2ac)'),('rx','r1 = memw(r19+#0x2b8)'),('rx','r2 = add(r2,#0x4)'),('rx','r3 = memw(r2+#0x0)'),('rx','call 0xd00170'),('rx','call 0xf74428'),('rx','call 0x141593c'),('event-parser','r1 = add(r2,#0x13)'),('event-parser','r17 = add(r20,#0x48)'),('event-parser','r2 = #0x30'),('callback-setter','r0 = add(r0,#0x2bc)'),('driver-init','call 0xcf45d0')]
for name,s in checks:assert s in asm[name],(name,s)
# Explicitly preserve instruction-packet boundaries in the decisive sequence.
lines=asm['rx'].splitlines();packet='\n'.join(x for x in lines if any(f'{a:x}:' in x for a in range(0xcf4c04,0xcf4c14,4)))
assert packet.count('{')==1 and packet.count('}')==1 and '.new' not in packet
# Semantics model, NOT execution of firmware: normal source reads use pre-packet values.
slots=[];ptr=0x2ac
for _ in range(3):
 old=ptr;ptr=old+4;slots.append(old)
assert slots==[0x2ac,0x2b0,0x2b4] and 0x2b8 not in slots
ro=blobs['dsp2-rodata.bin'];assert ro[0x19c4bbc-0x183e000:0x19c4bbc-0x183e000+3]==bytes.fromhex('001018')
small=blobs['dsp2-small-data.bin'];pairs=[]
for i in range(8):
 p,f=struct.unpack_from('<II',small,0xbd70+8*i)
 def string_at(a):
  if not 0x183e000<=a<0x183e000+len(ro):return None
  s=ro[a-0x183e000:].split(b'\0',1)[0]
  return s.decode('ascii') if s and all(32<=c<127 for c in s) else None
 pairs.append({'index':i,'name_pointer':hex(p),'name':string_at(p),'handler_word':hex(f),'handler_in_code_range':0xc01000<=f<0xc01000+len(blobs['dsp2-code.bin'])})
assert pairs[0]['name']=='alk_3g_manufacturer' and pairs[1]['name'] is None
next_work=['Resolve event callback registration from constructor/copy paths; matching offsets in unrelated structures are not evidence','Establish a bounded modem-native RNG bridge only after exact target, message ownership and entropy readiness are verified','Review the isolated offline-tested control-hardening revision for real interrupt behavior and memory footprint, then validate with freshly provisioned material','Complete secure reboot/rekey/reconnect and complete Wi-Fi forwarding acceptance']
r={'scope':'Exact UV310 ALKU7.3.2 own-device extracted firmware; static analysis plus separate read-only precheck', 'source_sha256':expected,'static_checks':len(checks),'firmware_execution_performed':False,'device_writes':False,'rng_bridge_verified':False,'event_protocol_inferred':{'ethertype':'0x886c','vendor_oui_offset':19,'vendor_oui_hex':'001018','user_subtype_offset':22,'user_subtype_endianness':'big','accepted_user_subtype':1,'event_header_offset':24,'event_header_copy_bytes':48,'payload_offset':72,'event_type_offset_within_header':4,'flags_offset_within_header':2,'status_offset_within_header':8,'callback_header_converted_to_host_order':True,'observed_event_switch_values':[5,6,8,10,11,12,16,18,54],'all_input_validation_proven':False},'callback_layout_inferred':{'context':'r19 = [receive argument r0 + 12]','raw_frame_callback_offset':'0x2b8','raw_frame_call_site':'0xcf4bec','converted_event_callback_offsets':[hex(x) for x in slots],'converted_event_call_site':'0xcf4c1c','converted_event_arguments':['pointer to 48-byte stack event header','payload pointer into received packet'],'packet_semantics_sequence':packet,'model_test_passed':True,'runtime_targets_resolved':False,'readiness_callback_offsets':['0x2bc','0x2c0'],'readiness_setter':'0xcf45d0 copies 8 bytes; known init caller at0xcf5d9c supplies a zero pair','ownership':'receive chain released via0x141593c at0xcf4c90; stack header and payload pointer must not escape without verified copying/refcount'},'special_debug_command_table':{'candidate_address':'0x340bd70','candidate_entries':pairs,'consistent_eight_entry_table':False,'runtime_initialization_unknown':True,'live_invocation_performed':False,'interpretation':'Do not turn static BRCM branch into a claimed supported command; current bytes are not eight valid string/function pairs'},'paged_search_false_positive':{'address':'0xf01e3bdc','reason':'surrounding repeated records/unknown encodings indicate data; a rendered add(r17,0x2ac) is not an established executable callback registration','complete_paged_callgraph_proven':False},'limitations':['Modern LLVM disassembly is not a validated Hexagon v3 execution model','Ordinary same-packet reads use old registers; do not interpret printed lines sequentially','No direct RNG call was found in the bounded event parser, but indirect callback targets remain unresolved; no global absence claim','Firmware contains mixed code/data; byte-pattern or objdump search hits require control-flow confirmation','Neither event EtherType nor internal RNG message IDs establish an externally supported entropy protocol'],'reference':{'title':'Qualcomm Hexagon V73 PRM, section3.3.1 packet execution semantics','url':'https://developer.qualcomm.com/qfile/70668/80-n2040-53_aa_prm_v73.pdf','scope':'General packet semantics cross-check only; newer revision is not proof of complete v3 ISA compatibility'},'next_required_work':next_work,'goal_complete':False}
(E/'bridge-static.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'static_checks':len(checks),'callback_offsets':r['callback_layout_inferred']['converted_event_callback_offsets'],'rng_bridge_verified':False}))
