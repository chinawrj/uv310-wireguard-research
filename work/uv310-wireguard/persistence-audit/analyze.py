"""Bounded offline audit of config persistence in the user's exact firmware."""
from pathlib import Path
import json,hashlib,subprocess
P=Path('work/uv310-wireguard');N=P/'persistence-audit';D=P/'private/nand';E=Path('outputs/uv310-wireguard/evidence')
expected={'dsp2-code.bin':'9bcdfd03028be95c1f6285c299e359d79be8e6e4e2f7e06191293b452dd17076','dsp2-rodata.bin':'588fd80ade91170e5a11431f8d21f78f72e62fd5b189f174863f9b21c018b98f'}
for name,h in expected.items():assert hashlib.sha256((D/name).read_bytes()).hexdigest()==h
ro=(D/'dsp2-rodata.bin').read_bytes()
def string(a):return ro[a-0x183e000:a-0x183e000+100].split(b'\0')[0].decode('ascii')
strings={a:string(a) for a in [0x19c1744,0x19c174c,0x19c1756,0x19c1764,0x19c155c,0x19c1788,0x19c0bff,0x19c290f]}
assert list(strings.values())==['asp_get','asp_match','getCfgGeneral','getCfgZero','','0','/web/userseting_nvconfig.txt','/web/update_skip']
ranges={'asp-registration':(0x18303e4,0x18306e0),'config-lookup-set':(0x182fbc0,0x1830100),'asp-dispatch':(0x1830900,0x1830ab0),'config-service':(0x182d000,0x182d3a0),'config-database':(0x182d268,0x182df00),'config-save':(0x18362d8,0x1836370)}
assembly={}
for name,(a,b) in ranges.items():
 s=subprocess.check_output(['/opt/homebrew/opt/llvm/bin/llvm-objdump','-d',f'--start-address={hex(a)}',f'--stop-address={hex(b)}',str(D/'dsp2-code-analysis.elf')],text=True)
 assembly[name]=s;(N/(name+'.asm')).write_text(s)
checks=[('asp-dispatch','1830a40:','call 0x182fc98'),('asp-dispatch','1830a7c:','call 0x182fc08'),('config-lookup-set','182fc68:','memb(r16+#0xc) = r1'),('config-lookup-set','182fc84:','call 0x182d054'),('config-lookup-set','182fd14:','call 0x182d054'),('config-service','182d088:','call 0x12b4d08'),('config-database','182d360:','call 0x182d268'),('config-database','182d28c:','r18 = #0x5db'),('config-database','182dad4:','call 0x182d3dc'),('config-database','182dadc:','call 0x182d334'),('config-database','182dacc:','call 0x182da8c'),('config-database','182da90:','call 0x182d9d8'),('config-database','182da14:','call 0x182d214'),('config-database','182da2c:','call 0x117f96c'),('config-database','182da48:','call 0x182d8b8'),('config-database','182d9ac:','call 0x117f82c'),('config-database','182da68:','call 0x182d118')]
for name,address,needle in checks:assert any(address in line and needle in line for line in assembly[name].splitlines()),(name,address,needle)
result={'scope':'Static analysis of exact stock Hexagon code; no runtime file/config writes','source_sha256':expected,'static_instruction_checks':len(checks),'registration_names':[strings[a] for a in [0x19c1744,0x19c174c,0x19c1756,0x19c1764]],
 'asp_get':{'entry':'0x1830650','read_callback':'0x182fc98','second_argument_behavior':'When second arg equals string 0, call setter with EMPTY string; not arbitrary-value setter','clear_call':'0x1830a7c','live_clear_test_performed':False},
 'config_request':{'setter':'0x182fc08','getter':'0x182fc98','shared_request':'0x254c2c8','layout':{'8':'key pointer','12':'operation byte:0 read,1 RAM update,2 persistence commit','16':'value/output pointer','20':'completion signal/task reference','32':'status byte'},'enqueue':'0x182d054 -> 0x12b4d08 queue0x2f00664','dispatcher':'0x182daa0','addresses_are_internal_not_wire_commands':True},
 'ram_update':{'entry':'0x182d268','list':'0x2f00674+0x14','existing_key_search':True,'new_key_creation_in_this_setter':False,'max_copied_value_bytes':1499,'rejects_CR_LF':True,'allocates_replacement_value':True,'durable_write_in_this_bounded_function':False},
 'commit_path':{'entry':'0x182d9d8','file':'/web/userseting_nvconfig.txt','steps':['allocate 5120-byte serialization buffer','validate config state','0x182d214 file removal/preparation path','open target using flags0x441/mode0x1b6 at0x182da2c','serialize/write through0x182d8b8','close through0x182d118','follow-up call0x117db58'], 'atomic_rename_or_journal_verified':False,'power_loss_durability_verified':False,'api_failure_checks_complete':False},
 'correction':'0x18362d8 references /web/update_skip; it is not the generic configuration database commit function',
 'decision':'Do not use asp_get clear or normal whole-config save as a proven crash-safe WireGuard boot counter. Need a verified separate durable-state bridge/API.',
 'limitations':['Modern LLVM Hexagon v3 disassembly is not execution-validated; same-packet register reads use old values','Storage helper names/semantics inferred from local control flow; no power-loss test or filesystem guarantees established','No generic remotely callable persistence primitive established','No user configuration/seed values read or modified'], 'goal_complete':False}
(E/'persistence-audit.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'checks':len(checks),'persistent_bridge_verified':False,'whole_config_commit_located':True}))
