"""Conservative visible-call frame sums from a linked ARM ELF, not a stack bound."""
import struct
import capstone

def analyze(elf):
 section=elf.get_section_by_name('.stack_sizes');assert section is not None,'Missing compiler stack-size section'
 data=section.data();pos=0;frames={}
 while pos<len(data):
  assert pos+4<=len(data);address=struct.unpack_from('<I',data,pos)[0]&~1;pos+=4;value=0;shift=0
  while True:
   assert pos<len(data) and shift<35
   byte=data[pos];pos+=1;value|=(byte&127)<<shift
   if not byte&128:break
   shift+=7
  assert address not in frames or frames[address]==value
  frames[address]=value
 functions={};names={}
 for symbol in elf.get_section_by_name('.symtab').iter_symbols():
  if symbol['st_info']['type']!='STT_FUNC' or not symbol['st_size']:continue
  address=symbol['st_value']&~1;names[symbol.name]=address
  if address in functions:continue
  functions[address]={'function':symbol.name,'address':hex(address),'size':symbol['st_size'],'frame_bytes':frames.get(address),'targets':set(),'indirect_register_calls':set()}
 cs=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB|capstone.CS_MODE_MCLASS);cs.detail=True
 code=[s for s in elf.iter_sections() if s['sh_flags']&4 and s['sh_size']]
 for address,f in functions.items():
  owner=next((s for s in code if s['sh_addr']<=address and address+f['size']<=s['sh_addr']+s['sh_size']),None)
  if owner is None:continue
  offset=address-owner['sh_addr'];raw=owner.data()[offset:offset+f['size']]
  for i in cs.disasm(raw,address):
   if i.group(capstone.CS_GRP_CALL) or i.group(capstone.CS_GRP_JUMP):
    op=i.operands[-1]
    if op.type==capstone.arm.ARM_OP_IMM:
     target=op.imm&~1
     if not address<=target<address+f['size']:f['targets'].add(target)
    elif op.type==capstone.arm.ARM_OP_REG and not (i.mnemonic=='bx' and i.reg_name(op.reg)=='lr'):f['indirect_register_calls'].add(i.reg_name(op.reg))
   elif i.mnemonic=='bx' and i.op_str!='lr':f['indirect_register_calls'].add(i.op_str)
 def walk(address,seen):
  f=functions[address];best=0;path=[];missing=set();indirect=set(f['indirect_register_calls']);cycles=set()
  if f['frame_bytes'] is None:missing.add(hex(address))
  for target in f['targets']:
   if target not in functions:missing.add(hex(target));continue
   if target in seen:cycles.add(hex(target));continue
   child=walk(target,seen|{target});missing.update(child['missing']);indirect.update(child['indirect']);cycles.update(child['cycles'])
   if child['bytes']>best:best=child['bytes'];path=child['path']
  return {'bytes':(f['frame_bytes'] or 0)+best,'path':[address]+path,'missing':missing,'indirect':indirect,'cycles':cycles}
 for name in ['worker','intercept','snapshot']:
  assert name in names and functions[names[name]]['frame_bytes'] is not None,'Missing root frame metadata: '+name
 roots={}
 for name in ['worker','intercept','emit_control','snapshot','memory_snapshot']:
  if name not in names:
   roots[name]={'separate_symbol_present':False};continue
  address=names[name];x=walk(address,{address})
  roots[name]={'separate_symbol_present':True,'visible_chain_frame_sum_bytes':x['bytes'],'path':[{'function':functions[a]['function'],'frame_bytes':functions[a]['frame_bytes']} for a in x['path']],'missing_frame_or_unresolved_target':sorted(x['missing']),'indirect_register_calls':sorted(x['indirect']),'cycles':sorted(x['cycles']),'is_complete_stack_bound':False}
 largest=sorted(({'function':f['function'],'frame_bytes':f['frame_bytes']} for f in functions.values() if f['frame_bytes'] is not None),key=lambda f:f['frame_bytes'],reverse=True)[:15]
 return {'scope':'Linked compiler frame metadata plus disassembled direct calls; tail calls added conservatively; no complete bound','roots':roots,'largest_frames':largest,'frame_records':len(frames),'disassembler_version':capstone.__version__,'limitations':['ROM/assembly callees, interrupt nesting and stock caller frames are not modeled','Indirect calls, unrecognized branch forms and missing function/frame symbols can omit paths','Compiler metadata covers inlining but not runtime stack high-water','Sums are neither a general upper nor lower bound']}
