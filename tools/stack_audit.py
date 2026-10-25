"""Compile public Cortex-M3 sources for frame/call-path evidence. No USB or images."""
from pathlib import Path
import argparse,hashlib,json,os,re,shutil,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--branch',choices=['rekey-memory','rekey-live'],default='rekey-memory');args=parser.parse_args()
P=Path('work/uv310-wireguard');N=P/args.branch;R=P/'rng-provider';H=P/'control-hardening';W=P/'wg-port';S=W/'upstream/src'
CC=os.environ.get('LLVM_CLANG') or shutil.which('clang')
if not CC:raise SystemExit('Set LLVM_CLANG to an ARM-target-capable clang')
sources=[N/'native.c',R/'wireguard.c',S/'crypto.c',*sorted((ROOT/S/'crypto/refc').glob('*.c')),W/'runtime.c']
sources=[p.relative_to(ROOT) if p.is_absolute() else p for p in sources]
flags=['--target=arm-none-eabi','-mcpu=cortex-m3','-mthumb','-Oz','-ffreestanding','-fno-builtin','-fno-stack-protector','-ffunction-sections','-fdata-sections','-DBYTE_ORDER=1234','-DLITTLE_ENDIAN=1234','-DBOUNDED_REKEY_LAB','-fstack-usage']+['-I'+str(p) for p in [N,R,W/'build',W/'include',W,S]]
assert '203,0,113,7' in (ROOT/N/'native-config.h').read_text(),'Only public synthetic configuration permitted'
functions={};indices={};unknown=[]
with tempfile.TemporaryDirectory(prefix='uv310-stack-') as tmp:
 for i,p in enumerate(sources):
  out=Path(tmp)/f'unit{i}.s'
  subprocess.run([CC,*flags,'-S',str(p),'-o',str(out)],cwd=ROOT,check=True)
  sizes={}
  for line in out.with_suffix('.su').read_text().splitlines():
   loc,size,kind=line.split('\t');name=loc.rsplit(':',1)[-1];sizes[name]=(int(size),kind)
  current=None;edges={};indirect={}
  for line in out.read_text().splitlines():
   m=re.search(r'\.type\s+([\w.$]+),%function',line)
   if m:current=m[1];edges.setdefault(current,set());indirect.setdefault(current,set())
   if not current:continue
   m=re.match(r'\s*(blx?|b(?:\.w)?)\s+([\w.$]+)',line)
   if m:
    target=m[2]
    if re.fullmatch(r'r\d+|ip|lr|pc',target):indirect[current].add(target)
    elif not target.startswith('.L'):edges[current].add(target)
   if re.match(r'\s*\.size\s+',line):current=None
  for name,(size,kind) in sizes.items():
   key=str(p)+':'+name
   functions[key]={'source':str(p),'function':name,'frame_bytes':size,'allocation_kind':kind,'targets':sorted(edges.get(name,set())),'indirect_register_calls':sorted(indirect.get(name,set()))}
   indices.setdefault(name,[]).append(key)
 def resolve(caller,target):
  local=functions[caller]['source']+':'+target
  if local in functions:return local
  values=indices.get(target,[])
  return values[0] if len(values)==1 else None
 def walk(key,visited):
  f=functions[key];path=[key];best=0;unresolved=set();cycles=set();indirect=set(f['indirect_register_calls'])
  for name in f['targets']:
   target=resolve(key,name)
   if target is None:unresolved.add(name);continue
   if target in visited:cycles.add(target);continue
   child=walk(target,visited|{target});unresolved.update(child['unresolved']);cycles.update(child['cycles']);indirect.update(child['indirect'])
   if child['bytes']>best:best=child['bytes'];path=[key]+child['path']
  return {'bytes':f['frame_bytes']+best,'path':path,'unresolved':unresolved,'cycles':cycles,'indirect':indirect}
 roots={}
 for name in ['worker','intercept','emit_control','snapshot','memory_snapshot']:
  key=str(N/'native.c')+':'+name
  if key not in functions:continue
  x=walk(key,{key});roots[name]={'visible_chain_frame_sum_bytes':x['bytes'],'path':[{'function':functions[k]['function'],'frame_bytes':functions[k]['frame_bytes']} for k in x['path']],'unresolved_targets':sorted(x['unresolved']),'cycles':sorted(x['cycles']),'indirect_register_calls':sorted(x['indirect']),'is_complete_stack_bound':False}
 heap_calls=sorted({t for f in functions.values() for t in f['targets'] if t in ('malloc','calloc','realloc','free')})
 result={'branch':args.branch,'scope':'Static compiler-reported frames and visible direct-call paths only; no hardware, no QEMU execution, no private build','compiler':subprocess.check_output([CC,'--version'],text=True).splitlines()[0],'flags':flags[:flags.index('-I'+str(N))],'fixture_config_sha256':hashlib.sha256((ROOT/N/'native-config.h').read_bytes()).hexdigest(),'source_sha256':{str(p):hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in sources},'roots':roots,'largest_frames':sorted(functions.values(),key=lambda f:f['frame_bytes'],reverse=True)[:15],'compiled_function_count':len(functions),'direct_standard_heap_calls':heap_calls,'limitations':['Public fixed synthetic material; BOUNDED_REKEY_LAB code path, not previously deployed private binary','Visible sums conservatively add tail calls; no general upper or lower bound claimed','Assembly hook frames, exception stacking/nesting, stock callers, ROM callees and unresolved targets not included','Compiler frames include inlined work but do not measure runtime high-water or failure cause','No standard malloc call does not rule out native raw_alloc or stock driver allocations','No throughput, reboot safety or hardware stability established']}
 dest=ROOT/'.test-results';dest.mkdir(exist_ok=True);(dest/f'stack-audit-{args.branch}.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({'compiled_functions':len(functions),'roots':roots,'direct_standard_heap_calls':heap_calls},indent=2))
