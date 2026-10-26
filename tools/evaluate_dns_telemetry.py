"""Offline resource experiment for a proposed D page; never builds an image or deploys."""
from pathlib import Path
import hashlib,json,shutil,subprocess,sys,tempfile
ROOT=Path(__file__).resolve().parents[1]
NATIVE=Path('work/uv310-wireguard/rekey-dns-grow/native.c')
INSERT=''' if(status_page==4){
  for(u32 i=0;i<15;i++)v[i]=0;
  v[0]=1;v[1]=dhcp_rewrites;v[2]=dhcp_rejects;v[3]=lan_dns_drops;v[15]=W(0x267c);
 }
'''
original=(ROOT/NATIVE).read_text()
anchor=' if(status_page==3)memory_snapshot(v);\n'
assert original.count(anchor)==1
assert original.count('"AERM"[status_page]')==1
assert original.count('(status_page+1)%4')==1
candidate=original.replace(anchor,anchor+INSERT).replace('"AERM"[status_page]','"AERMD"[status_page]').replace('(status_page+1)%4','(status_page+1)%5')
compact_insert=""" if(status_page==4){
  v[0]=dhcp_rewrites;v[1]=dhcp_rejects;v[2]=lan_dns_drops;v[3]=2;
 }
"""
compact=original.replace(anchor,anchor+compact_insert).replace('"AERM"[status_page]','"AERMD"[status_page]').replace('status_page=(status_page+1)%4;','if(++status_page==5)status_page=0;')
compact_tagged=compact.replace(";v[3]=2;", ";").replace('"AERMD"[status_page]','"AERMN"[status_page]')
exclusive=compact_tagged
for page in (2,3,4):exclusive=exclusive.replace(f" if(status_page=={page})",f" else if(status_page=={page})")
reports={}
with tempfile.TemporaryDirectory(prefix='uv310-dns-telemetry-') as tmp:
 t=Path(tmp).resolve()
 for sub in ('work','tools'):
  shutil.copytree(ROOT/sub,t/sub,ignore=shutil.ignore_patterns('private','private-*','__pycache__','*.pyc','*.o','*.elf','*.bin'))
 for name,source in [('baseline',original),('proposed-d-page',candidate),('compact-d-page',compact),('tagged-n-page',compact_tagged),('exclusive-n-page',exclusive)]:
  (t/NATIVE).write_text(source)
  out=t/(name+'.json')
  run=subprocess.run([sys.executable,str(t/'tools/audit_native_layout.py'),'--branch','rekey-dns-grow','--pool-bytes','256','--lto','--inline-policy','control','--icf','safe','--stack-sizes','--out',str(out)],cwd=t,capture_output=True,text=True)
  if run.returncode:raise SystemExit(run.stderr)
  reports[name]=json.loads(out.read_text())
rows=[]
for name,report in reports.items():
 b=report['branches'][0];s={x['name']:x['bytes'] for x in b['sections']}
 rows.append({'variant':name,'probe_bytes':s['.probe'],'state_bytes':s['.state'],'heap_start':b['rounded_heap_start'],'margin_bytes':b['ceiling_margin_bytes'],'stack_roots':{k:v['visible_chain_frame_sum_bytes'] for k,v in b['linked_stack']['roots'].items()}})
result={'scope':'Resource-only proposed DNS telemetry page; no functional validation, no runtime or firmware output','rows':rows,'reports':reports,'candidate_patch':{'insert_after':anchor,'insert':INSERT,'replacements':{'"AERM"[status_page]':'"AERMD"[status_page]','(status_page+1)%4':'(status_page+1)%5'},'candidate_native_sha256':hashlib.sha256(candidate.encode()).hexdigest()},'source_sha256':{str(p):hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in [NATIVE,Path('tools/evaluate_dns_telemetry.py'),Path('tools/audit_native_layout.py'),Path('tools/linked_stack.py')]},'page_fields':['schema_version','dhcp_rewrites','gateway_udp_rejects','lan_dns_guard_drops']+['reserved_'+str(i) for i in range(4,15)]+['clock'],'limitations':['All values are unsigned 32-bit, counters wrap; no cross-page atomicity or boot identity','dhcp_rejects also includes non-writable gateway UDP; not a pure DHCP error count','lan_dns_drops includes malformed or fragmented LAN TCP/UDP; not only identified DNS','No observed-candidate counter: all-zero cannot prove absent hook','Forwarding counters on page A are aggregate, not DNS-specific','Existing observer requires A/E/R/M only; D needs explicit opt-in and schema validation','Resource experiment only; serialization and negative tests are required before integration','Historical layout margin is not actual heap or complete stack bound']}
result['compact_proposal']={'insert_after':anchor,'insert':compact_insert,'replacements':{'"AERM"[status_page]':'"AERMD"[status_page]','status_page=(status_page+1)%4;':'if(++status_page==5)status_page=0;'},'candidate_native_sha256':hashlib.sha256(compact.encode()).hexdigest(),'fields':['dhcp_rewrites','gateway_udp_rejects','lan_dns_guard_drops','schema_version_2','rng_pos','init_time','response_time','receive_len','worker_count','f_tx','f_rx','f_drop','f_out_bytes','f_in_bytes','allocation_failures','clock']}
result['tagged_proposal']={'candidate_native_sha256':hashlib.sha256(compact_tagged.encode()).hexdigest(),'derivation':'compact_proposal with v[3]=2 removed and page tag D changed to N; tag N identifies this fixed schema','fields':result['compact_proposal']['fields'][:3]+['rx_count']+result['compact_proposal']['fields'][4:]}
result['exclusive_proposal']={'candidate_native_sha256':hashlib.sha256(exclusive.encode()).hexdigest(),'derivation':'tagged_proposal with mutually exclusive page 2/3/4 branches written as else if','fields':result['tagged_proposal']['fields']}
d=ROOT/'.test-results';d.mkdir(exist_ok=True)
(d/'dns-telemetry-budget.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(rows,indent=2))
