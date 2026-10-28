"""Test proposed N telemetry in an isolated synthetic copy; no deployed-source change."""
from pathlib import Path
import hashlib,json,os,re,shutil,subprocess,sys,tempfile
ROOT=Path(__file__).resolve().parents[1];N=Path('work/uv310-wireguard/rekey-dns-grow')
budget=json.loads((ROOT/'.test-results/dns-telemetry-budget.json').read_text())
for p,h in budget['source_sha256'].items():assert hashlib.sha256((ROOT/p).read_bytes()).hexdigest()==h,p
s=(ROOT/N/'native.c').read_text();p=budget['compact_proposal'];s=s.replace(p['insert_after'],p['insert_after']+p['insert'])
for a,b in p['replacements'].items():s=s.replace(a,b)
s=s.replace(';v[3]=2;',';').replace('"AERMD"[status_page]','"AERMN"[status_page]')
for page in (2,3,4):s=s.replace(f' if(status_page=={page})',f' else if(status_page=={page})')
assert hashlib.sha256(s.encode()).hexdigest()==budget['exclusive_proposal']['candidate_native_sha256']
CANDIDATE=Path('work/uv310-wireguard/rekey-dns-observe/native.c')
assert (ROOT/CANDIDATE).read_text()==s,'Committed candidate differs from audited transformation'
s=(ROOT/CANDIDATE).read_text()
extra=r'''
for name,old,new in [('telemetry_swap','v[0]=dhcp_rewrites;v[1]=dhcp_rejects;','v[0]=dhcp_rejects;v[1]=dhcp_rewrites;'),('telemetry_rotation','if(++status_page==5)','if(++status_page==4)'),('telemetry_tag','"AERMN"','"AERMD"'),('telemetry_clear','v[0]=dhcp_rewrites;','v[0]=dhcp_rewrites=0;'),('telemetry_nul','i==15?0:',"i==15?'x':")]:
 source=(N/'native.c').read_text();assert source.count(old)==1
 mutant=B/(name+'.c');mutant.write_text(source.replace(old,new));bad=obj(mutant,'native')
 out,_,_=link_run(name,bad,['-DTEST_BASELINE']);assert 'FAIL line=' in out and 'PASS renewal' not in out,(name,out)
 negative.append({'mutation':name,'detected':True})
'''
with tempfile.TemporaryDirectory(prefix='uv310-telemetry-test-') as tmp:
 t=Path(tmp).resolve();shutil.copytree(ROOT/'work',t/'work',ignore=shutil.ignore_patterns('private','private-*','__pycache__','*.pyc','*.o','*.elf','*.bin'))
 (t/N/'native.c').write_text(s)
 f=t/N/'native-config.h';h=f.read_text();m=re.search(r'(RANDOM_POOL\[\]=\{)([^}]+)(\})',h);assert m
 f.write_text(h[:m.start(2)]+','.join(m.group(2).split(',')[:256])+h[m.end(2):])
 f=t/N/'tests.c';h=f.read_text();assert h.count('int tests(void){')==1
 f.write_text(h.replace('int tests(void){','#include "telemetry-check.c"\nint tests(void){\n int telemetry=telemetry_check();if(telemetry)return telemetry;'))
 f=t/N/'test-build.py';h=f.read_text();assert h.count('result={')==1;f.write_text(h.replace('result={',extra+'\nresult={'))
 (t/'outputs/uv310-wireguard/evidence').mkdir(parents=True)
 env=dict(os.environ,UV310_TEST_LTO='1',UV310_TEST_POOL_BYTES='256',UV310_TEST_BUILD_PROFILE='control-icf')
 run=subprocess.run([sys.executable,str(t/N/'test-build.py')],cwd=t,env=env,capture_output=True,text=True)
 if run.returncode:raise SystemExit((run.stdout+run.stderr)[-5000:])
 report=json.loads((t/'outputs/uv310-wireguard/evidence/rekey-dns-grow-lto-pool256-control-icf-tests.json').read_text())
 assert len(report['suites'])==67 and all(x['passed'] for x in report['suites'])
 assert len(report['negative_controls'])==26 and all(x['detected'] for x in report['negative_controls'])
 report['scope']='Committed rekey-dns-observe candidate synthetic pool256 regression, 15 snapshot checks before each scenario; not hardware verified'
 report['derived_source_sha256']=report.pop('source_sha256')
 report['source_sha256']={str(p):hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in [CANDIDATE,N/'native.c',N/'tests.c',N/'test-build.py',N/'native-config.h',N/'telemetry-check.c',Path('tools/test_dns_telemetry.py'),Path('tools/evaluate_dns_telemetry.py')]}
 report['telemetry_checks']=['AERMN rotation for three cycles','16 hex words and separators','N counters and inherited A fields','zero and uint32 maximum representation','NUL and untouched buffer suffix','no counter reset, RNG consumption, allocation or phase change']
 (ROOT/'.test-results/dns-telemetry-tests.json').write_text(json.dumps(report,indent=2)+'\n')
 print('PASS proposed N page: 67 regression scenarios, 26 negative controls; production source unchanged')
