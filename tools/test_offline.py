"""Re-run synthetic Cortex-M3 tests in isolation; no hardware/network access."""
from pathlib import Path
import hashlib,json,os,re,shutil,subprocess,sys,tempfile
ROOT=Path(__file__).resolve().parents[1]
branch=sys.argv[1] if len(sys.argv)>1 else 'rekey-memory'
if branch not in ('rekey-memory','rekey-live','rekey-pressure','rekey-dns','rekey-dns-grow'):raise SystemExit('Unknown offline suite')
lto=os.environ.get('UV310_TEST_LTO','0')=='1'
if lto and branch!='rekey-dns-grow':raise SystemExit('LTO suite only supported for rekey-dns-grow')
pool=int(os.environ.get('UV310_TEST_POOL_BYTES','1024'))
if pool not in (256,1024) or (pool==256 and branch!='rekey-dns-grow'):raise SystemExit('Unsupported pool size/suite')
suffix=('-lto' if lto else '')+('-pool256' if pool==256 else '')
with tempfile.TemporaryDirectory(prefix='uv310-offline-') as tmp:
 t=Path(tmp);shutil.copytree(ROOT/'work',t/'work',ignore=shutil.ignore_patterns('__pycache__','*.pyc','*.o','*.elf','*.bin','private','private-*'))
 if pool==256:
  fixture=t/f'work/uv310-wireguard/{branch}/native-config.h';header=fixture.read_text()
  match=re.search(r'(RANDOM_POOL\[\]=\{)([^}]+)(\})',header);assert match
  values=match.group(2).split(',');assert len(values)==1024
  fixture.write_text(header[:match.start(2)]+','.join(values[:pool])+header[match.end(2):])
 (t/'outputs/uv310-wireguard/evidence').mkdir(parents=True)
 r=subprocess.run([sys.executable,f'work/uv310-wireguard/{branch}/test-build.py'],cwd=t)
 if r.returncode:raise SystemExit(r.returncode)
 src=t/f'outputs/uv310-wireguard/evidence/{branch}{suffix}-tests.json'
 data=json.loads(src.read_text());assert data.get('lto_enabled',False)==lto
 expected={'rekey-memory':32,'rekey-live':20,'rekey-pressure':45,'rekey-dns':62,'rekey-dns-grow':67}[branch]
 assert len(data['suites'])==expected and all(x['passed'] for x in data['suites'])
 negatives={'rekey-memory':6,'rekey-live':3,'rekey-pressure':12,'rekey-dns':18,'rekey-dns-grow':20}[branch]
 if pool==256:negatives+=1
 assert len(data['negative_controls'])==negatives and all(x['detected'] for x in data['negative_controls'])
 if pool==256:
  config=f'work/uv310-wireguard/{branch}/native-config.h'
  data['effective_fixture_config_sha256']=data['source_sha256'][config]
  data['source_sha256'][config]=hashlib.sha256((ROOT/config).read_bytes()).hexdigest()
  data['fixture_derivation']='Use first 256 bytes of public synthetic 1024-byte RANDOM_POOL; source hashes record original fixture, effective hash records compiled fixture'
 data['source_sha256']['tools/test_offline.py']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
 dest=ROOT/'.test-results';dest.mkdir(exist_ok=True)
 (dest/src.name).write_text(json.dumps(data,indent=2)+'\n')
 print(f'PASS: {expected} synthetic suites, {negatives} negative controls detected. No USB/network/firmware deployment.')
 print('Result:',dest/src.name)
