"""Re-run synthetic Cortex-M3 tests in isolation; no hardware/network access."""
from pathlib import Path
import json,os,shutil,subprocess,sys,tempfile
ROOT=Path(__file__).resolve().parents[1]
branch=sys.argv[1] if len(sys.argv)>1 else 'rekey-memory'
if branch not in ('rekey-memory','rekey-live','rekey-pressure','rekey-dns','rekey-dns-grow'):raise SystemExit('Unknown offline suite')
with tempfile.TemporaryDirectory(prefix='uv310-offline-') as tmp:
 t=Path(tmp);shutil.copytree(ROOT/'work',t/'work',ignore=shutil.ignore_patterns('__pycache__','*.pyc','*.o','*.elf','*.bin','private','private-*'))
 (t/'outputs/uv310-wireguard/evidence').mkdir(parents=True)
 r=subprocess.run([sys.executable,f'work/uv310-wireguard/{branch}/test-build.py'],cwd=t)
 if r.returncode:raise SystemExit(r.returncode)
 src=t/f'outputs/uv310-wireguard/evidence/{branch}-tests.json'
 data=json.loads(src.read_text());expected={'rekey-memory':32,'rekey-live':20,'rekey-pressure':45,'rekey-dns':62,'rekey-dns-grow':67}[branch]
 assert len(data['suites'])==expected and all(x['passed'] for x in data['suites'])
 negatives={'rekey-memory':6,'rekey-live':3,'rekey-pressure':12,'rekey-dns':18,'rekey-dns-grow':20}[branch]
 assert len(data['negative_controls'])==negatives and all(x['detected'] for x in data['negative_controls'])
 dest=ROOT/'.test-results';dest.mkdir(exist_ok=True)
 (dest/src.name).write_bytes(src.read_bytes())
 print(f'PASS: {expected} synthetic suites, {negatives} negative controls detected. No USB/network/firmware deployment.')
 print('Result:',dest/src.name)
