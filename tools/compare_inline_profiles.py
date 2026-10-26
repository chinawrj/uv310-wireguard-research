"""Measure a fixed offline LTO build matrix, never select or deploy firmware."""
from pathlib import Path
import hashlib,json,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
profiles=[('default','none'),('default','safe'),('none','safe'),('wireguard','safe'),('native','safe'),('dhcp','safe'),('handshakes','safe'),('control','safe')]
rows=[]
for policy,icf in profiles:
 name=f'inline-profile-{policy}-{icf}.json';out=ROOT/'.test-results'/name
 subprocess.run([sys.executable,str(ROOT/'tools/audit_native_layout.py'),'--branch','rekey-dns-grow','--pool-bytes','256','--lto','--inline-policy',policy,'--icf',icf,'--stack-sizes','--out',str(out)],cwd=ROOT,check=True,capture_output=True)
 report=json.loads(out.read_text());assert len(report['branches'])==1
 branch=report['branches'][0];sections={s['name']:s for s in branch['sections']};roots=branch['linked_stack']['roots']
 rows.append({'inline_policy':policy,'icf':icf,'probe_bytes':sections['.probe']['bytes'],'state_bytes':sections['.state']['bytes'],'heap_start':branch['rounded_heap_start'],'historical_ceiling_margin_bytes':branch['ceiling_margin_bytes'],'worker_visible_chain_frame_sum_bytes':roots['worker']['visible_chain_frame_sum_bytes'],'intercept_visible_chain_frame_sum_bytes':roots['intercept']['visible_chain_frame_sum_bytes'],'report':name,'report_sha256':hashlib.sha256(out.read_bytes()).hexdigest()})
result={'scope':'Synthetic pool256 BOUNDED_REKEY_LAB native layout and visible linked frame comparison only; not functional tests or a runtime benchmark','branch':'rekey-dns-grow','profiles':rows,'selected_for_functional_validation':'control/safe','hardware_access':False,'deployment_ready':False,'source_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),ROOT/'tools/audit_native_layout.py',ROOT/'tools/linked_stack.py',ROOT/'work/uv310-wireguard/handshake-noinline.h']},'limitations':['Historical ceiling margin is not live heap capacity','No real private configuration, throughput, IRQ or radio behavior verified','Visible frame sums are not complete stack bounds','A favorable layout does not imply the profile is safe to deploy']}
(ROOT/'.test-results/inline-profile-comparison.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(rows,indent=2))
