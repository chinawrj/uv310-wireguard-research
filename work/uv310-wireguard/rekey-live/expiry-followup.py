"""Finish expiry observation after transient AT ERROR; no restart or image write."""
from pathlib import Path
import json,subprocess,time
from live import status
O=Path('outputs/uv310-wireguard/evidence')
e={'statuses':[],'query_errors':[],'passed':False,'same_ram_session':True}
def snap():
 for attempt in range(3):
  try:
   s=status();e['statuses'].append(s);return s
  except Exception as ex:
   e['query_errors'].append(repr(ex))
   if attempt<2:time.sleep(1)
 raise RuntimeError('No status after bounded spaced retries')
try:
 before=snap();assert before['R']['stopped'] and before['A']['phase']==255
 r=subprocess.run(['/sbin/ping','-b','en0','-S','192.168.100.100','-c','2','-t','4','192.168.123.1'],capture_output=True,text=True,timeout=7)
 time.sleep(1);after=snap()
 e['expiry']={'ping_returncode':r.returncode,'ping_output':r.stdout,'native_tx_delta':after['A']['f_tx']-before['A']['f_tx'],'drop_delta':after['A']['f_drop']-before['A']['f_drop'],'control_submitted_delta':after['E']['submitted']-before['E']['submitted'],'passed':r.returncode!=0 and after['A']['f_tx']==before['A']['f_tx'] and after['E']['submitted']==before['E']['submitted'] and after['A']['f_drop']>=before['A']['f_drop']+2}
 e['passed']=e['expiry']['passed']
except Exception as ex:e['error']=repr(ex)
finally:(O/'rekey-live-expiry-followup.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e,indent=2))
if e['passed']:
 original=json.loads((O/'rekey-live-post-rekey.json').read_text());h=original['https']
 merged={'original_post_harness_passed':original['passed'],'original_post_harness_error_preserved':True,'https':h,'expiry':e['expiry'],'supplemental_expiry_source':'rekey-live-expiry-followup.json','passed':h['returncode']==0 and h['result'].startswith('200 192.168.100.100 ') and h['native_tx_delta']>0 and h['native_rx_delta']>0 and e['passed']}
 (O/'rekey-live-post-rekey-verified.json').write_text(json.dumps(merged,indent=2)+'\n')
else:raise SystemExit(1)
