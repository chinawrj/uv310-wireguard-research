"""HTTPS after renewal and bounded-lab expiry, same RAM session."""
from pathlib import Path
import json,subprocess,time
from live import status
out=Path('outputs/uv310-wireguard/evidence/rekey-live-post-rekey.json')
e={'statuses':[],'host_wireguard_crypto':False,'passed':False}
def save():out.write_text(json.dumps(e,indent=2)+'\n')
def snap():
 s=status();e['statuses'].append(s);save();return s
try:
 s=snap();assert s['R']['renewals']>=2 and not s['R']['stopped']
 r=subprocess.run(['curl','-4','--interface','en0','--noproxy','*','--connect-timeout','4','--max-time','12','-sS','-o','/dev/null','-w','%{http_code} %{local_ip} %{size_download} %{time_total}','https://www.wireguard.com/'],capture_output=True,text=True,timeout=15)
 after=snap();e['https']={'returncode':r.returncode,'result':r.stdout,'stderr':r.stderr,'native_tx_delta':after['A']['f_tx']-s['A']['f_tx'],'native_rx_delta':after['A']['f_rx']-s['A']['f_rx'],'dns_policy_scope':'Host resolver may use stock LAN DNS; HTTPS payload bound to en0 and native counters checked'};save()
 end=time.monotonic()+130
 while time.monotonic()<end and not after['R']['stopped']:
  time.sleep(min(20,max(1,(360000-after['R']['lab_elapsed'])/1000+1)))
  after=snap();print(json.dumps({'lab_elapsed':after['R']['lab_elapsed'],'stopped':after['R']['stopped'],'phase':after['A']['phase']}),flush=True)
 assert after['R']['stopped'] and after['A']['phase']==255
 before=after
 r=subprocess.run(['/sbin/ping','-b','en0','-S','192.168.100.100','-c','2','-t','4','192.168.123.1'],capture_output=True,text=True,timeout=7)
 after=snap();e['expiry']={'ping_returncode':r.returncode,'ping_output':r.stdout,'native_tx_delta':after['A']['f_tx']-before['A']['f_tx'],'drop_delta':after['A']['f_drop']-before['A']['f_drop'],'control_submitted_delta':after['E']['submitted']-before['E']['submitted'],'passed':r.returncode!=0 and after['A']['f_tx']==before['A']['f_tx'] and after['E']['submitted']==before['E']['submitted'] and after['A']['f_drop']>=before['A']['f_drop']+2}
 h=e['https'];e['passed']=h['returncode']==0 and h['result'].startswith('200 192.168.100.100 ') and h['native_tx_delta']>0 and h['native_rx_delta']>0 and e['expiry']['passed']
except Exception as ex:e['error']=repr(ex)
finally:save();print(json.dumps({'passed':e['passed'],'error':e.get('error')}),flush=True)
if not e['passed']:raise SystemExit(1)
