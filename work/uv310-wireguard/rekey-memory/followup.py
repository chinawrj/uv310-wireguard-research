"""Continue the SAME RAM session through transient read-only AT query failures."""
from pathlib import Path
import json,socket,struct,subprocess,time
from live import status
out=Path('outputs/uv310-wireguard/evidence/rekey-memory-followup.json')
e={'host_wireguard_crypto':False,'statuses':[],'traffic':[],'query_failures':[],'passed':False}
start=time.monotonic()
def save():out.write_text(json.dumps(e,indent=2)+'\n')
def probe():
 ip=subprocess.check_output(['ipconfig','getifaddr','en0'],text=True).strip();assert ip=='192.168.100.100'
 r=subprocess.run(['/sbin/ping','-b','en0','-S',ip,'-c','4','-t','7','192.168.123.1'],capture_output=True,text=True,timeout=10)
 row={'elapsed':round(time.monotonic()-start,3),'ping_returncode':r.returncode,'ping_output':r.stdout}
 q=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);q.setsockopt(socket.IPPROTO_IP,25,socket.if_nametoindex('en0'));q.bind((ip,0));q.settimeout(3)
 try:
  q.sendto(bytes.fromhex('6b3301000001000000000000')+b'\x03www\x09wireguard\x03com\0\0\1\0\1',('1.1.1.1',53));b,addr=q.recvfrom(4096)
  ident,flags,qd,an,ns,ar=struct.unpack_from('!6H',b);row['dns_passed']=addr==('1.1.1.1',53) and ident==0x6b33 and flags&0x8000!=0 and flags&15==0 and an>0
 except Exception as ex:row['dns_error']=str(ex);row['dns_passed']=False
 finally:q.close()
 e['traffic'].append(row);save();return row
try:
 while time.monotonic()-start<240:
  row=probe()
  try:
   s=status();assert s['M']['free_list_valid'] and s['M']['stack_bounds_valid'],'Memory snapshot rejected';s['elapsed']=round(time.monotonic()-start,3);e['statuses'].append(s)
   print(json.dumps({'renewals':s['R']['renewals'],'phase':s['A']['phase'],'age':s['R']['key_age'],'lab_elapsed':s['R']['lab_elapsed'],'ping':row['ping_returncode'],'dns':row['dns_passed'],'allocation_failures':s['A']['allocation_failures'],'free_payload':s['M']['free_payload'],'largest':s['M']['largest_free_block'],'stack_unused':s['M']['stack_sentinel_unused']}),flush=True)
   if s['R']['stopped']:break
   if s['R']['renewals']>=1 and row['ping_returncode']==0 and row['dns_passed']:
    finalprobe=probe();final=status();e['statuses'].append(final)
    e['passed']=finalprobe['ping_returncode']==0 and finalprobe['dns_passed'] and final['R']['renewals']>=1 and final['R']['current_valid'] and not final['R']['rng_failed'] and final['E']['submitted']==final['E']['freed'] and not final['E']['control_packet'] and not final['E']['control_errors']
    break
  except Exception as ex:
   e['query_failures'].append({'elapsed':round(time.monotonic()-start,3),'error':repr(ex)});print('Transient status query failure; retain ordinary-traffic evidence',flush=True)
  save();time.sleep(6)
except Exception as ex:e['error']=repr(ex)
finally:e['elapsed_seconds']=round(time.monotonic()-start,3);save();print(json.dumps({'passed':e['passed'],'status_samples':len(e['statuses']),'query_failures':len(e['query_failures'])}),flush=True)
if not e['passed']:raise SystemExit(1)
