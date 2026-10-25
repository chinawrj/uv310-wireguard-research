"""Read-only status or ordinary Wi-Fi traffic; never host-side WG encryption."""
from pathlib import Path
import argparse,json,re,socket,struct,subprocess,time
import usb.core,usb.util
FIELDS={
 'A':'phase err tx_count rx_count rng_pos init_time response_time receive_len worker_count f_tx f_rx f_drop f_out_bytes f_in_bytes allocation_failures clock'.split(),
 'E':'attempts control_ready control_kind control_packet submitted freed free_payload_delta free_header_delta keepalive_tx last_send source_context destination_context send_ipsr send_mask control_errors clock'.split(),
 'R':'renewals handshake_failures rng_failed pool_bytes session_start key_age current_index previous_index current_valid previous_valid lab_started lab_elapsed lab_limit stopped allocation_failures clock'.split()}
def status(memory=False):
 d=usb.core.find(idVendor=0x05c6,idProduct=0x6000);assert d is not None
 assert {i.bInterfaceNumber:sorted(x.bEndpointAddress for x in i) for i in d.get_active_configuration()}=={0:[1,129,130],1:[2,131],2:[3,132],3:[4,133],4:[5,134]}
 usb.util.claim_interface(d,1);pages={};observed=[]
 def cmd(s):
  d.write(2,(s+'\r').encode(),timeout=1000);b=b'';end=time.monotonic()+5
  while time.monotonic()<end:
   try:b+=bytes(d.read(0x83,8192,timeout=200))
   except usb.core.USBTimeoutError:continue
   if b'\r\nOK\r\n' in b or b'\r\nERROR\r\n' in b:return b
  raise TimeoutError('AT reply timed out: '+s)
 try:
  identity=cmd('AT^PROJECTNAME?');assert b'MDM9600' in identity and b'UV310' in identity
  for _ in range(9):
   b=cmd('AT+WL=wl ver');m=re.search(rb'([AER])=([0-9a-f]{8}(?:,[0-9a-f]{8}){15})',b)
   observed.append(b.decode('ascii','replace'))
   if m:
    name=m[1].decode();pages[name]=dict(zip(FIELDS[name],[int(v,16) for v in m[2].split(b',')]))
   if len(pages)==3:break
  assert len(pages)==3,('Missing rekey pages',list(pages),observed)
  if memory:pages['memory_response']=cmd('AT+WL=wl memuse').decode('ascii','replace')
  return pages
 finally:usb.util.release_interface(d,1);usb.util.dispose_resources(d)

def main():
 ap=argparse.ArgumentParser();ap.add_argument('mode',choices=['status','traffic']);args=ap.parse_args()
 out=Path('outputs/uv310-wireguard/evidence/rekey-live-'+args.mode+'.json')
 e={'host_wireguard_crypto':False,'special_trigger_packets':0,'statuses':[],'traffic':[],'passed':False}
 def save():out.write_text(json.dumps(e,indent=2)+'\n')
 def snap(memory=False):
  s=status(memory);s['host_monotonic']=round(time.monotonic(),3);e['statuses'].append(s);save()
  print(json.dumps({'phase':s['A']['phase'],'renewals':s['R']['renewals'],'key_age':s['R']['key_age'],'lab_elapsed':s['R']['lab_elapsed'],'tx':s['A']['f_tx'],'rx':s['A']['f_rx'],'rng_pos':s['A']['rng_pos'],'errors':s['E']['control_errors']}),flush=True);return s
 try:
  first=snap(False)
  if args.mode=='status':e['passed']=True;return
  ip=subprocess.check_output(['ipconfig','getifaddr','en0'],text=True).strip();assert ip=='192.168.100.100'
  assert 'interface: en0' in subprocess.check_output(['route','-n','get','192.168.100.1'],text=True)
  e['interface']='en0';e['client_ip']=ip
  def ping(count=1):
   r=subprocess.run(['/sbin/ping','-b','en0','-S',ip,'-c',str(count),'-t',str(count+3),'192.168.123.1'],capture_output=True,text=True,timeout=count+6)
   row={'kind':'icmp','returncode':r.returncode,'elapsed':round(time.monotonic()-started,3),'stdout':r.stdout,'stderr':r.stderr};e['traffic'].append(row);save();return row
  def dns():
   q=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);q.setsockopt(socket.IPPROTO_IP,25,socket.if_nametoindex('en0'));q.bind((ip,0));q.settimeout(4)
   ident=0x6b32;payload=struct.pack('!6H',ident,0x0100,1,0,0,0)+b'\x03www\x09wireguard\x03com\0\0\1\0\1';row={'kind':'udp_dns','elapsed':round(time.monotonic()-started,3),'passed':False}
   try:
    q.sendto(payload,('1.1.1.1',53));b,addr=q.recvfrom(4096);id2,flags,qd,an,ns,ar=struct.unpack_from('!6H',b)
    row.update(passed=addr==('1.1.1.1',53) and id2==ident and bool(flags&0x8000) and flags&15==0 and an>0,bytes=len(b),answers=an)
   except Exception as ex:row['error']=str(ex)
   finally:q.close()
   e['traffic'].append(row);save();return row
  started=time.monotonic();ping(6);s=snap(False)
  assert s['A']['phase']==9 and s['R']['current_valid'] and s['A']['f_tx'] and s['A']['f_rx'],'Initial live handshake/forwarding failed'
  e['first_live_index']=s['R']['current_index'];seen={s['R']['current_index']};last_renew=s['R']['renewals'];dns()
  # Continuously provide bounded ordinary traffic across two real key renewals.
  while time.monotonic()-started<310 and s['R']['renewals']<2:
   ping(3);s=snap();seen.add(s['R']['current_index'])
   assert not s['R']['stopped'] and not s['R']['rng_failed']
   if s['R']['renewals']>last_renew:
    dns();last_renew=s['R']['renewals'];s=snap(False)
  lastping=ping(3);lastdns=dns();final=snap(False)
  e.update(distinct_current_indices=len(seen),renewals=final['R']['renewals'],elapsed_seconds=round(time.monotonic()-started,3))
  e['passed']=final['R']['renewals']>=2 and len(seen)>=3 and lastping['returncode']==0 and lastdns['passed'] and final['E']['submitted']==final['E']['freed'] and not final['E']['control_packet'] and not final['E']['control_errors'] and not final['R']['handshake_failures']
 except Exception as ex:e['error']=repr(ex)
 finally:save();print(json.dumps({'passed':e['passed'],'error':e.get('error'),'renewals':e.get('renewals')}),flush=True)
 if not e['passed']:raise SystemExit(1)
if __name__=='__main__':main()
