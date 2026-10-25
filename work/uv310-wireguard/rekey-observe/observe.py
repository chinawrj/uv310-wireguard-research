"""Bounded read-only UV310 status diagnostics. No restart or image operations."""
from pathlib import Path
import argparse,datetime,ipaddress,json,re,subprocess,time
import usb.core,usb.util
NORMAL={0:[1,129,130],1:[2,131],2:[3,132],3:[4,133],4:[5,134]}
FIELDS={
'A':'phase err tx_count rx_count rng_pos init_time response_time receive_len worker_count f_tx f_rx f_drop f_out_bytes f_in_bytes allocation_failures clock'.split(),
'E':'attempts control_ready control_kind control_packet submitted freed free_payload_delta free_header_delta keepalive_tx last_send source_context destination_context send_ipsr send_mask control_errors clock'.split(),
'R':'renewals handshake_failures rng_failed pool_bytes session_start key_age current_index previous_index current_valid previous_valid lab_started lab_elapsed lab_limit stopped allocation_failures clock'.split(),
'M':'arena_bytes allocated_payload allocated_headers peak_payload allocation_failures free_payload largest_free_block free_nodes free_list_valid stack_sentinel_unused stack_floor stack_top stack_bounds_valid clock entry_primask reserved'.split()}
class ObservationError(Exception):
 def __init__(self,code,**details):self.code=code;self.details=details;super().__init__(code)
 def record(self):return {'code':self.code,**self.details}
def usb_error(ex,stage):
 # Preserve numeric cause, never device serials or arbitrary backend response text.
 return ObservationError('USB_IO_ERROR',stage=stage,errno=getattr(ex,'errno',None),backend_error_code=getattr(ex,'backend_error_code',None),exception_type=type(ex).__name__)
def query(d,command,clock=time.monotonic):
 if command not in ('AT^PROJECTNAME?','AT+WL=wl ver'):raise ValueError('Query not allowed')
 try:
  payload=(command+'\r').encode();n=d.write(2,payload,timeout=1000)
  if n!=len(payload):raise ObservationError('SHORT_WRITE',command=command,expected=len(payload),actual=n)
  data=bytearray();deadline=clock()+5
  for _ in range(64):
   if clock()>=deadline:break
   try:part=bytes(d.read(0x83,8192,timeout=200))
   except usb.core.USBTimeoutError:continue
   data.extend(part)
   if len(data)>8192:raise ObservationError('REPLY_LIMIT',command=command,bytes=len(data))
   if b'\r\nERROR\r\n' in data:raise ObservationError('AT_ERROR',command=command,bytes=len(data))
   if b'\r\nOK\r\n' in data:return bytes(data)
  raise ObservationError('AT_TIMEOUT',command=command,bytes=len(data))
 except usb.core.USBError as ex:raise usb_error(ex,'query') from ex

def status(pause=time.sleep):
 d=None;claimed=False;stage='find';cleanup=[];error=None;result=None
 try:
  d=usb.core.find(idVendor=0x05c6,idProduct=0x6000)
  if d is None:raise ObservationError('DEVICE_ABSENT',vid='05c6',pid='6000')
  stage='configuration';top={i.bInterfaceNumber:sorted(e.bEndpointAddress for e in i) for i in d.get_active_configuration()}
  if top!=NORMAL:raise ObservationError('TOPOLOGY_MISMATCH',observed=top,expected=NORMAL)
  stage='claim';usb.util.claim_interface(d,1);claimed=True
  # Drain stale bytes with an independent hard bound. No writes in this step.
  stage='drain'
  for n in range(8):
   try:d.read(0x83,8192,timeout=25)
   except usb.core.USBTimeoutError:break
  else:raise ObservationError('STALE_INPUT_LIMIT')
  identity=query(d,'AT^PROJECTNAME?')
  if not re.search(rb'\^PROJECTNAME:\s*MDM9600\s+UV310\s*\r',identity):raise ObservationError('IDENTITY_MISMATCH')
  pages={};last_clock=None;counts={'status_queries':0,'unrecognized_replies':0}
  for _ in range(12):
   pause(.15);raw=query(d,'AT+WL=wl ver');counts['status_queries']+=1
   m=re.search(rb'([AERM])=([0-9a-f]{8}(?:,[0-9a-f]{8}){15})(?![0-9a-f,])',raw)
   if not m:counts['unrecognized_replies']+=1
   else:
    name=m[1].decode();page=dict(zip(FIELDS[name],[int(v,16) for v in m[2].split(b',')]))
    now=page['clock']
    if last_clock is not None and ((now-last_clock)&0xffffffff)>=0x80000000:
     raise ObservationError('CLOCK_DISCONTINUITY',previous=last_clock,current=now,page=name)
    last_clock=now;pages[name]=page
   if len(pages)==4:break
  if len(pages)!=4:raise ObservationError('MISSING_STATUS_PAGES',received=sorted(pages),**counts)
  if not pages['M']['free_list_valid'] or not pages['M']['stack_bounds_valid']:raise ObservationError('MEMORY_SNAPSHOT_INVALID',memory=pages['M'])
  result={'pages':pages,'queries':counts,'atomic_cross_page_snapshot':False}
 except ObservationError as ex:error=ex
 except usb.core.USBError as ex:error=usb_error(ex,stage)
 finally:
  if d is not None:
   if claimed:
    try:usb.util.release_interface(d,1)
    except usb.core.USBError as ex:cleanup.append(usb_error(ex,'release').record())
   try:usb.util.dispose_resources(d)
   except usb.core.USBError as ex:cleanup.append(usb_error(ex,'dispose').record())
 if error:
  if cleanup:error.details['cleanup_errors']=cleanup
  raise error
 if cleanup:raise ObservationError('CLEANUP_ERROR',cleanup_errors=cleanup)
 return result

def host_state():
 def read(args):
  try:
   r=subprocess.run(args,capture_output=True,text=True,timeout=3)
   return r.returncode,r.stdout
  except (OSError,subprocess.TimeoutExpired):return None,''
 rc,out=read(['/usr/sbin/ipconfig','getifaddr','en0']);ip=out.strip()
 try:
  ip=str(ipaddress.IPv4Address(ip)) if rc==0 else None
 except ipaddress.AddressValueError:ip=None
 rc2,out=read(['/sbin/route','-n','get','192.168.100.1']);m=re.search(r'interface:\s*(\w+)',out)
 return {'interface':'en0','source_ip':ip,'source_ip_exit':rc,'matches_lab_client':ip=='192.168.100.100','gateway_route_interface':m[1] if m and rc2==0 else None,'route_exit':rc2}

def collect():
 result={'scope':'read-only AT/USB and local host diagnostics; no traffic or restart','utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'host_before':host_state(),'status_read_ok':False}
 try:result['status']=status();result['status_read_ok']=True
 except ObservationError as ex:result['error']=ex.record()
 except Exception as ex:result['error']={'code':'UNEXPECTED_OBSERVER_ERROR','exception_type':type(ex).__name__}
 result['host_after']=host_state()
 before=result['host_before'];after=result['host_after']
 result['host_network_changed']=any(before.get(k)!=after.get(k) for k in ('source_ip','gateway_route_interface'))
 result['lab_client_ready']=all(x.get('matches_lab_client') and x.get('gateway_route_interface')=='en0' for x in (before,after))
 result['vpn_or_rekey_verified_by_this_tool']=False
 return result

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path,required=True);a=ap.parse_args()
 # Exclusive-create prevents replacing earlier experiments, including on failure.
 with a.out.open('x') as f:
  result=collect();json.dump(result,f,indent=2);f.write('\n')
 print(json.dumps({'status_read_ok':result['status_read_ok'],'error':result.get('error'),'lab_client_ready':result['lab_client_ready'],'host_network_changed':result['host_network_changed']}))
 return 0 if result['status_read_ok'] else 2
if __name__=='__main__':raise SystemExit(main())
