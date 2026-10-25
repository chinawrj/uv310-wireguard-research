"""Identity/hash-pinned cold-start control using verified DIAG->DMSS RESET.
Candidate workflow calls the separately verified EFS restore tool after boot.
Only ejects uniquely identified read-only UV310 CD.
"""
import argparse,json,time,subprocess,plistlib,re
from pathlib import Path
import usb.core,usb.util
import efs_rekey as p
arg=argparse.ArgumentParser();arg.add_argument('phase',choices=['candidate','restored']);phase=arg.parse_args().phase
e={'phase':phase,'software_restart':True, 'physical_power_removal':False,'direct_file_writes':False,'candidate_phase_calls_efs_restore':phase=='candidate','events':[]};out=Path('outputs/uv310-wireguard/evidence/rekey-live-cold-'+phase+'.json')
def close(d,i):
 try:usb.util.release_interface(d,i)
 except usb.core.USBError:pass
 usb.util.dispose_resources(d)
def exchange(d,epout,epin,payload,timeout=2):
 d.write(epout,b'\x7e'+p.fs.encode(payload),timeout=1000);end=time.monotonic()+timeout;buf=b''
 while time.monotonic()<end:
  try:buf+=bytes(d.read(epin,8192,timeout=200))
  except usb.core.USBTimeoutError:continue
  while b'\x7e' in buf:
   raw,buf=buf.split(b'\x7e',1);r=p.fs.decode(raw)
   if r:return r
 return None
def waitmode(pid,n,seconds=30):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  d=usb.core.find(idVendor=0x05c6,idProduct=pid)
  if d is not None:
   try:
    if len(list(d.get_active_configuration()))==n:
     top={i.bInterfaceNumber:sorted(x.bEndpointAddress for x in i) for i in d.get_active_configuration()}
     expected={5:{0:[1,129,130],1:[2,131],2:[3,132],3:[4,133],4:[5,134]},4:{0:[1,129],1:[2,130],2:[3,131],3:[4,132]}}
     if n in expected:assert top==expected[n]
     return d
   except usb.core.USBError:pass
  time.sleep(1)
 raise TimeoutError('USB mode not observed '+hex(pid)+' / '+str(n))
try:
 assert not out.exists(),'Do not repeat a keyed-image boot'
 d=p.verify_device();p.fs.d=d;usb.util.claim_interface(d,3)
 try:
  data,_=p.read(p.ACTIVE);h=p.sha(data);assert h==(p.CANDIDATE if phase=='candidate' else p.ORIGINAL)
  e['active_before_sha256']=h
  r=exchange(d,4,0x85,b'\x3a');e['diag_enter_reply']=r.hex() if r else None
 finally:close(d,3)
 d=waitmode(0x6000,4);assert [x.bEndpointAddress for x in d.get_active_configuration()[(3,0)]]==[0x84,4]
 usb.util.claim_interface(d,3)
 try:
  assert exchange(d,4,0x84,b'\x06')==b'\x02'
  assert exchange(d,4,0x84,b'\x07')==bytes.fromhex('0807014000000000')
  e['dmss_parameters_verified']=True
  r=exchange(d,4,0x84,b'\x0a');e['reset_reply']=r.hex() if r else None
 finally:close(d,3)
 d=waitmode(0xf000,1);usb.util.dispose_resources(d)
 time.sleep(6)
 e['cd_settle_wait_seconds']=6
 # Wait for macOS disk publication, always re-check all identity properties.
 end=time.monotonic()+15;found=[]
 while time.monotonic()<end:
  info=plistlib.loads(subprocess.check_output(['diskutil','list','-plist','external','physical']))
  found=[]
  for name in info.get('WholeDisks',[]):
   x=plistlib.loads(subprocess.check_output(['diskutil','info','-plist',name]))
   if x.get('BusProtocol')=='USB' and x.get('IORegistryEntryName')=='4G MMC Storage Media' and x.get('Content')=='CD_partition_scheme' and x.get('TotalSize')==15052800 and x.get('Writable') is False:found.append(name)
  if found:break
  time.sleep(1)
 assert len(found)==1,found
 r=subprocess.run(['diskutil','eject',found[0]],check=True,capture_output=True,text=True);e['verified_cd_eject']=r.stdout.strip()
 d=waitmode(0x6000,5);usb.util.dispose_resources(d)
 if phase=='candidate':
  r=subprocess.run(['python3','work/uv310-wireguard/rekey-live/efs_rekey.py','restore'],capture_output=True,text=True,timeout=40)
  assert r.returncode==0,'Immediate stored-stock restoration failed'
  e['stored_stock_restored_before_client_test']=True
 d=p.verify_device();usb.util.claim_interface(d,1);rows=[]
 try:
  for cmd in (['AT+CPIN?','AT+WIFI?'] if phase=='candidate' else ['AT+CPIN?','AT+WIFI?','AT+WL=wl ver','AT+WL=wl isup']):
   d.write(2,(cmd+'\r').encode(),timeout=1000);buf=b'';end=time.monotonic()+5
   while time.monotonic()<end:
    try:buf+=bytes(d.read(0x83,8192,timeout=200))
    except usb.core.USBTimeoutError:continue
    if b'\r\nOK\r\n' in buf or b'\r\nERROR\r\n' in buf:break
   rows.append({'command':cmd,'response':re.sub(r'R=([0-9a-f]{8}):[0-9a-f]{128}', r'R=\1:[64 ROM bytes retained privately]', buf.decode('ascii','replace'))})
  e['rows']=rows
 finally:close(d,1)
 e['workflow_finished']=True
except Exception as ex:
 e['error']=str(ex);e['workflow_finished']=False
finally:
 out.write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e,indent=2))
if not e['workflow_finished']:raise SystemExit(1)
