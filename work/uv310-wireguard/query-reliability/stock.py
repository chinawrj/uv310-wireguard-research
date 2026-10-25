"""Bounded read-only stock AT pacing comparison; no reset/config/firmware writes."""
from pathlib import Path
import json,re,time
import usb.core,usb.util
O=Path('outputs/uv310-wireguard/evidence/query-reliability-stock.json')
d=usb.core.find(idVendor=0x05c6,idProduct=0x6000);assert d is not None
assert {i.bInterfaceNumber:sorted(e.bEndpointAddress for e in i) for i in d.get_active_configuration()}=={0:[1,129,130],1:[2,131],2:[3,132],3:[4,133],4:[5,134]}
e={'scope':'Read-only stock UV310 AT command pacing; no Wi-Fi client traffic generated','rows':[],'device_modified':False,'completed':False}
usb.util.claim_interface(d,1)
def cmd(s,block,interval):
 time.sleep(interval);start=time.monotonic();d.write(2,(s+'\r').encode(),timeout=1000);b=b''
 while time.monotonic()-start<3 and len(b)<8192:
  try:b+=bytes(d.read(0x83,8192,timeout=200))
  except usb.core.USBTimeoutError:continue
  if b'\r\nOK\r\n' in b or b'\r\nERROR\r\n' in b:break
 row={'command':s,'block':block,'pre_delay_seconds':interval,'elapsed_ms':round((time.monotonic()-start)*1000,3),'ok':b'\r\nOK\r\n' in b,'error':b'\r\nERROR\r\n' in b,'response':re.sub(r'\d{12,}','[REDACTED]',b.decode('ascii','replace'))}
 e['rows'].append(row);O.write_text(json.dumps(e,indent=2)+'\n');return b
try:
 for _ in range(8):
  try:d.read(0x83,8192,timeout=100)
  except usb.core.USBTimeoutError:break
 identity=cmd('AT^PROJECTNAME?','identity',0);assert b'MDM9600' in identity and b'UV310' in identity
 b=cmd('AT+WL=wl ver','precheck',.25);assert b'version 5.90.153.52.1' in b and b'A=' not in b
 for block,interval in [('rapid1',0),('spaced',.25),('rapid2',0)]:
  for _ in range(12):cmd('AT+WL=wl ver',block,interval)
  rows=[r for r in e['rows'] if r['block']==block];print(json.dumps({'block':block,'ok':sum(r['ok'] for r in rows),'error':sum(r['error'] for r in rows)}),flush=True)
 cmd('AT+WL=wl memuse','unsupported_control',.25)
 cmd('AT+WL=wl isup','final',.25);cmd('AT+CPIN?','final',.25)
 e['completed']=True
except Exception as ex:e['error']=repr(ex)
finally:
 usb.util.release_interface(d,1);usb.util.dispose_resources(d);O.write_text(json.dumps(e,indent=2)+'\n')
 print(json.dumps({'completed':e['completed'],'error':e.get('error')}),flush=True)
if not e['completed']:raise SystemExit(1)
