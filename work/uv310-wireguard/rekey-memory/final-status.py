"""Bounded read-only identity/help queries on the user's UV310, no settings writes."""
from pathlib import Path
import time,json,re
import usb.core,usb.util
d=usb.core.find(idVendor=0x05c6,idProduct=0x6000)
if d is None:raise SystemExit('Expected UV310 USB device missing')
c=d.get_active_configuration()
actual={x.bInterfaceNumber: sorted(e.bEndpointAddress for e in x) for x in c}
assert actual=={0:[1,129,130],1:[2,131],2:[3,132],3:[4,133],4:[5,134]}, actual
i=c[(1,0)]
if sorted(e.bEndpointAddress for e in i)!=[2,131]:raise SystemExit('Unexpected endpoint topology')
usb.util.claim_interface(d,1)
rows=[]
try:
 for cmd in ['AT^PROJECTNAME?','AT+CPIN?','AT+WIFI?','AT+WL=wl ver','AT+WL=wl isup']:
  for _ in range(8):
   try:d.read(0x83,8192,timeout=100)
   except usb.core.USBTimeoutError:break
  d.write(2,(cmd+'\r').encode(),timeout=1000)
  data=b'';end=time.monotonic()+5
  while time.monotonic()<end and len(data)<65536:
   try:data+=bytes(d.read(0x83,8192,timeout=200))
   except usb.core.USBTimeoutError:continue
   if any(x in data for x in [b'\r\nOK\r\n',b'\r\nERROR\r\n']):break
  if cmd=='AT^PROJECTNAME?' and not re.search(rb'MDM9600\s+UV310',data):raise RuntimeError('Unexpected project; stopped before Wi-Fi queries')
  txt=re.sub(r'\b\d{12,}\b','[REDACTED]',data.decode('ascii','replace'))
  rows.append({'command':cmd,'response':txt,'bytes':len(data)})
finally:
 usb.util.release_interface(d,1);usb.util.dispose_resources(d)
result={'commands_read_only':True,'source':'Own firmware: +WL table at 0xf01c1800 -> 0xd380fc -> 0xcf475c; read-only precheck on user-reconnected device; no write/reset','rows':rows}
Path('outputs/uv310-wireguard/evidence/rekey-memory-final-status.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
