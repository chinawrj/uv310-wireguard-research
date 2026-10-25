"""Bounded DMSS NOP/parameter probe; no writes/reboot/upload commands."""
import ast,json,time,struct
from pathlib import Path
import usb.core,usb.util
tree=ast.parse(Path('outputs/new-dongle-hello/tools/list_efs_root.py').read_text())
exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('crc','encode','decode')],type_ignores=[]),'<framing>','exec'))
d=usb.core.find(idVendor=0x05c6,idProduct=0x6000)
if d is None:raise SystemExit('Missing device')
cfg=d.get_active_configuration()
assert len(list(cfg))==4 and all(len(list(i))==2 for i in cfg),'Unexpected mode descriptors'
rows=[]
try:
 for i in [cfg[(3,0)]]:
  n=i.bInterfaceNumber;row={'interface':n};rows.append(row)
  usb.util.claim_interface(d,n)
  try:
   d.write(n+1,b'\x7e'+encode(b'\x06'),timeout=800)
   buf=b'';until=time.monotonic()+1.5
   while time.monotonic()<until:
    try:buf+=bytes(d.read(0x81+n,4096,timeout=200))
    except usb.core.USBTimeoutError:continue
    if b'\x7e' in buf:break
   replies=[decode(x) for x in buf.split(b'\x7e') if x]
   row['raw_hex']=buf.hex()
   row['nop_replies']=[r.hex() for r in replies if r]
   if b'\x02' in replies:
    d.write(n+1,b'\x7e'+encode(b'\x07'),timeout=800)
    try:
     buf=bytes(d.read(0x81+n,4096,timeout=1200))
     row['parameters_replies']=[r.hex() for x in buf.split(b'\x7e') if x and (r:=decode(x))]
    except usb.core.USBError as e:row['parameters_error']=str(e)
  except usb.core.USBError as e:row['error']=str(e)
  finally:usb.util.release_interface(d,n)
finally:usb.util.dispose_resources(d)
Path('outputs/new-dongle-hello/evidence/download-parameters.json').write_text(json.dumps(rows,indent=2)+'\n')
print(json.dumps(rows,indent=2))
