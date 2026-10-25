"""Bounded read-only EFS directory metadata query on the user's 05c6:6000.
Only opens a fixed allowlisted directory, lists at most 64 entries and closes it.
Does not read files, NV, keys, SIM data or write any filesystem contents.
Reference: P1sec/QCSuper protocol/efs2.py and modules/efs_shell_commands/ls.py.
"""
import argparse,json,re,struct,time
from pathlib import Path
import usb.core,usb.util

def crc(data):
    value=0xffff
    for b in data:
        value^=b
        for _ in range(8):value=(value>>1)^0x8408 if value&1 else value>>1
    return value^0xffff

def encode(data):
    data+=struct.pack('<H',crc(data))
    return data.replace(b'\x7d',b'\x7d\x5d').replace(b'\x7e',b'\x7d\x5e')+b'\x7e'

def decode(data):
    out=bytearray();escaped=False
    for b in data:
        if escaped:out.append(b^0x20);escaped=False
        elif b==0x7d:escaped=True
        else:out.append(b)
    if escaped or len(out)<3 or crc(out[:-2])!=int.from_bytes(out[-2:],'little'):return None
    return bytes(out[:-2])

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--path',choices=['/','/etc','/web','/sd','/ftl1','/hdev','/web/util','/web/json','/web/xml','/web/res','/web/res/js'],default='/')
p.add_argument('--alternate',action='store_true',help='Query documented alternate FS subsystem 62 instead of 19')
a=p.parse_args()
subsys=62 if a.alternate else 19
d=usb.core.find(idVendor=0x05c6,idProduct=0x6000)
if d is None:raise SystemExit('Expected 05c6:6000 missing')
def request(cmd,body=b''):
    assert cmd in (11,12,13)
    packet=bytes([75,subsys])+struct.pack('<H',cmd)+body
    d.write(4,encode(packet),timeout=1000)
    buf=b'';deadline=time.monotonic()+3
    while time.monotonic()<deadline and len(buf)<65536:
        try:buf+=bytes(d.read(0x85,8192,timeout=200))
        except usb.core.USBTimeoutError:continue
        while b'\x7e' in buf:
            raw,buf=buf.split(b'\x7e',1);reply=decode(raw)
            if reply and (reply[:4]==packet[:4] or reply[0] in (19,20,21,24,71)):return reply
    raise TimeoutError('No matching EFS metadata response')

result={'usb':'05c6:6000','interface':3,'path':a.path,'entries':[],
        'subsystem':subsys,
        'scope':'Directory metadata only; no file reads or writes'}
fd=None
usb.util.claim_interface(d,3)
try:
    reply=request(11,a.path.encode()+b'\0')
    result['opendir_response_opcode']=reply[0]
    if reply[:4]==bytes([75,subsys,11,0]) and len(reply)>=12:
        handle,errno=struct.unpack('<Ii',reply[4:12]);result['opendir_errno']=errno
        if errno==0:
            fd=handle
            for seq in range(1,65):
                reply=request(12,struct.pack('<II',fd,seq))
                if len(reply)<40 or reply[:4]!=bytes([75,subsys,12,0]):
                    result['readdir_response_opcode']=reply[0];break
                gotfd,gotseq,err,kind,mode,size,at,mt,ct=struct.unpack('<I8i',reply[4:40])
                if gotfd!=fd or gotseq!=seq:raise ValueError('Unexpected directory response')
                if err:result['readdir_errno']=err;break
                name=reply[40:].split(b'\0')[0].decode('utf-8','replace')
                if not name:result['complete']=True;break
                name=re.sub(r'\d{12,}','[REDACTED]',name)
                result['entries'].append({'name':name,'type':kind,'mode':oct(mode),'bytes':size})
            else:result['entry_limit_reached']=True
except (usb.core.USBError,TimeoutError,ValueError) as error:result['error']=str(error)
finally:
    if fd is not None:
        try:
            reply=request(13,struct.pack('<I',fd))
            result['closedir_errno']=int.from_bytes(reply[4:8],'little') if reply[:4]==bytes([75,subsys,13,0]) and len(reply)>=8 else None
        except Exception as error:result['closedir_error']=str(error)
    usb.util.release_interface(d,3);usb.util.dispose_resources(d)
Path('outputs/new-dongle-hello/evidence/efs-'+('alternate-' if a.alternate else '')+(a.path.strip('/').replace('/','-') or 'root')+'.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
