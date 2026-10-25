"""One bounded Hello World execution using hash-pinned ARM reply-only code.
Targets only the loader's verified 1bbb:f000 single-interface USB topology.
Implements streaming HELLO and EXEC only; no flash/NV/partition operations.
"""
import ast,hashlib,json,time,struct
from pathlib import Path
import usb.core,usb.util
tree=ast.parse(Path('outputs/new-dongle-hello/tools/list_efs_root.py').read_text())
exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('crc','encode','decode')],type_ignores=[]),'<framing>','exec'))
code=Path('outputs/new-dongle-hello/hello-ram.bin').read_bytes()
assert hashlib.sha256(code).hexdigest()=='5f03e8cc08877b82919123b3a94126967a9c415f43b8cab9a270fae7d8d14b58'
d=usb.core.find(idVendor=0x1bbb,idProduct=0xf000)
assert d is not None,'Loader not present'
c=d.get_active_configuration()
assert len(list(c))==1 and [e.bEndpointAddress for e in c[(0,0)]]==[0x81,1]
def exchange(payload):
    assert payload[0] in (1,0x11)
    d.write(1,b'\x7e'+encode(payload),timeout=1500)
    buf=b'';until=time.monotonic()+5
    while time.monotonic()<until:
        try:buf+=bytes(d.read(0x81,8192,timeout=250))
        except usb.core.USBTimeoutError:continue
        while b'\x7e' in buf:
            raw,buf=buf.split(b'\x7e',1);r=decode(raw)
            if r:return r
    return None
e={'transport':'1bbb:f000 interface 0 OUT01 IN81','flash_commands_sent':False,'hello_world_executed':False}
usb.util.claim_interface(d,0)
try:
    r=exchange(b'\x01QCOM fast download protocol host\x03### ')
    e['streaming_hello_hex']=r.hex() if r else None
    assert r and r[0]==2 and b'QCOM' in r,'Loader handshake mismatch; no EXEC sent'
    r=exchange(b'\x11\x00'+code)
    e['program_reply_hex']=r.hex() if r else None
    expected=b'\x12Hello World from UV310 ARM RAM!\n'
    e['hello_world_executed']=r==expected
    if r==expected:e['program_output']=r[1:].decode('ascii')
except Exception as ex:e['error']=str(ex)
finally:
    usb.util.release_interface(d,0);usb.util.dispose_resources(d)
    Path('outputs/new-dongle-hello/evidence/hello-ram-live.json').write_text(json.dumps(e,indent=2)+'\n')
print(json.dumps(e,indent=2))
