"""Verify reversible file I/O on fixed, newly-created UV310 research files.
Does not alter active firmware, configuration, NV, SIM or existing files.
Protocol layout reference: P1sec/QCSuper efs2.py, put.py, mv.py.
"""
from pathlib import Path
import ast, hashlib, json, struct, time
import usb.core, usb.util

tree=ast.parse(Path('outputs/new-dongle-hello/tools/list_efs_root.py').read_text())
exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('crc','encode','decode')],type_ignores=[]),'<framing>','exec'))
ROOT='/SyFi/brew/mod/'
PATHS={ROOT+'wg_probe_io_a.bin', ROOT+'wg_probe_io_b.bin'}
PAYLOAD=b'UV310 WireGuard research file-I/O verification\n'+bytes(range(64))
e={'scope':'Only two new allowlisted probe files; no active firmware replacement',
   'payload_bytes':len(PAYLOAD),'payload_sha256':hashlib.sha256(PAYLOAD).hexdigest(),
   'events':[], 'active_firmware_modified':False}

def pathbytes(path):
    assert path in PATHS
    return path.encode()+b'\0'

def request(cmd,body):
    assert cmd in (2,3,4,5,8,14,15)
    packet=b'\x4b\x13'+struct.pack('<H',cmd)+body
    d.write(4,encode(packet),timeout=1000)
    buf=b'';end=time.monotonic()+5
    while time.monotonic()<end and len(buf)<65536:
        try:buf+=bytes(d.read(0x85,8192,timeout=250))
        except usb.core.USBTimeoutError:continue
        while b'\x7e' in buf:
            raw,buf=buf.split(b'\x7e',1);r=decode(raw)
            if r and r[:4]==packet[:4]:return r[4:]
            if r and r[0] in (19,20,21,24,71):raise RuntimeError('DIAG rejection '+hex(r[0]))
    raise TimeoutError('No matching EFS reply')

def stat(path):
    r=request(15,pathbytes(path));assert len(r)==28
    err,mode,size,*_=struct.unpack('<7i',r)
    return err,mode,size

def read(path):
    fd,err=struct.unpack('<ii',request(2,struct.pack('<II',0,0)+pathbytes(path)))
    assert err==0,('read open',err)
    try:
        r=request(4,struct.pack('<iII',fd,256,0))
        got,off,count,err=struct.unpack_from('<iIii',r)
        assert (got,off,err)==(fd,0,0) and count==len(r)-16
        return r[16:]
    finally:assert request(3,struct.pack('<i',fd))==bytes(4)

def remove_owned(path):
    # Only delete our exact, byte-for-byte verified payload.
    assert read(path)==PAYLOAD
    assert request(8,pathbytes(path))==bytes(4)
    assert stat(path)[0]==2
    e['events'].append({'operation':'remove','path':path,'verified_absent':True})

if __name__=='__main__':
    d=usb.core.find(idVendor=0x05c6,idProduct=0x6000)
    if d is None:raise SystemExit('Expected UV310 not present')
    c=d.get_active_configuration()
    assert sorted(x.bEndpointAddress for x in c[(1,0)])==[2,131]
    assert sorted(x.bEndpointAddress for x in c[(3,0)])==[4,133]
    usb.util.claim_interface(d,1)
    try:
        d.write(2,b'AT^PROJECTNAME?\r',timeout=1000)
        b=b'';end=time.monotonic()+3
        while time.monotonic()<end and b'\r\nOK\r\n' not in b:
            try:b+=bytes(d.read(0x83,4096,timeout=250))
            except usb.core.USBTimeoutError:pass
        assert b'MDM9600' in b and b'UV310' in b
    finally:usb.util.release_interface(d,1)
    usb.util.claim_interface(d,3)
    created=set()
    try:
        a,b=sorted(PATHS)
        for path in (a,b):
            err,mode,size=stat(path)
            e['events'].append({'operation':'preflight_stat','path':path,'errno':err})
            assert err==2,'Probe path must not exist'
        fd,err=struct.unpack('<ii',request(2,struct.pack('<II',0o301,0o100600)+pathbytes(a)))
        e['events'].append({'operation':'exclusive_create','path':a,'errno':err})
        assert err==0,('exclusive create failed',err)
        created.add(a)
        try:
            r=request(5,struct.pack('<iI',fd,0)+PAYLOAD)
            got,off,count,err=struct.unpack('<iIii',r)
            assert (got,off,count,err)==(fd,0,len(PAYLOAD),0)
        finally:assert request(3,struct.pack('<i',fd))==bytes(4)
        assert read(a)==PAYLOAD
        e['events'].append({'operation':'write_readback','matched':True})
        assert request(14,pathbytes(a)+pathbytes(b))==bytes(4)
        created.remove(a);created.add(b)
        assert stat(a)[0]==2 and read(b)==PAYLOAD
        e['events'].append({'operation':'rename_readback','matched':True})
        remove_owned(b);created.remove(b)
        e['passed']=True
    except Exception as ex:
        e['error']=str(ex);e['passed']=False
    finally:
        for path in created:
            try:remove_owned(path)
            except Exception as ex:e['events'].append({'operation':'cleanup_failed','path':path,'error':str(ex)})
        usb.util.release_interface(d,3);usb.util.dispose_resources(d)
        Path('outputs/uv310-wireguard/evidence/efs-probe-io.json').write_text(json.dumps(e,indent=2)+'\n')
    print(json.dumps(e,indent=2))
