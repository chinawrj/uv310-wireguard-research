"""Stage/activate/restore one hash-pinned startup probe on the user's UV310.
Only the active Wi-Fi RAM-image file and two exact research paths are permitted.
No raw NAND, NV, bootloader or QDSP firmware writes.
"""
from pathlib import Path
import argparse, hashlib, json, struct, time
import usb.core, usb.util
import sys
sys.path.insert(0,"work/uv310-wireguard")
import efs_probe_io as fs

P=Path('work/uv310-wireguard')
ACTIVE='/SyFi/brew/mod/rtecdc_new.bin'
BACKUP='/SyFi/brew/mod/wg_rekeymemory_stock_4b86d71b.bin'
STAGED='/SyFi/brew/mod/wg_rekeymemory_probe_stage.bin'
fs.PATHS={ACTIVE,BACKUP,STAGED}
original=(P/'private/web-assets/rtecdc_new.bin').read_bytes()
candidate=(P/'private/rtecdc_new.rekey-memory.bin').read_bytes()
sha=lambda b:hashlib.sha256(b).hexdigest()
ORIGINAL='4b86d71b92529034b2b46da7b93402f67c8aef98d2fc1efa91fc67ff7e5fb85a'
CANDIDATE='a0dd391a08d715051fdd83c4c70432c2ee37c653ae296c89c105b98386bac56e'
assert sha(original)==ORIGINAL and sha(candidate)==CANDIDATE
assert candidate[0x19b80:0x19b8e]==b'5.90.153.52.1\0'
assert json.loads((P/'private/rekey-memory/result.json').read_text())['crc_check_unchanged']

def read(path):
    err,mode,size=fs.stat(path)
    assert err==0 and 0<=size<250000,('stat',path,err,size)
    fd,err=struct.unpack('<ii',fs.request(2,struct.pack('<II',0,0)+fs.pathbytes(path)))
    assert err==0,('open',err)
    buf=bytearray()
    try:
        while len(buf)<size:
            n=min(1024,size-len(buf))
            r=fs.request(4,struct.pack('<iII',fd,n,len(buf)))
            h,off,count,err=struct.unpack_from('<iIii',r)
            assert (h,off,count,err)==(fd,len(buf),n,0) and len(r)==16+n
            buf.extend(r[16:])
    finally:assert fs.request(3,struct.pack('<i',fd))==bytes(4)
    return bytes(buf),mode

def stage(path,blob,mode):
    err,_,_=fs.stat(path)
    if err==0:
        assert read(path)[0]==blob,'Existing staged file differs; do not overwrite'
        e['events'].append({'operation':'existing_stage_verified','path':path,'sha256':sha(blob)})
        return
    assert err==2
    fd,err=struct.unpack('<ii',fs.request(2,struct.pack('<II',0o301,mode)+fs.pathbytes(path)))
    assert err==0,('exclusive_create',path,err)
    try:
        for offset in range(0,len(blob),1024):
            part=blob[offset:offset+1024]
            r=fs.request(5,struct.pack('<iI',fd,offset)+part)
            assert struct.unpack('<iIii',r)==(fd,offset,len(part),0)
    finally:assert fs.request(3,struct.pack('<i',fd))==bytes(4)
    assert read(path)[0]==blob
    e['events'].append({'operation':'staged_readback_verified','path':path,'bytes':len(blob),'sha256':sha(blob)})
    print('Verified staged file',path,len(blob),'bytes',flush=True)

def rename(old,new):
    r=fs.request(14,fs.pathbytes(old)+fs.pathbytes(new))
    assert r==bytes(4),('rename errno',r.hex())
    e['events'].append({'operation':'rename','source':old,'destination':new})

def verify_device():
    d=usb.core.find(idVendor=0x05c6,idProduct=0x6000)
    assert d is not None,'Expected device absent'
    c=d.get_active_configuration()
    assert {i.bInterfaceNumber:sorted(x.bEndpointAddress for x in i) for i in c}=={0:[1,129,130],1:[2,131],2:[3,132],3:[4,133],4:[5,134]}
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
    return d

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=['stage','activate','restore'])
    op=parser.parse_args().operation
    if op in ('stage','activate'):
        meta=json.loads((P/'private/rekey-memory/provision.json').read_text())
        assert 0<time.time_ns()-meta['generated_unix_ns']<1200*10**9,'Fresh material expired'
        assert not Path('outputs/uv310-wireguard/evidence/rekey-memory-cold-candidate.json').exists(),'One boot only; already attempted'
    e={'operation':op,'events':[],'raw_flash_or_nv_writes':False,
       'active_firmware_path':ACTIVE,'original_sha256':ORIGINAL,'candidate_sha256':CANDIDATE}
    fs.d=verify_device();usb.util.claim_interface(fs.d,3)
    try:
        active,mode=read(ACTIVE);active_hash=sha(active)
        e['active_before_sha256']=active_hash
        assert active_hash in (ORIGINAL,CANDIDATE),'Unexpected active image; stopped'
        if op=='stage':
            assert active_hash==ORIGINAL
            stage(BACKUP,original,mode);stage(STAGED,candidate,mode)
            assert read(ACTIVE)[0]==original
        elif op=='activate':
            assert read(BACKUP)[0]==original
            if active_hash==ORIGINAL:
                assert read(STAGED)[0]==candidate
                rename(STAGED,ACTIVE)
            assert read(ACTIVE)[0]==candidate
        elif op=='restore':
            if active_hash==CANDIDATE:
                assert read(BACKUP)[0]==original
                rename(BACKUP,ACTIVE)
            assert read(ACTIVE)[0]==original
            for path,expected in [(STAGED,candidate),(BACKUP,original)]:
                err,_,_=fs.stat(path)
                if err==0:
                    assert read(path)[0]==expected
                    assert fs.request(8,fs.pathbytes(path))==bytes(4)
                    e['events'].append({'operation':'remove_verified_research_file','path':path})
                else:assert err==2
        e['active_after_sha256']=sha(read(ACTIVE)[0]);e['passed']=True
    except Exception as ex:
        e['error']=str(ex);e['passed']=False
    finally:
        usb.util.release_interface(fs.d,3);usb.util.dispose_resources(fs.d)
        Path('outputs/uv310-wireguard/evidence/rekey-memory-efs-'+op+'.json').write_text(json.dumps(e,indent=2)+'\n')
    print(json.dumps(e,indent=2))
    if not e['passed']:raise SystemExit(1)
