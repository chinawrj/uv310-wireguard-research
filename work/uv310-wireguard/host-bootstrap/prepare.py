"""Prepare private host material only. Does not compile, deploy or authorize boot."""
import argparse,base64,configparser,fcntl,hashlib,ipaddress,json,os,secrets,stat,time,uuid
from pathlib import Path
from check import CheckError,read_regular,parse_config,STOCK_BYTES,STOCK_SHA

def sync_dir(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)

def write_new(path,data):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())

def prepare(config,stock,root):
 raw=read_regular(config,65536,True);parse_config(raw)
 data=read_regular(stock,STOCK_BYTES)
 if len(data)!=STOCK_BYTES or hashlib.sha256(data).hexdigest()!=STOCK_SHA:raise CheckError('STOCK_MISMATCH')
 # Caller creates a private directory; no automatic chmod of existing paths.
 root=Path(root);st=root.lstat()
 if root.name!='private' or not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode&0o077:raise CheckError('PRIVATE_DIRECTORY_REQUIRED')
 c=configparser.ConfigParser(interpolation=None);c.read_string(raw.decode())
 fd=os.open(root/'prepare.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'r+b') as lock:
  st=os.fstat(lock.fileno())
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode&0o077:raise CheckError('LOCK_PERMISSIONS')
  fcntl.flock(lock,fcntl.LOCK_EX)
  ledger=root/'prepare-clock.json';last=0
  if ledger.exists() or ledger.is_symlink():
   try:last=json.loads(read_regular(ledger,4096,True))['reserved_through_ns']
   except (ValueError,KeyError,TypeError):raise CheckError('INVALID_CLOCK_LEDGER') from None
   if type(last) is not int or last<0:raise CheckError('INVALID_CLOCK_LEDGER')
  now=time.time_ns()
  if now<1577836800*10**9 or now<=last:raise CheckError('HOST_CLOCK_NOT_FRESH')
  pool=secrets.token_bytes(256);seed=secrets.token_bytes(32)
  if len(pool)!=256 or len(seed)!=32:raise CheckError('RANDOM_SOURCE_FAILURE')
  attempt=uuid.uuid4().hex;directory=root/('bootstrap-'+attempt);directory.mkdir(mode=0o700)
  # Reserve before publishing material. Failed attempts may consume a reservation.
  temporary=root/('clock-'+attempt+'.tmp')
  write_new(temporary,json.dumps({'reserved_through_ns':now+10**9}).encode())
  os.replace(temporary,ledger);sync_dir(root)
  decode=lambda value:base64.b64decode(value,validate=True)
  host,port=c['Peer']['endpoint'].split(':')
  values={'PRIVATE_KEY':decode(c['Interface']['privatekey']),'PEER_KEY':decode(c['Peer']['publickey']),
   'PRESHARED_KEY':decode(c['Peer']['presharedkey']) if 'presharedkey' in c['Peer'] else bytes(32),
   'RANDOM_POOL':pool,'TAI64N':(0x400000000000000a+now//10**9).to_bytes(8,'big')+(now%10**9).to_bytes(4,'big'),
   'ENDPOINT_IP':ipaddress.IPv4Address(host).packed,'INNER_SOURCE':ipaddress.IPv4Interface(c['Interface']['address']).ip.packed,
   'LAN_GATEWAY':bytes([192,168,100,1]),'TUNNEL_DNS':ipaddress.IPv4Address(c['Interface']['dns']).packed}
  header='/* PRIVATE: fresh single-attempt material; not boot authorization. */\n'+''.join('static const unsigned char '+k+'[]={'+','.join(map(str,v))+'};\n' for k,v in values.items())+f'#define ENDPOINT_PORT {int(port)}\n'
  write_new(directory/'native-config.h',header.encode())
  # This seed is reserved for future generator development, not used by native.c.
  write_new(directory/'generator-seed.bin',seed)
  meta={'attempt_id':attempt,'generated_unix_ns':now,'pool_bytes':256,'seed_bytes':32,'seed_integrated':False,'phase':'prepared-only','boot_authorized':False,'native_config_sha256':hashlib.sha256(header.encode()).hexdigest(),'not_reusable_after_boot_attempt':True}
  write_new(directory/'material.json',json.dumps(meta,indent=2).encode());sync_dir(directory);sync_dir(root)
 return {'prepared':True,'attempt_id':attempt,'directory_name':directory.name,'boot_authorized':False,'seed_integrated':False,'device_access':False,'network_access':False}

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',type=Path,required=True);p.add_argument('--stock',type=Path,required=True);p.add_argument('--private-dir',type=Path,required=True);a=p.parse_args()
 try:r=prepare(a.config,a.stock,a.private_dir)
 except CheckError as e:print(json.dumps({'prepared':False,'error':str(e)}));return 2
 except (OSError,ValueError,OverflowError):print(json.dumps({'prepared':False,'error':'PREPARATION_FAILED'}));return 2
 print(json.dumps(r));return 0
if __name__=='__main__':raise SystemExit(main())
