"""Offline structural preflight. No USB/network, material generation, or deployment."""
import argparse,base64,configparser,hashlib,ipaddress,json,os,stat
from pathlib import Path
STOCK_SHA='4b86d71b92529034b2b46da7b93402f67c8aef98d2fc1efa91fc67ff7e5fb85a'
STOCK_BYTES=193315
LAN=ipaddress.IPv4Network('192.168.100.0/24')
class CheckError(Exception):pass

def read_regular(path,limit,private=False):
 try:
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  with os.fdopen(fd,'rb') as f:
   meta=os.fstat(f.fileno())
   if not stat.S_ISREG(meta.st_mode):raise CheckError('NOT_REGULAR_FILE')
   if private and (meta.st_uid!=os.getuid() or meta.st_mode&0o077):raise CheckError('CONFIG_PERMISSIONS')
   data=f.read(limit+1)
   if len(data)>limit:raise CheckError('INPUT_TOO_LARGE')
   return data
 except OSError:raise CheckError('INPUT_UNREADABLE') from None

def ipv4(value,code):
 try:a=ipaddress.IPv4Address(value)
 except ValueError:raise CheckError(code) from None
 if a.is_unspecified or a.is_multicast or a.is_loopback or a.is_reserved or a in LAN:raise CheckError(code)
 return a

def parse_config(data):
 c=configparser.ConfigParser(interpolation=None,strict=True)
 try:c.read_string(data.decode('utf-8'))
 except (UnicodeError,configparser.Error):raise CheckError('CONFIG_SYNTAX') from None
 if c.defaults() or set(c.sections())!={'Interface','Peer'}:raise CheckError('ONE_INTERFACE_ONE_PEER_REQUIRED')
 allowed={'Interface':{'privatekey','address','dns','mtu'},'Peer':{'publickey','presharedkey','endpoint','allowedips'}}
 for section in allowed:
  if set(c[section])-allowed[section]:raise CheckError('UNSUPPORTED_OPTION')
 required={'Interface':{'privatekey','address','dns'},'Peer':{'publickey','endpoint','allowedips'}}
 for section in required:
  if not required[section].issubset(c[section]):raise CheckError('MISSING_OPTION')
 for section,name in [('Interface','privatekey'),('Peer','publickey'),('Peer','presharedkey')]:
  if name not in c[section]:continue
  try:key=base64.b64decode(c[section][name],validate=True)
  except ValueError:raise CheckError('INVALID_KEY') from None
  if len(key)!=32 or (not any(key) and name!='presharedkey'):raise CheckError('INVALID_KEY')
 try:address=ipaddress.IPv4Interface(c['Interface']['address'])
 except ValueError:raise CheckError('SINGLE_IPV4_ADDRESS_REQUIRED') from None
 ipv4(str(address.ip),'INVALID_INNER_ADDRESS')
 ipv4(c['Interface']['dns'],'SINGLE_TUNNEL_DNS_REQUIRED')
 endpoint=c['Peer']['endpoint'].split(':')
 if len(endpoint)!=2:raise CheckError('IPV4_LITERAL_ENDPOINT_REQUIRED')
 ipv4(endpoint[0],'IPV4_LITERAL_ENDPOINT_REQUIRED')
 try:port=int(endpoint[1])
 except ValueError:raise CheckError('INVALID_ENDPOINT_PORT') from None
 if not 1<=port<=65535:raise CheckError('INVALID_ENDPOINT_PORT')
 if c['Peer']['allowedips'].strip()!='0.0.0.0/0':raise CheckError('IPV4_DEFAULT_ROUTE_REQUIRED')
 if c['Interface'].get('mtu','1420')!='1420':raise CheckError('UNSUPPORTED_MTU')
 return {'configuration_shape_supported':True,'preshared_key_present':'presharedkey' in c['Peer'],'ipv4_inner_packet_limit':1420}

def check(config,stock):
 result=parse_config(read_regular(config,65536,private=True))
 data=read_regular(stock,STOCK_BYTES)
 if len(data)!=STOCK_BYTES or hashlib.sha256(data).hexdigest()!=STOCK_SHA:raise CheckError('STOCK_MISMATCH')
 result.update(stock_hash_matches=True,scope='offline structural preflight only',device_access=False,network_access=False,material_generated=False,peer_server_verified=False,private_config_link_verified=False,deployable=False)
 return result

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',required=True,type=Path);p.add_argument('--stock',required=True,type=Path);a=p.parse_args()
 try:result=check(a.config,a.stock)
 except CheckError as e:print(json.dumps({'check_passed':False,'error':str(e)}));return 2
 print(json.dumps({'check_passed':True,**result}));return 0
if __name__=='__main__':raise SystemExit(main())
