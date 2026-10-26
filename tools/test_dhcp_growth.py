"""Bounded DHCP growth: independent golden bytes, host sanitizers and Cortex-M3.
No device/network access. Imports existing synthetic packet builders only.
"""
from pathlib import Path
import hashlib,json,os,shutil,struct,subprocess,tempfile
from test_dhcp_dns import packet,repair,TYPE,END,SERVER,DNS,cases as base_cases,qemu_cases
ROOT=Path(__file__).resolve().parents[1];SRC=ROOT/'work/uv310-wireguard/dhcp-dns'
cases=[]
def add(name,b,capacity,rc,expected=None):
 expected=bytes(b) if expected is None else bytes(expected)
 cases.append((name,bytes(b),capacity,rc,expected,DNS))
def growing(name,pad=0,spare=0,tail=0,ip_options=b'',junk=False,extra=0,udp_zero=False):
 b,_,end=packet([TYPE,END],padding=pad,eth_padding=tail,ip_options=ip_options,udp_zero=udp_zero)
 if junk:
  # Nonzero bytes after END must survive, never silently overwritten.
  b[end+1:end+1]=b'\x81\x82\x83'
  h=(b[14]&15)*4;struct.pack_into('!H',b,16,struct.unpack_from('!H',b,16)[0]+3)
  struct.pack_into('!H',b,14+h+4,struct.unpack_from('!H',b,14+h+4)[0]+3);repair(b)
  pad=0
 if extra:b+=bytes([0xa5])*extra
 growth=max(0,6-pad);capacity=len(b)+growth+spare
 if spare<0 or len(b)+growth>2048:
  add(name,b,capacity,-2);return
 expected=bytearray(b);expected[end:end+1+min(pad,6)]=b'\x06\x04'+DNS+b'\xff'
 h=(expected[14]&15)*4
 struct.pack_into('!H',expected,16,struct.unpack_from('!H',expected,16)[0]+growth)
 struct.pack_into('!H',expected,14+h+4,struct.unpack_from('!H',expected,14+h+4)[0]+growth)
 repair(expected);add(name,b,capacity,1,expected)
for pad in range(7):
 for spare in [-1,0,9]:
  if pad==6 and spare<0:continue
  growing(f'pad_{pad}_spare_{spare}',pad,spare)
for name,kw in [('ether_tail',{'tail':17}),('ip_options',{'ip_options':bytes([1,1,1,0])}),('nonzero_after_end',{'pad':5,'tail':9,'junk':True}),('zero_checksum',{'udp_zero':True}),('odd_growth',{'pad':1}),('frame_limit_exact',{'extra':1756}),('frame_limit_over',{'extra':1757})]:growing(name,**kw)
# Existing named vectors exercise all old rejects and non-growing outputs.
for name,b,rc,expected,dns in base_cases[:qemu_cases]:cases.append(('base_'+name,b,len(b),rc,expected,dns))
b,_,_=packet([TYPE,END]);add('capacity_less_than_size',b,len(b)-1,-1)
# Growth also at both boundaries for every main END offset with preceding options.
for length in [0,1,2,31,127,255]:
 b,_,end=packet([TYPE,(222,bytes([0x93])*length),END],eth_padding=7)
 expected=bytearray(b);expected[end:end+1]=b'\x06\x04'+DNS+b'\xff'
 struct.pack_into('!H',expected,16,struct.unpack_from('!H',expected,16)[0]+6)
 struct.pack_into('!H',expected,38,struct.unpack_from('!H',expected,38)[0]+6);repair(expected)
 add('offset_exact_'+str(length),b,len(b)+6,1,expected)
 add('offset_short_'+str(length),b,len(b)+5,-2)

def vectors():
 lines=['struct vector{unsigned n,capacity,expected_n;int result;const unsigned char *input,*expected,*dns;};']
 for i,(_,b,c,rc,e,dns) in enumerate(cases):
  for field,data in [('input',b),('expected',e),('dns',dns)]:lines.append('static const unsigned char '+field+str(i)+'[]={'+','.join(map(str,data))+'};')
 lines.append('static const struct vector vectors[]={')
 for i,(_,b,c,rc,e,dns) in enumerate(cases):lines.append('{%d,%d,%d,%d,input%d,expected%d,dns%d},'%(len(b),c,len(e),rc,i,i,i))
 return '\n'.join(lines+['};'])
RUNNER=r'''
#include "dhcp_dns_grow.h"
#include "vectors.h"
#ifdef HOST
#include <stdlib.h>
#else
static unsigned char storage[4096];
#endif
static const unsigned char server[]={192,168,100,1};
int tests(void){
 for(unsigned i=0;i<sizeof(vectors)/sizeof(vectors[0]);i++){
  const struct vector *v=&vectors[i];
  unsigned allocation=v->capacity>v->n?v->capacity:v->n;
#ifdef HOST
  unsigned char *b=malloc(allocation);if(!b)return 10001;
#else
  unsigned char *b=storage+1;storage[0]=0xa5;for(unsigned j=0;j<sizeof(storage)-1;j++)b[j]=0xa5;
#endif
  for(unsigned j=0;j<allocation;j++)b[j]=j<v->n?v->input[j]:0xa5;
  size_t n=v->n;int rc=dhcp_dns_rewrite_grow(b,&n,v->capacity,server,v->dns);
  if(rc!=v->result||n!=v->expected_n)return i+1;
  for(unsigned j=0;j<n;j++)if(b[j]!=v->expected[j])return i+1;
  for(unsigned j=n;j<allocation;j++)if(b[j]!=0xa5)return i+1;
#ifndef HOST
  if(storage[0]!=0xa5)return i+1;
  for(unsigned j=allocation;j<sizeof(storage)-1;j++)if(b[j]!=0xa5)return i+1;
#else
  free(b);
#endif
 }return 0;
}
#ifdef HOST
#include <stdio.h>
int main(void){int r=tests();printf("%d\n",r);return r?1:0;}
#endif
'''
def run(cmd,**kw):
 r=subprocess.run(cmd,capture_output=True,text=True,**kw)
 if r.returncode:raise RuntimeError(r.stdout+r.stderr)
 return r

def main():
 cc=os.environ.get('LLVM_CLANG') or shutil.which('clang');ld=os.environ.get('LLVM_LD') or shutil.which('ld.lld');q=os.environ.get('QEMU_ARM') or shutil.which('qemu-system-arm')
 host=os.environ.get('HOST_CLANG') or ('/usr/bin/clang' if os.uname().sysname=='Darwin' else cc)
 assert all([cc,ld,q,host]);san=os.environ.get('HOST_SANITIZERS','address,undefined');assert san in ('undefined','address,undefined')
 sdk=['-isysroot',os.environ['HOST_SDKROOT']] if os.environ.get('HOST_SDKROOT') else []
 negatives=[]
 with tempfile.TemporaryDirectory(prefix='uv310-growth-') as temp:
  t=Path(temp);(t/'vectors.h').write_text(vectors());(t/'tests.c').write_text(RUNNER)
  def host_test(src):
   run([host,*sdk,'-std=c11','-Wall','-Wextra','-Werror','-g','-O1','-DHOST','-fsanitize='+san,'-fno-sanitize-recover=all','-I'+str(SRC),'-I'+str(t),str(src),str(SRC/'dhcp_dns.c'),str(t/'tests.c'),'-o',str(t/'host')])
   return subprocess.run([str(t/'host')],capture_output=True,text=True,timeout=30)
  r=host_test(SRC/'dhcp_dns_grow.c');assert r.returncode==0,r.stdout+r.stderr
  source=(SRC/'dhcp_dns_grow.c').read_text()
  for name,old,new in [
   ('skip_capacity','growth>capacity-n||','0||'),
   ('skip_frame_limit','growth>2048u-n','0'),
   ('wrong_result_length','*size=n+growth;','*size=n;'),
   ('wrong_ip_length','put16(ip+2,get16(ip+2)+growth);','put16(ip+2,get16(ip+2));'),
   ('wrong_udp_length','put16(udp+4,udp_len+growth);','put16(udp+4,udp_len);'),
   ('skip_udp_checksum','put16(udp+6,checksum?checksum:65535u);','put16(udp+6,1u+(checksum&0u));'),
   ('forward_overlap_copy','for(size_t i=n;i>end+1+pad;i--)b[i-1+growth]=b[i-1];','for(size_t i=end+1+pad;i<n;i++)b[i+growth]=b[i];'),
  ]:
   assert source.count(old)==1,name
   p=t/'mutant.c';p.write_text(source.replace(old,new));r=host_test(p);assert r.returncode!=0,name
   negatives.append({'mutation':name,'detected':True})
  start=(ROOT/'work/uv310-wireguard/control-hardening/start.S').read_text().replace('PASS native adapter: handshake, client packet forwarding, NAT, checksums, bounds, rejection','PASS DHCP growth')
  (t/'start.S').write_text(start);(t/'test.ld').write_text('ENTRY(start)\nSECTIONS { .vectors 0 : { KEEP(*(.vectors)) } .text 0x1000 : { *(.start) *(.text*) *(.rodata*) } .state 0x20000000 : { *(.bss*) *(.data*) } /DISCARD/ : { *(.ARM.exidx*) } }')
  flags=['--target=arm-none-eabi','-mcpu=cortex-m3','-mthumb','-Oz','-ffreestanding','-fno-builtin','-I'+str(SRC),'-I'+str(t)]
  objs=[]
  for src in [SRC/'dhcp_dns.c',SRC/'dhcp_dns_grow.c',t/'tests.c',t/'start.S',ROOT/'work/uv310-wireguard/wg-port/runtime.c']:
   out=t/(src.stem+'.o');run([cc,*flags,'-c',str(src),'-o',str(out)]);objs.append(str(out))
  run([ld,'-T',str(t/'test.ld'),*objs,'-o',str(t/'test.elf')])
  result=run([q,'-M','mps2-an385','-nographic','-semihosting-config','enable=on,target=native','-kernel',str(t/'test.elf')],timeout=20)
  assert 'PASS DHCP growth' in result.stdout+result.stderr,result.stdout+result.stderr
 report={'scope':'Bounded DHCP growth standalone, synthetic host and Cortex-M3, no hardware deployment','host_vectors':len(cases),'qemu_vectors':len(cases),'host_sanitizers':san,'negative_controls':negatives,'case_names':[x[0] for x in cases],'source_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [SRC/'dhcp_dns.c',SRC/'dhcp_dns.h',SRC/'dhcp_dns_grow.c',SRC/'dhcp_dns_grow.h',Path(__file__)]},'maximum_growth_bytes':6,'maximum_frame_bytes':2048,'native_hook_integrated':False,'hardware_deployed':False}
 out=ROOT/'.test-results';out.mkdir(exist_ok=True);(out/'dhcp-growth-tests.json').write_text(json.dumps(report,indent=2)+'\n')
 print('PASS',len(cases),'host and Cortex-M3 vectors;',len(negatives),'negative controls')
if __name__=='__main__':main()
