"""Synthetic DHCP transformer tests: host sanitizers + Cortex-M3 QEMU.
No USB/network access or proprietary firmware. Does not integrate native hooks.
"""
from pathlib import Path
import hashlib,json,os,random,shutil,struct,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/'work/uv310-wireguard/dhcp-dns'
SERVER=bytes([192,168,100,1]);DNS=bytes([10,77,0,1])
cases=[]
def checksum(data):
    if len(data)%2:data+=b'\0'
    value=sum(struct.unpack('!%dH'%(len(data)//2),data))
    while value>>16:value=(value&65535)+(value>>16)
    return (~value)&65535

def repair(b, udp=True):
    h=(b[14]&15)*4;start=14+h;length=struct.unpack_from('!H',b,start+4)[0]
    b[24:26]=b'\0\0';struct.pack_into('!H',b,24,checksum(bytes(b[14:14+h])))
    if udp:
        b[start+6:start+8]=b'\0\0'
        value=checksum(bytes(b[26:34])+b'\0\x11'+struct.pack('!H',length)+bytes(b[start:start+length]))
        struct.pack_into('!H',b,start+6,value or 65535)
    return b

def options(items):
    result=bytearray();slots=[]
    for code,value in items:
        if code in (0,255):result.append(code);continue
        if code==6:slots.extend(range(len(result)+2,len(result)+2+len(value)))
        result+=bytes([code,len(value)])+value
    return result,slots

def packet(items, file=None, sname=None, ip_options=b'', padding=0, eth_padding=0, udp_zero=False):
    opts,slots=options(items)
    boot=bytearray(240);boot[0:3]=b'\x02\x01\x06';boot[4:8]=b'TEST';boot[16:20]=bytes([192,168,100,100]);boot[236:240]=bytes([99,130,83,99])
    positions=[240+i for i in slots]
    for start,size,seq in [(108,128,file),(44,64,sname)]:
        if seq is not None:
            value,fields=options(seq);assert len(value)<=size
            boot[start:start+len(value)]=value;positions.extend(start+i for i in fields)
    boot+=opts+bytes(padding)
    h=20+len(ip_options);udp=bytearray(struct.pack('!4H',67,68,8+len(boot),0))+boot
    ip=bytearray(20);ip[0]=0x40+h//4;struct.pack_into('!H',ip,2,h+len(udp));ip[8]=64;ip[9]=17;ip[12:16]=SERVER;ip[16:20]=bytes([255]*4);ip+=ip_options
    frame=bytearray(bytes([255]*6)+bytes([2,0,0,0,0,1])+b'\x08\x00')+ip+udp
    repair(frame)
    if udp_zero:frame[14+h+6:14+h+8]=b'\0\0'
    frame+=bytes([0xa5])*eth_padding
    return frame,[14+h+8+i for i in positions],14+h+8+240+len(opts)-1

def add(name,b,result,positions=(),insert=None,dns=DNS):
    expected=bytearray(b)
    if result==1:
        if insert is not None:expected[insert:insert+7]=b'\x06\x04'+dns+b'\xff'
        else:
            assert len(positions)%4==0 and positions
            for i,pos in enumerate(positions):expected[pos]=dns[i%4]
        repair(expected)
    cases.append((name,bytes(b),result,bytes(expected),dns))

END=(255,b'');TYPE=(53,b'\x05');OLD=SERVER
positives=[
 ('ack', [TYPE,(6,OLD),END],{}),
 ('offer_two_dns',[(53,b'\x02'),(6,OLD+bytes([8,8,8,8])),END],{}),
 ('split_255_1',[TYPE,(6,bytes(range(255))),(6,b'X'),END],{}),
 ('split_1_3',[TYPE,(6,OLD[:1]),(6,OLD[1:]),END],{}),
 ('split_main_file',[TYPE,(52,b'\x01'),(6,OLD[:1]),END],{'file':[(6,OLD[1:]),END]}),
 ('split_all_fields',[TYPE,(52,b'\x03'),(6,b'X'),END],{'file':[(6,b'YZ'),END],'sname':[(6,b'12345'),END]}),
 ('sname_only',[TYPE,(52,b'\x02'),END],{'sname':[(6,OLD),END]}),
 ('empty_chunk',[TYPE,(6,b''),(6,OLD),END],{}),
 ('unknown_and_pad',[(0,b''),TYPE,(222,b'ABC'),(6,OLD),(0,b''),END],{}),
 ('ipv4_options',[TYPE,(6,OLD),END],{'ip_options':bytes([1,1,1,0])}),
 ('zero_udp_checksum',[TYPE,(6,OLD),END],{'udp_zero':True}),
 ('odd_udp_length',[TYPE,(6,OLD),END],{'padding':1}),
 ('ether_padding',[TYPE,(6,OLD),END],{'eth_padding':20}),
 ('file_ignored_without_overload',[TYPE,(6,OLD),END],{'file':[(6,b'XXXX'),END]}),
]
for name,seq,kw in positives:
 b,slots,_=packet(seq,**kw)
 if name=='file_ignored_without_overload':slots=slots[:4]
 add(name,b,1,slots)
# A checksum of zero must be encoded as 0xffff, never as disabled UDP checksum.
b,slots,_=packet([TYPE,(6,OLD),END]);expected=bytearray(b)
for i,p in enumerate(slots):expected[p]=DNS[i%4]
for value in range(65536):
 expected[46:48]=struct.pack('!H',value);repair(expected)
 if expected[40:42]==b'\xff\xff':break
else:raise AssertionError('no zero-checksum fixture')
b[46:48]=struct.pack('!H',value);repair(b);add('computed_checksum_zero',b,1,slots)
for name,kind in [('insert_ack',5),('insert_offer',2)]:
 b,_,end=packet([(53,bytes([kind])),END],padding=6);add(name,b,1,insert=end)
b,_,end=packet([TYPE,(52,b'\x01'),END],file=[END],padding=8);add('insert_with_overload',b,1,insert=end)
# Golden output is idempotent, but still reported as handled.
_,b,_,expected,dns=cases[0];add('repeat_rewrite',expected,1,packet([TYPE,(6,OLD),END])[1])
for name,seq,kw,rc in [
 ('no_dns_no_room',[TYPE,END],{},-2),
 ('no_dns_short_room',[TYPE,END],{'padding':5},-2),
 ('empty_dns',[TYPE,(6,b''),END],{},-1),
 ('dns_aggregate_three',[TYPE,(6,b'ABC'),END],{},-1),
 ('missing_end',[TYPE,(6,OLD)],{},-1),
 ('duplicate_type',[TYPE,TYPE,(6,OLD),END],{},-1),
 ('missing_type',[(6,OLD),END],{},-1),
 ('type_two_bytes',[(53,b'\x05\x05'),(6,OLD),END],{},-1),
 ('bad_overload_zero',[TYPE,(52,b'\x00'),(6,OLD),END],{},-1),
 ('bad_overload_four',[TYPE,(52,b'\x04'),(6,OLD),END],{},-1),
 ('duplicate_overload',[TYPE,(52,b'\x01'),(52,b'\x01'),(6,OLD),END],{'file':[END]},-1),
 ('nested_overload',[TYPE,(52,b'\x01'),(6,OLD),END],{'file':[(52,b'\x01'),END]},-1),
 ('type_in_file',[TYPE,(52,b'\x01'),(6,OLD),END],{'file':[TYPE,END]},-1),
 ('unterminated_file',[TYPE,(52,b'\x01'),(6,OLD),END],{'file':[(6,OLD)]},-1),
 ('nak',[(53,b'\x06'),END],{},0),
 ('request',[(53,b'\x03'),END],{},0),
]:
 b,_,_=packet(seq,**kw);add(name,b,rc)
base,slots,_=packet([TYPE,(6,OLD),END])
for name,pos,value,rc,fix in [
 ('wrong_server',26,193,0,True),('not_ipv4',12,0x86,0,False),('not_udp',23,6,0,True),
 ('wrong_source_port',35,66,0,True),('wrong_dest_port',37,67,0,True),
 ('bad_ip_checksum',24,base[24]^1,-1,False),('bad_udp_checksum',40,base[40]^1,-1,False),
 ('bad_cookie',278,0,-1,True),('boot_request',42,1,-1,True),('wrong_htype',43,2,-1,True),
 ('wrong_hlen',44,5,-1,True),('option_truncated',286,255,-1,True),
 ('ip_reserved_flag',20,0x80,-1,True),('ip_more_fragments',20,0x20,-1,True),
 ('nonfirst_fragment',21,1,-1,True),('ip_df_allowed',20,0x40,1,True),
]:
 b=bytearray(base);b[pos]=value
 if fix:repair(b)
 add(name,b,rc,slots if rc==1 else ())
b=bytearray(base);struct.pack_into('!H',b,38,len(b)-34-1);repair(b);add('udp_length_mismatch',b,-1)
b=bytearray(base);b[14]=0x44;add('ihl_too_small',b,-1)
b=bytearray(base);b[14]=0x4f;repair(b,False);add('ihl_displaced_udp',b,0) # ports at new location are not DHCP
b=bytearray(base)+bytes(2049-len(base));add('frame_limit',b,-1)
b,_,end=packet([TYPE,END],padding=6);b[end+2]=0xa5;repair(b);add('insertion_would_clobber',b,-2)
for i,dns in enumerate([bytes(4),bytes([127,0,0,1]),bytes([224,1,2,3]),SERVER]):add('invalid_dns_'+str(i),base,-3,dns=dns)
# Exact-length heap allocations expose every truncated packet boundary to ASan.
qemu_cases=len(cases)
for n in range(len(base)):add('truncate_'+str(n),base[:n],0 if n<34 else -1)
rng=random.Random(0xD1C0)
for i in range(1000):
 b=bytearray(base);p=rng.randrange(42,len(b));b[p]^=1<<rng.randrange(8);add('udp_bitflip_'+str(i),b,-1)
HOST_RUNNER=r'''
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "dhcp_dns.h"
int main(void){uint32_t n;uint8_t server[4]={192,168,100,1},dns[4];
 while(fread(&n,4,1,stdin)==1){if(n>4096||fread(dns,4,1,stdin)!=1)return 2;
 uint8_t*b=malloc(n?n:1);if(!b||fread(b,1,n,stdin)!=n)return 3;
 int32_t result=dhcp_dns_rewrite(b,n,server,dns);
 if(fwrite(&result,4,1,stdout)!=1||fwrite(b,1,n,stdout)!=n)return 4;free(b);}return 0;}
'''
QEMU_RUNNER=r'''
#include "dhcp_dns.h"
#include "vectors.h"
static uint8_t buffer[4096+64];
int tests(void){const uint8_t server[4]={192,168,100,1};
 for(unsigned i=0;i<sizeof(vectors)/sizeof(vectors[0]);i++){
 const struct vector*v=&vectors[i];unsigned off=16+(i&3);
 for(unsigned j=0;j<sizeof(buffer);j++)buffer[j]=0xa5;
 for(unsigned j=0;j<v->n;j++)buffer[off+j]=v->input[j];
 if(dhcp_dns_rewrite(buffer+off,v->n,server,v->dns)!=v->result)return i+1;
 for(unsigned j=0;j<v->n;j++)if(buffer[off+j]!=v->expected[j])return i+1;
 for(unsigned j=0;j<off;j++)if(buffer[j]!=0xa5)return i+1;
 for(unsigned j=off+v->n;j<sizeof(buffer);j++)if(buffer[j]!=0xa5)return i+1;
 }return 0;}
'''
def run(cmd,**kw):
    result=subprocess.run(cmd,capture_output=True,text=True,**kw)
    if result.returncode:raise RuntimeError(result.stdout+result.stderr)
    return result
def encode_vectors(rows):
 s=['struct vector {unsigned n;int result;const unsigned char *input,*expected,*dns;};']
 for i,(_,b,rc,e,dns) in enumerate(rows):
  for field,data in [('input',b),('expected',e),('dns',dns)]:s.append('static const unsigned char '+field+str(i)+'[]={'+','.join(map(str,data))+ '};')
 s.append('static const struct vector vectors[]={')
 for i,(_,b,rc,e,dns) in enumerate(rows):s.append('{%d,%d,input%d,expected%d,dns%d},'%(len(b),rc,i,i,i))
 return '\n'.join(s+['};'])

def main():
 cc=os.environ.get('LLVM_CLANG') or shutil.which('clang');ld=os.environ.get('LLVM_LD') or shutil.which('ld.lld');q=os.environ.get('QEMU_ARM') or shutil.which('qemu-system-arm')
 host=os.environ.get('HOST_CLANG') or ('/usr/bin/clang' if os.uname().sysname=='Darwin' else cc)
 assert all([cc,ld,q,host]),'Set LLVM_CLANG, LLVM_LD, QEMU_ARM; host Clang needs sanitizer runtime'
 source=(SRC/'dhcp_dns.c').read_text();negative=[]
 sanitizers=os.environ.get('HOST_SANITIZERS','address,undefined')
 assert sanitizers in ('address,undefined','undefined')
 sdkflags=['-isysroot',os.environ['HOST_SDKROOT']] if os.environ.get('HOST_SDKROOT') else []
 with tempfile.TemporaryDirectory(prefix='uv310-dhcp-tests-') as d:
  t=Path(d);(t/'host.c').write_text(HOST_RUNNER)
  payload=b''.join(struct.pack('<I',len(b))+dns+b for _,b,_,_,dns in cases)
  def host_test(src):
   run([host,*sdkflags,'-std=c11','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize='+sanitizers,'-fno-sanitize-recover=all','-fno-omit-frame-pointer','-I'+str(SRC),str(src),str(t/'host.c'),'-o',str(t/'host')])
   result=subprocess.run([str(t/'host')],input=payload,capture_output=True,timeout=30)
   if result.returncode:return False, 'sanitizer/process failure'
   out=result.stdout;offset=0
   for name,b,rc,expected,dns in cases:
    if len(out)<offset+4+len(b):return False,'short output'
    actual=struct.unpack_from('<i',out,offset)[0];body=out[offset+4:offset+4+len(b)];offset+=4+len(b)
    if actual!=rc or body!=expected:return False,name
   return offset==len(out),'all golden vectors'
  ok,why=host_test(SRC/'dhcp_dns.c');assert ok,why
  for name,old,new in [
   ('skip_udp_integrity','if(get16(udp+6)&&finish(addsum(udp,len,pseudo)))','if(0)'),
   ('partial_mutation_on_reject','if(get16(udp+6)&&finish(addsum(udp,len,pseudo))) return DHCP_DNS_REJECT;', 'if(get16(udp+6)&&finish(addsum(udp,len,pseudo))) { udp[6]=0; return DHCP_DNS_REJECT; }'),
   ('accept_bad_dns_length','if(!s.dns_bytes||(s.dns_bytes&3u))','if(0)'),
   ('restart_split_dns_offset','unsigned len=p[i++];\n        if(code==6) for','unsigned len=p[i++]; *offset=0;\n        if(code==6) for'),
   ('leave_old_checksum','put16(udp+6,checksum?checksum:65535u);','put16(udp+6,1u+(checksum&0u));'),
  ]:
   assert source.count(old)==1,(name,source.count(old));mutant=t/'mutant.c';mutant.write_text(source.replace(old,new));ok,why=host_test(mutant);assert not ok,name
   negative.append({'mutation':name,'detected':True,'first_difference':why})
  (t/'tests.c').write_text(QEMU_RUNNER);(t/'vectors.h').write_text(encode_vectors(cases[:qemu_cases]))
  start=(ROOT/'work/uv310-wireguard/control-hardening/start.S').read_text().replace('PASS native adapter: handshake, client packet forwarding, NAT, checksums, bounds, rejection','PASS DHCP transformer')
  (t/'start.S').write_text(start);(t/'test.ld').write_text('ENTRY(start)\nSECTIONS { .vectors 0 : { KEEP(*(.vectors)) } .text 0x1000 : { *(.start) *(.text*) *(.rodata*) } .state 0x20000000 : { *(.bss*) *(.data*) } /DISCARD/ : { *(.ARM.exidx*) } }')
  flags=['--target=arm-none-eabi','-mcpu=cortex-m3','-mthumb','-Oz','-ffreestanding','-fno-builtin','-fstack-usage','-I'+str(SRC),'-I'+str(t)]
  objects=[]
  for f in [SRC/'dhcp_dns.c',t/'tests.c',t/'start.S',ROOT/'work/uv310-wireguard/wg-port/runtime.c']:
   o=t/(f.stem+'.o');run([cc,*flags,'-c',str(f),'-o',str(o)]);objects.append(str(o))
  run([ld,'-T',str(t/'test.ld'),*objects,'-o',str(t/'test.elf')])
  result=run([q,'-M','mps2-an385','-nographic','-semihosting-config','enable=on,target=native','-kernel',str(t/'test.elf')],timeout=20)
  assert 'PASS DHCP transformer' in result.stdout+result.stderr,result.stdout+result.stderr
  stack=[]
  for line in (t/'dhcp_dns.su').read_text().splitlines():
   function,size,kind=line.split('\t');stack.append({'function':function.rsplit(':',1)[-1],'bytes':int(size),'kind':kind})
  blob=(t/'dhcp_dns.o').read_bytes();header=struct.unpack_from('<16sHHIIIIIHHHHHH',blob)
  sizes={'executable_bytes':0,'writable_bytes':0,'readonly_allocated_bytes':0}
  for i in range(header[12]):
   entry=struct.unpack_from('<10I',blob,header[6]+i*header[11]);flags,size=entry[2],entry[5]
   if flags&2:sizes['executable_bytes' if flags&4 else ('writable_bytes' if flags&1 else 'readonly_allocated_bytes')]+=size
  result={'scope':'Standalone unintegrated DHCP DNS transformer; synthetic host sanitizers and Cortex-M3 QEMU; no device access',
   'host_compiler':run([host,'--version']).stdout.splitlines()[0],
   'target_compiler':run([cc,'--version']).stdout.splitlines()[0],
   'host_sanitizers':sanitizers,'host_golden_vectors':len(cases),'qemu_golden_vectors':qemu_cases,'exhaustive_truncations':len(base),'udp_bitflip_rejections':1000,
   'named_cases':[x[0] for x in cases[:qemu_cases]],'negative_controls':negative,'compiler_stack_frames':stack,'cortex_m3_object_sizes':sizes,
   'source_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [SRC/'dhcp_dns.c',SRC/'dhcp_dns.h',Path(__file__)]},
   'native_hook_integrated':False,'hardware_deployed':False,'dns_bypass_fixed':False,
   'limitations':['Single replacement DNS repeated in all existing slots','No VLAN, IPv6, relay or packet resizing support','No-space requires future caller policy; never pass silently in protected mode','Source IP matching is not authentication; trusted packet direction required','No real DHCP lease, DNS resolution, performance or memory-pressure verification']}
  out=ROOT/'.test-results';out.mkdir(exist_ok=True);(out/'dhcp-dns-tests.json').write_text(json.dumps(result,indent=2)+'\n')
  print('PASS',len(cases),'host vectors;',qemu_cases,'Cortex-M3 vectors;',len(negative),'negative controls detected')
if __name__=='__main__':main()
