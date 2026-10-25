"""Add bounded atomic heap/stack observations to proven one-boot rekey adapter."""
from pathlib import Path
import hashlib,json
P=Path('work/uv310-wireguard');N=P/'rekey-memory';L=P/'rekey-live';N.mkdir(exist_ok=True)
s=(L/'native.c').read_text()
memory='''/* Read-only, bounded, atomic observation of this exact ROM allocator.
 * A rejected list is not interpreted as zero available memory. */
void memory_snapshot(u32*v){
 u32 mask;__asm__ volatile("mrs %0,primask\\n cpsid i":"=r"(mask)::"memory");
 for(u32 i=0;i<16;i++)v[i]=0;
 v[0]=W(0x26c8);v[1]=W(0x2688);v[2]=W(0x26a4);v[3]=W(0x26cc);v[4]=W(0x2690);
 u32 p=W(0x26c4),end=0;v[8]=1;
 while(p){
  if((p&3)||p<0x1c000||!range(p,8)||p<end||v[7]>=256){v[8]=0;break;}
  u32 n=W(p),next=W(p+4);
  if(!range(p+8,n)||(n&3)||n>0x3c000-v[5]){v[8]=0;break;}
  v[5]+=n;if(n>v[6])v[6]=n;v[7]++;end=p+8+n;p=next;
 }
 u32 floor=W(0x1c3e8),top=W(0x1c3ec);v[10]=floor;v[11]=top;
 if(!(floor&3)&&floor>=0x30000&&floor<0x3c000&&top>=floor&&top<=0x3c000&&top-floor==0x1400){
  v[12]=1;
  for(u32 a=floor;a<top;a+=4){if(W(a)!=0x5354414b)break;v[9]+=4;}
 }
 v[13]=W(0x267c);v[14]=mask;
 __asm__ volatile("msr primask,%0"::"r"(mask):"memory");
}
'''
s=s.replace('void snapshot(void){',memory+'void snapshot(void){')
s=s.replace(' char*p=version;', ' if(status_page==3)memory_snapshot(v);\n char*p=version;')
s=s.replace('"AER"[status_page]', '"AERM"[status_page]').replace('status_page=(status_page+1)%3','status_page=(status_page+1)%4')
(N/'native.c').write_text(s)
(N/'native-config.h').write_bytes((L/'native-config.h').read_bytes())
t=(L/'tests.c').read_text()
cases='''
#if defined(TEST_MEMORY) || defined(TEST_MEMORY_BAD_NODE) || defined(TEST_MEMORY_CYCLE) || defined(TEST_MEMORY_SIZE) || defined(TEST_MEMORY_BAD_STACK)
 extern void memory_snapshot(u32*);u32 v[16];
 W(0x26c8)=4096;W(0x2688)=1024;W(0x26a4)=16;W(0x26cc)=2048;W(0x2690)=3;
 W(0x26c4)=0x34000;W(0x34000)=256;W(0x34004)=0x34200;W(0x34200)=512;W(0x34204)=0;
 W(0x1c3e8)=0x39000;W(0x1c3ec)=0x3a400;for(u32 a=0x39000;a<0x3a400;a+=4)W(a)=0x5354414b;
 W(0x39100)=0;
#ifdef TEST_MEMORY_BAD_NODE
 W(0x26c4)=0xfffffffcu;
#endif
#ifdef TEST_MEMORY_CYCLE
 W(0x34204)=0x34000;
#endif
#ifdef TEST_MEMORY_SIZE
 W(0x34000)=0xfffffffcu;
#endif
#ifdef TEST_MEMORY_BAD_STACK
 W(0x1c3ec)=0xffffffffu;
#endif
 memory_snapshot(v);CHECK(v[0]==4096&&v[1]==1024&&v[2]==16&&v[3]==2048&&v[4]==3);
#if defined(TEST_MEMORY_BAD_NODE) || defined(TEST_MEMORY_CYCLE) || defined(TEST_MEMORY_SIZE)
 CHECK(v[8]==0);
#else
 CHECK(v[8]&&v[5]==768&&v[6]==512&&v[7]==2);
#endif
#ifdef TEST_MEMORY_BAD_STACK
 CHECK(v[12]==0&&v[9]==0);
#else
 CHECK(v[12]&&v[9]==256);
#endif
 u32 mask;__asm__ volatile("mrs %0,primask":"=r"(mask));CHECK(mask==0);
 __asm__ volatile("cpsid i":::"memory");memory_snapshot(v);__asm__ volatile("mrs %0,primask":"=r"(mask));CHECK(mask==1&&v[14]==1);__asm__ volatile("cpsie i":::"memory");return 0;
#endif
'''
t=t.replace('int tests(void){','int tests(void){'+cases);(N/'tests.c').write_text(t)
b=(L/'test-build.py').read_text().replace("N=P/'rekey-live'","N=P/'rekey-memory'").replace("'LAB_WRAP']:","'LAB_WRAP','MEMORY','MEMORY_BAD_NODE','MEMORY_CYCLE','MEMORY_SIZE','MEMORY_BAD_STACK']:").replace('rekey-live-tests.json','rekey-memory-tests.json')
(N/'test-build.py').write_text(b)
# Fresh private inputs and file names are distinct from the already-used image.
b=(L/'package.py').read_text().replace('rekey-live','rekey-memory').replace('wg_rekeylive_','wg_rekeymemory_').replace("==20 and", "==25 and").replace('token_bytes(512)','token_bytes(256)').replace("'random_pool_bytes':512","'random_pool_bytes':256").replace("'pool_bytes':512","'pool_bytes':256")
(N/'package.py').write_text(b)
e={'base_source_sha256':hashlib.sha256((L/'native.c').read_bytes()).hexdigest(),'memory_source_sha256':hashlib.sha256(s.encode()).hexdigest(),'scope':'Bounded free list and stack sentinel reads; PRIMASK preserved; no entropy claims','new_random_pool_bytes':256,'device_written':False}
(N/'prepare.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e))
