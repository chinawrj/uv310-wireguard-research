/* Offline renewal integration: RNG/time/persistence remain unresolved. */
#ifndef HARDWARE_LAYOUT_AUDIT
#error Hardware-address layout audit only; not a deployable image
#endif
#include "wireguard.h"
#include "crypto.h"
#include <string.h>
#include "native-config.h"
#include "checked-random.h"
typedef uint32_t u32;typedef uint16_t u16;typedef uint8_t u8;
#define W(a) (*(volatile u32 *)(a))
extern volatile u32 phase;
static struct wireguard_device dev;
struct wireguard_device *fixture_device(void){return &dev;}
#define KEY_RENEW_MS (REKEY_AFTER_TIME*1000u)
#define KEY_REJECT_MS (REJECT_AFTER_TIME*1000u)
#define RETRY_MS (REKEY_TIMEOUT*1000u)
#define MAX_TRIES 18u
static u32 initialized,cycle_tries,retry_paused,demand,try_started,retry_wait;
u32 renewals,handshake_failures;
static u32 control_key_index;
static int key_live(struct wireguard_keypair*k,u32 now){return k->valid&&(u32)(now-k->keypair_millis)<KEY_REJECT_MS;}
static int can_send(u32 now){struct wireguard_keypair*k=&dev.peers[0].curr_keypair;return key_live(k,now)&&k->sending_valid&&k->sending_counter<REJECT_AFTER_MESSAGES;}
static int data_phase(void){return phase==2||phase==3||phase==4||phase==9;}
static u8 initiation[148] __attribute__((aligned(4))), received[256] __attribute__((aligned(4)));
volatile u32 phase;
volatile u32 pending,timer_count;
u32 rng_failed,worker_count,err,rng_pos,tx_count,rx_count,init_time,response_time,receive_len,echo_verified;
static u8 ethernet[14],control[190] __attribute__((aligned(4)));
volatile u32 control_ready,control_packet;
u32 control_len,control_kind,attempts,submitted,freed,free_payload_delta,free_header_delta,keepalive_tx,last_send,last_keepalive,control_errors,send_ipsr,send_mask;
u32 source_context,destination_context,release_pointer,release_payload,release_headers;
static u32 status_page;
extern u32 raw_alloc(u32),submit(u32,u32,u32);extern void raw_packet_free(u32);
static u8 client_ip[4],client_mac[6];static u16 client_port;
u32 f_tx,f_rx,f_drop,f_out_bytes,f_in_bytes,session_start;
__attribute__((section(".version"))) char version[192]="5.90.153.52.1";
static u16 be16(const u8*p){return ((u16)p[0]<<8)|p[1];}
static void put16(u8*p,u16 x){p[0]=x>>8;p[1]=x;}
static u16 checksum(const u8*p,u32 n){u32 x=0;while(n>1){x+=be16(p);p+=2;n-=2;}if(n)x+=(u16)p[0]<<8;while(x>>16)x=(x&65535)+(x>>16);return (u16)~x;}
static int range(u32 p,u32 n){return p>=0x2000&&p<0x3c000&&n<=0x3c000-p;}
uint32_t wireguard_sys_now(void){
#ifdef SYNTHETIC_TEST
 extern volatile u32 fixture_clock,fixture_step;fixture_clock+=fixture_step;return fixture_clock;
#else
 /* Shared clock is maintained by stock timer paths; avoid a new thread/ISR
  * race in the ROM clock updater. Timing fields are cached ticks, not benchmarks. */
 return W(0x267c);
#endif
}
bool wireguard_random_bytes_checked(void *v,size_t n){
 if(rng_failed||rng_pos>sizeof(RANDOM_POOL)||n>sizeof(RANDOM_POOL)-rng_pos){
  rng_failed=1;err=0xe1;memset(v,0,n);return false;
 }
 memcpy(v,RANDOM_POOL+rng_pos,n);rng_pos+=n;return true;
}
void wireguard_tai64n_now(u8*v){
 memcpy(v,TAI64N,12);
 u32 nano=((u32)v[8]<<24)|((u32)v[9]<<16)|((u32)v[10]<<8)|v[11];
 u32 carry=attempts/1000000000u;nano+=attempts%1000000000u;
 if(nano>=1000000000u){nano-=1000000000u;carry++;}
 for(int i=7;i>=0&&carry;i--){u32 sum=v[i]+carry;v[i]=(u8)sum;carry=sum>>8;}
 v[8]=nano>>24;v[9]=nano>>16;v[10]=nano>>8;v[11]=nano;
}
bool wireguard_is_under_load(void){return false;}
/* Terminal failure is separate from the transient worker phase. */
volatile u32 stopped;
static u32 control_queued_at;
#ifdef SYNTHETIC_TEST
extern void fixture_before_publish(u32 next);
#endif
static void publish_phase(u32 next){
#ifdef SYNTHETIC_TEST
 fixture_before_publish(next);
#endif
 u32 mask;__asm__ volatile("mrs %0,primask\n cpsid i":"=r"(mask)::"memory");
 if(stopped){phase=255;control_ready=0;}else phase=next;
 __asm__ volatile("msr primask,%0"::"r"(mask):"memory");
}
static void fail(u32 e){stopped=1;__asm__ volatile("":::"memory");err=e;control_ready=0;phase=255;}
static int control_expired(u32 kind,u32 now){
 if(kind==1)return (u32)(now-control_queued_at)>=RETRY_MS;
 if(kind==2)return !can_send(now)||control_key_index!=dev.peers[0].curr_keypair.local_index;
 return 1;
}
static void discard_control(u32 kind){
 control_ready=0;control_errors++;
 if(kind==1){last_send=control_queued_at;publish_phase(3);}
}
/* Claim under PRIMASK: a just-arrived response cannot be replaced by retry. */
#ifdef SYNTHETIC_TEST
extern void fixture_before_claim(u32 expected);
#endif
static int claim_phase(u32 expected,u32 busy){
#ifdef SYNTHETIC_TEST
 fixture_before_claim(expected);
#endif
 u32 mask;__asm__ volatile("mrs %0,primask\n cpsid i":"=r"(mask)::"memory");
 int ok=!stopped&&phase==expected;if(ok)phase=busy;
 __asm__ volatile("msr primask,%0"::"r"(mask):"memory");return ok;
}
static void expire_keys(u32 now){
 struct wireguard_peer*p=&dev.peers[0];
 struct wireguard_keypair*k[3]={&p->curr_keypair,&p->prev_keypair,&p->next_keypair};
 for(u32 i=0;i<3;i++)if(k[i]->valid&&!key_live(k[i],now))keypair_destroy(k[i]);
}
/* Single-client IPv4 forwarding experiment. Return 1 means caller consumes
 * raw packet with the original raw-release routine; 0 continues original ops. */
static u32 addsum(const u8*p,u32 n,u32 x){while(n>1){x+=be16(p);p+=2;n-=2;}if(n)x+=(u16)*p<<8;return x;}
static void copy_down(u8*d,const u8*s,u32 n){while(n--)*d++=*s++;}
static u16 finishsum(u32 x){while(x>>16)x=(x&65535)+(x>>16);return (u16)~x;}
static int ip_valid(const u8*ip,u32 bytes){
 if(bytes<20||(ip[0]>>4)!=4)return 0;
 u32 h=(ip[0]&15)*4,n=be16(ip+2);if(h<20||h>60||h>n||n>bytes||(be16(ip+6)&0x3fff)||ip[8]<2)return 0;
 const u8*t=ip+h;u32 l=n-h;
 if(ip[9]==17)return l>=8&&be16(t+4)==l;
 if(ip[9]==1)return l>=8&&(t[0]==0||t[0]==8);
 if(ip[9]!=6||l<20)return 0;
 u32 th=(t[12]>>4)*4;if(th<20||th>l)return 0;
 for(u32 i=20;i<th;){u32 kind=t[i];if(!kind)break;if(kind==1){i++;continue;}if(i+2>th||t[i+1]<2||t[i+1]>th-i)return 0;if(kind==2&&t[i+1]!=4)return 0;i+=t[i+1];}
 return 1;
}
static void translate(u8*ip,const u8*address,u32 incoming){
 u32 h=(ip[0]&15)*4,n=be16(ip+2),l=n-h;u8*t=ip+h;memcpy(ip+(incoming?16:12),address,4);ip[8]--;
 if(ip[9]==6&&(t[13]&2)){
  for(u32 i=20;i<(u32)(t[12]>>4)*4;){u32 kind=t[i];if(!kind)break;if(kind==1){i++;continue;}if(kind==2&&be16(t+i+2)>1380)put16(t+i+2,1380);i+=t[i+1];}
 }
 u32 offset=ip[9]==6?16:(ip[9]==17?6:2);t[offset]=t[offset+1]=0;
 u32 initial=ip[9]==1?0:addsum(ip+12,8,l+ip[9]);u16 sum=finishsum(addsum(t,l,initial));
 if(ip[9]==17&&!sum)sum=0xffff;put16(t+offset,sum);
 ip[10]=ip[11]=0;put16(ip+10,checksum(ip,h));
}
static int drop(u32 reason){f_drop++;if(phase!=255)err=reason;return 1;}
static int forward(u32 dir,u32 pkt){
 if(stopped)return drop(0x25);
 u32 data=W(pkt+16),n=*(volatile u16*)(pkt+20);u8*b=(u8*)data,*ip=b+14;
 if(n<34)return 0;
 u32 et=be16(b+12);
 if(!dir&&et==0x86dd&&!memcmp(b+6,client_mac,6))return drop(0x21);
 if(et!=0x800)return 0;
 if(!dir){
  if(memcmp(ip+12,client_ip,4))return 0;
  /* Keep LAN management/DHCP/ARP reachable; DNS policy remains unfinished. */
  if(!memcmp(ip+16,LAN_GATEWAY,3)||ip[16]>=224)return 0;
 }else{
  if(memcmp(ip+16,client_ip,4))return 0;
  if(memcmp(ip+12,ENDPOINT_IP,4)||ip[0]!=0x45||ip[9]!=17||n<42||be16(b+34)!=ENDPOINT_PORT||be16(b+36)!=client_port){
   if(memcmp(ip+12,LAN_GATEWAY,3))return drop(0x22);return 0;
  }
 }
 if(!range(pkt,0x44)||W(pkt)||(*(volatile u16*)(pkt+22)&0x40)||*(volatile u8*)(pkt+0x1d)!=1)return drop(0x23);
 u32 head=W(pkt+8),end=W(pkt+12);
 if(head>data||end<data||n>end-data||!range(head,end-head))return drop(0x24);
 u32 now=wireguard_sys_now();
 if(!dir&&!can_send(now))return drop(0x25);
 if(!dir){
  if(!ip_valid(ip,n-14))return drop(0x26);
  u32 len=be16(ip+2);if(len>1420)return drop(0x27);
  u32 padded=(len+15)&~15u,shift=(60+padded-len+3)&~3u;
  if(data-head<shift+64)return drop(0x28);
  u8*out=b-shift,*inner=out+58,*outer=out+14,*udp=out+34,*wg=out+42;
  memcpy(out,b,14);copy_down(inner,ip,len);translate(inner,INNER_SOURCE,0);memset(inner+len,0,padded-len);
  memset(wg,0,16);wg[0]=4;U32TO8_LITTLE(wg+4,dev.peers[0].curr_keypair.remote_index);U64TO8_LITTLE(wg+8,dev.peers[0].curr_keypair.sending_counter);
  wireguard_encrypt_packet(inner,inner,padded,&dev.peers[0].curr_keypair);
  dev.peers[0].curr_keypair.last_tx=now;
  memset(outer,0,28);outer[0]=0x45;put16(outer+2,60+padded);outer[8]=64;outer[9]=17;
  memcpy(outer+12,client_ip,4);memcpy(outer+16,ENDPOINT_IP,4);put16(outer+10,checksum(outer,20));
  put16(udp,client_port);put16(udp+2,ENDPOINT_PORT);put16(udp+4,40+padded);
  W(pkt+16)=(u32)out;*(volatile u16*)(pkt+20)=74+padded;f_tx++;f_out_bytes+=len;return 0;
 }
 u32 total=be16(ip+2),ulen=be16(b+38);
 if((be16(ip+6)&0x3fff)||total<60||total>n-14||ulen!=total-20)return drop(0x29);
 u32 plen=ulen-8;u8*wg=b+42;
 if(plen<32||U8TO32_LITTLE(wg)!=4)return drop(0x2a);
 struct wireguard_keypair*k=get_peer_keypair_for_idx(&dev.peers[0],U8TO32_LITTLE(wg+4));
 uint64_t count=U8TO64_LITTLE(wg+8);u32 padded=plen-32;u8*inner=wg+16;
 if(!k||!key_live(k,now)||!k->receiving_valid||count>=REJECT_AFTER_MESSAGES)return drop(0x2a);
 if(!wireguard_decrypt_packet(inner,inner,plen-16,count,k)||!wireguard_check_replay(k,count))return drop(0x2b);
 k->last_rx=now;
 if(!padded)return drop(0x2c); /* authenticated keepalive, consumed */
 if(!ip_valid(inner,padded)||memcmp(inner+16,INNER_SOURCE,4))return drop(0x2d);
 u32 len=be16(inner+2);translate(inner,client_ip,1);memcpy(b+44,b,14);
 W(pkt+16)=data+44;*(volatile u16*)(pkt+20)=14+len;f_rx++;f_in_bytes+=len;return 0;
}
static int context(u32 src,u32 dst){
 if((dst&3)||!range(dst,28))return 0;
 u32 soft=W(dst+24);if((soft&3)||!range(soft,28))return 0;
 u32 ctx=W(soft+24);if((ctx&3)||!range(ctx,76))return 0;
 u32 osh=W(ctx+4),bus=W(ctx+12);
 if((osh&3)||!range(osh,4)||(bus&3)||!range(bus,76)||W(bus+72)>256)return 0;
 if(src==0||src==W(ctx+60))return 1;
 u32 n=W(ctx+72),p=W(ctx+64);if(n>16||(p&3)||!range(p,n*4))return 0;
 for(u32 i=0;i<n;i++)if(W(p+4*i)==src)return 1;return 0;
}

static void make_control(const u8*payload,u32 bytes,u32 kind){
 if(stopped)return;control_queued_at=wireguard_sys_now();
 control_key_index=dev.peers[0].curr_keypair.local_index;
 memcpy(control,ethernet,14);u8*ip=control+14,*udp=control+34;memset(ip,0,28);
 ip[0]=0x45;put16(ip+2,28+bytes);ip[8]=64;ip[9]=17;memcpy(ip+12,client_ip,4);memcpy(ip+16,ENDPOINT_IP,4);put16(ip+10,checksum(ip,20));
 put16(udp,client_port);put16(udp+2,ENDPOINT_PORT);put16(udp+4,8+bytes);memcpy(control+42,payload,bytes);
 control_len=42+bytes;control_kind=kind;__asm__ volatile("":::"memory");control_ready=kind;
}
static void prepare_keepalive(void){
 if(!can_send(wireguard_sys_now()))return;
 u8 message[32];memset(message,0,sizeof(message));message[0]=4;
 U32TO8_LITTLE(message+4,dev.peers[0].curr_keypair.remote_index);U64TO8_LITTLE(message+8,dev.peers[0].curr_keypair.sending_counter);
 wireguard_encrypt_packet(message+16,message+16,0,&dev.peers[0].curr_keypair);make_control(message,32,2);last_keepalive=wireguard_sys_now();
}
void release_before(u32 p){if(!control_packet||p!=control_packet||release_pointer)return;release_pointer=p;release_payload=W(0x2688);release_headers=W(0x26a4);}
void release_after(u32 p){if(!release_pointer||p!=release_pointer)return;free_payload_delta=release_payload-W(0x2688);free_header_delta=release_headers-W(0x26a4);release_pointer=0;freed++;__asm__ volatile("":::"memory");control_packet=0;}
void emit_control(void){
 if(stopped||!control_ready||control_packet)return;
 u32 kind=control_ready;
 if((kind==1&&phase!=2)||(kind==2&&phase!=9))return;
 if(control_expired(kind,wireguard_sys_now())){discard_control(kind);return;}
 u32 irq,mask;__asm__ volatile("mrs %0,ipsr":"=r"(irq));__asm__ volatile("mrs %0,primask":"=r"(mask));send_ipsr=irq;send_mask=mask;
#ifndef SYNTHETIC_TEST
 if(irq!=16||mask||!context(source_context,destination_context)||W(0x18c)!=0x806bcd||W(0x2b4)!=0x80aa5d){control_errors++;fail(0xe3);return;}
#endif
 if((kind==1&&phase!=2)||(kind==2&&phase!=9))return;
 u32 p=raw_alloc(512);if(!p){control_errors++;fail(0xe4);return;}
 if((p&3)||!range(p,68)){control_errors++;fail(0xe5);return;}
 u32 h=W(p+8),end=W(p+12);
 if(h!=p+68||end-h!=512||!range(h,512)||W(p)||(*(u16*)(p+22)&0x240)||*(u8*)(p+29)!=1){raw_packet_free(p);control_errors++;fail(0xe5);return;}
 W(p+16)=h+256;*(u16*)(p+20)=control_len;memcpy((void*)(h+256),control,control_len);
 if(stopped||control_expired(kind,wireguard_sys_now())){raw_packet_free(p);discard_control(kind);return;}
 control_packet=p;control_ready=0;submitted++;last_send=wireguard_sys_now();if(kind==1){tx_count++;publish_phase(3);}else keepalive_tx++;
 __asm__ volatile("":::"memory");submit(source_context,destination_context,p);
}
/* No special host packet or AT query is needed. First ordinary external IPv4
 * packet identifies a single client, and is dropped while worker prepares keys.
 * The timer independently allocates and submits initiation; further traffic is held closed
 * until an authenticated response has been processed by the idle worker. */
int intercept(u32 dir,u32 pkt,u32 src,u32 dst){
 if((pkt&3)||!range(pkt,0x44))return 0;
 u32 data=W(pkt+16),n=*(volatile u16*)(pkt+20);if(n<14||!range(data,n))return 0;
 u8*b=(u8*)data,*ip=b+14;u32 et=be16(b+12);
 if(!dir&&et==0x86dd)return drop(0x32);
 if(et!=0x800||n<34)return 0;
 if(!dir){
  if(!memcmp(ip+16,LAN_GATEWAY,3)||ip[16]>=224)return 0;
  if(memcmp(ip+12,LAN_GATEWAY,3)||ip[15]<2||ip[15]==255)return drop(0x33);
  if(n>2048||!ip_valid(ip,n-14))return drop(0x34);
  if(!stopped&&phase==0){
   if(!context(src,dst))return drop(0x39);
   source_context=src;destination_context=dst;memcpy(ethernet,b,14);
   memcpy(client_ip,ip+12,4);memcpy(client_mac,b+6,6);client_port=59997;
   __asm__ volatile("":::"memory");publish_phase(1);return drop(0x35);
  }
  if(memcmp(ip+12,client_ip,4)||memcmp(b+6,client_mac,6))return drop(0x36);
  if(!stopped&&data_phase()){demand=1;return forward(dir,pkt);}
  return drop(0x37);
 }
 if(phase==0||memcmp(ip+16,client_ip,4))return 0;
 if(!memcmp(ip+12,LAN_GATEWAY,3))return 0;
 if(n>=42&&ip[0]==0x45&&ip[9]==17&&!(be16(ip+6)&0x3fff)&&!memcmp(ip+12,ENDPOINT_IP,4)&&be16(b+34)==ENDPOINT_PORT&&be16(b+36)==client_port){
  u32 total=be16(ip+2),ulen=be16(b+38);u8*p=b+42;
  if(total==120&&total<=n-14&&ulen==100&&phase==3&&U8TO32_LITTLE(p)==2){
   memcpy(received,p,92);receive_len=92;rx_count++;
   __asm__ volatile("":::"memory");publish_phase(4);
  }
 }
 if(!stopped&&data_phase())return forward(dir,pkt);
 return drop(0x38); /* Never deliver handshake/control UDP to client stack. */
}
void signal_timer(void *unused){(void)unused;timer_count++;pending=1;emit_control();}
/* Crypto remains in the idle worker. While phase10/11/12 owns mutable state,
 * interrupt packet hooks drop external traffic instead of racing crypto. */
void worker(void){
 u32 ipsr,primask;__asm__ volatile("mrs %0,ipsr":"=r"(ipsr));__asm__ volatile("mrs %0,primask":"=r"(primask));
 if(stopped||ipsr||primask||!pending)return;pending=0;worker_count++;
 u32 current=phase,now=wireguard_sys_now();
 if(current==3){
  if((u32)(now-last_send)<RETRY_MS||control_packet)return;
  if(!claim_phase(3,10))return;
  if(cycle_tries>=MAX_TRIES){
   crypto_zero(&dev.peers[0].handshake,sizeof(dev.peers[0].handshake));
   retry_paused=1;demand=0;retry_wait=1;try_started=now;publish_phase(9);return;
  }
  current=1;
 }else if(current==9){
  if(!claim_phase(9,12))return;
  expire_keys(now);
  if(!control_ready&&!control_packet&&
    (!retry_wait||(u32)(now-try_started)>=RETRY_MS)&&(!retry_paused||demand)&&
    (!can_send(now)||(u32)(now-dev.peers[0].curr_keypair.keypair_millis)>=KEY_RENEW_MS||dev.peers[0].curr_keypair.sending_counter>=REKEY_AFTER_MESSAGES)){
   retry_paused=0;demand=0;cycle_tries=0;current=1;publish_phase(10);
  }else{
   if(can_send(now)&&(u32)(now-last_keepalive)>=20000&&!control_ready&&!control_packet)prepare_keepalive();
   publish_phase(9);return;
  }
 }else if(current==1){if(!claim_phase(1,10))return;}
 else if(current==4){if(!claim_phase(4,11))return;}
 else return;
 u32 begin=wireguard_sys_now();
 expire_keys(begin);
 if(current==1){
  try_started=begin;retry_wait=1;cycle_tries++;
  /* Never reset this serial at rekey. Fixed synthetic TAI+serial is monotonic
   * within a run, but is NOT reboot-safe freshness. */
  if(attempts==0xffffffffu){fail(0xe8);return;}attempts++;
  if(!initialized){
   wireguard_init();
   if(!wireguard_device_init(&dev,PRIVATE_KEY)||!wireguard_peer_init(&dev,&dev.peers[0],PEER_KEY,PRESHARED_KEY)){fail(1);return;}
   initialized=1;
  }
  if(!wireguard_create_handshake_initiation(&dev,&dev.peers[0],(struct message_handshake_initiation*)initiation)||rng_failed){
   handshake_failures++;err=2;retry_paused=1;demand=0;publish_phase(9);
  }else{make_control(initiation,148,1);publish_phase(2);}
  init_time=wireguard_sys_now()-begin;
 }else{
  struct message_handshake_response*r=(void*)received;
  if((u32)(begin-try_started)>=KEY_REJECT_MS||r->receiver!=dev.peers[0].handshake.local_index||!wireguard_check_mac1(&dev,received,60,r->mac1)||!wireguard_process_handshake_response(&dev,&dev.peers[0],r)){
   handshake_failures++;err=3;crypto_zero(received,sizeof(received));publish_phase(3);
  }else{
   if(dev.peers[0].curr_keypair.valid)renewals++;
   wireguard_start_session(&dev.peers[0],true);session_start=dev.peers[0].curr_keypair.keypair_millis;
   retry_paused=0;retry_wait=0;cycle_tries=0;demand=0;err=0;
   crypto_zero(received,sizeof(received));prepare_keepalive();publish_phase(9);
  }
  response_time=wireguard_sys_now()-begin;
 }
}
void snapshot(void){
 u32 v[16]={phase,err,tx_count,rx_count,rng_pos,init_time,response_time,receive_len,worker_count,f_tx,f_rx,f_drop,f_out_bytes,f_in_bytes,W(0x2690),W(0x267c)};
 if(status_page){u32 e[16]={attempts,control_ready,control_kind,control_packet,submitted,freed,free_payload_delta,free_header_delta,keepalive_tx,last_send,source_context,destination_context,send_ipsr,send_mask,control_errors,W(0x267c)};memcpy(v,e,sizeof(v));}
 char*p=version;const char*s="5.90.153.52.1 ";while(*s)*p++=*s++;*p++=status_page?'E':'A';*p++='=';status_page^=1;
 for(u32 i=0;i<16;i++){for(int j=28;j>=0;j-=4)*p++="0123456789abcdef"[(v[i]>>j)&15];*p++=i==15?0:',';}
}
