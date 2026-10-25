/* Synthetic adapter integration tests; never linked into live candidate. */
#include "wireguard.h"
#include "crypto.h"
#include <string.h>
#include "native-config.h"
typedef uint32_t u32;typedef uint16_t u16;typedef uint8_t u8;
extern void snapshot(void);extern int intercept(u32,u32,u32,u32);
#define intercept(d,p) intercept(d,p,0x33c00,0x33d00)
extern u32 control_ready,control_packet,attempts,submitted,freed,keepalive_tx,last_send,last_keepalive;extern void release_before(u32),release_after(u32);
volatile u32 fixture_clock=1000,fixture_step=0;
static u32 alloc_calls,expiry_alloc,inject_publish;
extern volatile u32 stopped;extern void emit_control(void);
void fixture_before_publish(u32 next){if(next==9&&inject_publish){inject_publish=0;fixture_clock+=180000;emit_control();}}
static u8 sent[190];static u32 sent_bytes;
#define W(a) (*(volatile u32*)(a))
/* Packet ownership is modeled separately from submit return status. */
static u32 alloc_null,alloc_bad_layout,defer_release,owned_packet,alloc_success,raw_frees,ownership_errors;
static u32 submit_result;
static void release_owned(u32 p){
 if(owned_packet!=p){ownership_errors++;return;}
 release_before(p);W(0x2688)-=580;W(0x26a4)-=8;owned_packet=0;release_after(p);
}
u32 fake_alloc(u32 n){
 alloc_calls++;if(expiry_alloc)fixture_clock+=180000;
 if(n!=512||alloc_null)return 0;
 if(owned_packet){ownership_errors++;return 0;}
 u32 p=0x34200;owned_packet=p;alloc_success++;
 memset((void*)p,0,68);W(p+8)=p+68;W(p+12)=p+580;W(p+16)=p+68;
 *(u16*)(p+20)=512;*(u8*)(p+29)=alloc_bad_layout?0:1;
 W(0x2688)+=580;W(0x26a4)+=8;return p;
}
u32 fake_submit(u32 src,u32 dst,u32 p){
 (void)src;(void)dst;
 if(owned_packet!=p){ownership_errors++;return submit_result;}
 sent_bytes=*(u16*)(p+20);if(sent_bytes<=190)memcpy(sent,(void*)W(p+16),sent_bytes);
 if(!defer_release)release_owned(p);return submit_result;
}
extern u32 f_tx,f_rx,f_drop,session_start;extern volatile u32 phase;extern u32 err,rng_pos;extern void worker(void),signal_timer(void*);extern char version[];
static struct wireguard_device server;
static struct wireguard_keypair *active_server_key;
volatile unsigned failure_line;
extern struct wireguard_device *fixture_device(void);
extern u32 renewals,handshake_failures,rng_failed,lab_origin;
/* Independent test-only ledger at the crypto API boundary. Neither linked
 * into the native candidate nor a new cryptographic implementation. */
struct nonce_record {u8 key[32];uint64_t highest;u32 used;};
static struct nonce_record nonce_records[8];
static u32 nonce_errors,nonce_encryptions,nonce_keys;
extern void __real_wireguard_encrypt_packet(u8*,const u8*,size_t,struct wireguard_keypair*);
void __wrap_wireguard_encrypt_packet(u8*d,const u8*s,size_t len,struct wireguard_keypair*k){
 struct wireguard_peer*p=&fixture_device()->peers[0];
 if(k==&p->curr_keypair||k==&p->prev_keypair||k==&p->next_keypair){
  u32 i;for(i=0;i<nonce_keys;i++)if(!memcmp(nonce_records[i].key,k->sending_key,32))break;
  if(i==nonce_keys){
   if(nonce_keys>=8){nonce_errors++;goto encrypt;}
   memcpy(nonce_records[i].key,k->sending_key,32);nonce_keys++;
  }
  if(nonce_records[i].used&&k->sending_counter<=nonce_records[i].highest)nonce_errors++;
  nonce_records[i].highest=k->sending_counter;nonce_records[i].used=1;nonce_encryptions++;
 }
encrypt:
 __real_wireguard_encrypt_packet(d,s,len,k);
}
static u32 fixture_alignment;
static u8 decoded[1700],reply[1740];
#define CHECK(x) do{if(!(x)){if(!failure_line)failure_line=__LINE__;return failure_line;}}while(0)
static void put16(u8*p,u16 n){p[0]=n>>8;p[1]=n;}
static u16 sum(const u8*p,u32 n){u32 x=0;for(u32 i=0;i<n;i+=2)x+=((u16)p[i]<<8)|(i+1<n?p[i+1]:0);while(x>>16)x=(x&65535)+(x>>16);return ~x;}
static u8 *frame(u32 incoming,const void *msg,u32 len){
 u8 *b=(u8*)(0x35140+fixture_alignment);memset((void*)0x35000,0,0x44);memset((void*)0x35040,0,0x900);*(u32*)0x35008=0x35040;*(u32*)0x3500c=0x35940;*(u8*)0x3501d=1;*(u32*)0x35010=(u32)b;*(u16*)0x35014=42+len;
 b[12]=8;b[14]=0x45;put16(b+16,28+len);b[22]=64;b[23]=17;
 static const u8 client[4]={192,168,100,100};
 memcpy(b+26,incoming?ENDPOINT_IP:client,4);memcpy(b+30,incoming?client:LAN_GATEWAY,4);
 put16(b+34,incoming?ENDPOINT_PORT:51888);put16(b+36,incoming?59997:59998);put16(b+38,8+len);put16(b+24,sum(b+14,20));
 if(msg)memcpy(b+42,msg,len);return b;
}
static u8*ordinary(u32 proto,u32 payload);
static int forward_tests(void);
static struct message_handshake_response response,old_response;
static struct wireguard_keypair old_server;
static u32 inject_claim;
void fixture_before_claim(u32 expected){
 if(expected==3&&inject_claim){inject_claim=0;frame(1,&response,92);intercept(1,0x35000);}
}
static int make_response(void){
 struct message_handshake_initiation init;memcpy(&init,sent+42,148);
 CHECK(sent_bytes==190&&wireguard_check_mac1(&server,(u8*)&init,116,init.mac1));
 CHECK(wireguard_process_initiation_message(&server,&init)==&server.peers[0]);
 CHECK(wireguard_create_handshake_response(&server,&server.peers[0],&response));
 wireguard_start_session(&server.peers[0],false);return 0;
}
static int complete_response(void){
 frame(1,&response,92);CHECK(intercept(1,0x35000)==1&&phase==4);
 signal_timer(0);worker();CHECK(phase==9&&!stopped&&control_ready==2);
 signal_timer(0);CHECK(!control_ready&&!control_packet&&submitted==freed);
 struct wireguard_keypair*k=&server.peers[0].next_keypair;
 CHECK(sent_bytes==74&&U8TO32_LITTLE(sent+46)==k->local_index);
 CHECK(wireguard_decrypt_packet(decoded,sent+58,16,U8TO64_LITTLE(sent+50),k));
 CHECK(wireguard_check_replay(k,U8TO64_LITTLE(sent+50)));
 keypair_update(&server.peers[0],k);active_server_key=&server.peers[0].curr_keypair;return 0;
}
static int one_forward(u32,u32);
static int late_packet(struct wireguard_keypair*k,int accepted){
 /* Valid inner echo reply under explicitly selected old/new transport key. */
 memset(decoded,0,32);decoded[0]=0x45;put16(decoded+2,28);decoded[8]=64;decoded[9]=1;
 memcpy(decoded+12,INNER_DEST,4);memcpy(decoded+16,INNER_SOURCE,4);
 memset(reply,0,16);reply[0]=4;U32TO8_LITTLE(reply+4,k->remote_index);U64TO8_LITTLE(reply+8,k->sending_counter);
 wireguard_encrypt_packet(reply+16,decoded,32,k);u32 before=f_rx;
 frame(1,reply,64);CHECK(intercept(1,0x35000)==(accepted?0:1));CHECK(f_rx==before+(accepted?1:0));
 if(accepted){frame(1,reply,64);CHECK(intercept(1,0x35000)==1&&f_rx==before+1);}return 0;
}
/* Verify external IPv4 stays closed after a terminal allocator fault,
 * even after allocator capacity returns. LAN bypass remains separate policy. */
static int terminal_alloc_check(u32 expected,u32 calls,u32 submits,u32 payload,u32 headers){
 CHECK(stopped&&phase==255&&err==expected&&!control_ready&&!control_packet);
 CHECK(!owned_packet&&!ownership_errors&&submitted==submits);
 CHECK(W(0x2688)==payload&&W(0x26a4)==headers);
 alloc_null=alloc_bad_layout=0;u32 tx=f_tx;
 for(u32 i=0;i<8;i++){
  fixture_clock+=1000;signal_timer(0);worker();
  ordinary(17,13);CHECK(intercept(0,0x35000)==1);
 }
 CHECK(stopped&&err==expected&&alloc_calls==calls&&submitted==submits&&f_tx==tx);
 return 0;
}
/* Capacity can return without a new handshake or re-encrypting a queued
 * keepalive. Repeated timer/worker calls must not spin on allocation. */
static int recover_alloc(u32 expected_phase){
 u32 calls=alloc_calls,submits=submitted,random=rng_pos,serial=attempts;
 u32 payload=W(0x2688),headers=W(0x26a4),kind=control_ready;
 uint64_t counter=fixture_device()->peers[0].curr_keypair.sending_counter;
 alloc_null=1;signal_timer(0);
 CHECK(!stopped&&phase==expected_phase&&control_ready==kind&&!owned_packet&&!control_packet);
 CHECK(alloc_calls==calls+1&&submitted==submits&&W(0x2688)==payload&&W(0x26a4)==headers);
 if(!fixture_device()->peers[0].curr_keypair.valid){u32 closed_tx=f_tx;ordinary(17,13);CHECK(intercept(0,0x35000)==1&&f_tx==closed_tx);}
 for(u32 i=0;i<8;i++){signal_timer(0);worker();}
 fixture_clock+=249;signal_timer(0);worker();CHECK(alloc_calls==calls+1);
#ifdef TEST_PRESSURE_SECOND_FAIL
 fixture_clock++;signal_timer(0);CHECK(alloc_calls==calls+2&&control_ready==kind&&!stopped);
 fixture_clock+=249;signal_timer(0);CHECK(alloc_calls==calls+2);
#endif
 alloc_null=0;fixture_clock++;signal_timer(0);
 CHECK(!stopped&&!control_ready&&!control_packet&&!owned_packet&&!ownership_errors&&submitted==submits+1&&submitted==freed);
 CHECK(rng_pos==random&&attempts==serial&&fixture_device()->peers[0].curr_keypair.sending_counter==counter);
 CHECK(W(0x2688)==payload&&W(0x26a4)==headers);return 0;
}
static int scenario(void){
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

#ifdef TEST_TAI_CARRY
 u8 last[12],now[12];u32 serials[]={0,1,999999999u,1000000000u,2000000000u,4294967294u};
 for(u32 i=0;i<6;i++){
  attempts=serials[i];wireguard_tai64n_now(now);
  u32 n=((u32)now[8]<<24)|((u32)now[9]<<16)|((u32)now[10]<<8)|now[11];CHECK(n<1000000000u);
  if(i)CHECK(memcmp(last,now,12)<0);memcpy(last,now,12);
 }
 return 0;
#endif
 W(0x33d18)=0x33e00;W(0x33e18)=0x33f00;W(0x33f04)=0x34000;W(0x33f0c)=0x34100;W(0x34148)=64;W(0x33f3c)=0x33c00;
 #ifdef TEST_PRESSURE_WRAP
 fixture_clock=0xffffff80u;
#endif
 ordinary(1,0);CHECK(intercept(0,0x35000)==1&&phase==1);
 signal_timer(0);worker();CHECK(phase==2&&attempts==1);
#if defined(TEST_ALLOC_NULL_FIRST) || defined(TEST_PRESSURE_WRAP) || defined(TEST_PRESSURE_SECOND_FAIL)
 CHECK(recover_alloc(2)==0);CHECK(phase==3);
#else
 signal_timer(0);CHECK(phase==3&&submitted==freed);
#endif
 CHECK(wireguard_device_init(&server,SERVER_PRIVATE));CHECK(wireguard_peer_init(&server,&server.peers[0],CLIENT_PUBLIC,PRESHARED_KEY));
 CHECK(make_response()==0);CHECK(complete_response()==0);old_response=response;
 struct wireguard_peer*p=&fixture_device()->peers[0];
#ifdef TEST_NONCE_LEDGER_PROBE
 /* Deliberately reuse the initial keepalive counter. No decrypt/packet check
  * follows; only the independent ledger should make tests() fail. */
 p->curr_keypair.sending_counter=0;
 wireguard_encrypt_packet(decoded,decoded,0,&p->curr_keypair);
 return 0;
#endif
#if defined(TEST_ALLOC_NULL_FIRST) || defined(TEST_PRESSURE_WRAP) || defined(TEST_PRESSURE_SECOND_FAIL)
 CHECK(one_forward(17,25)==0);return 0;
#endif
#if defined(TEST_NONCE_DELAYED_KEEPALIVE) || defined(TEST_NONCE_DISCARDED_KEEPALIVE) || defined(TEST_NONCE_REKEY_PRESSURE) || defined(TEST_NONCE_WRAP_INTERLEAVE)
 /* Queue an encrypted keepalive, then send ordinary traffic while allocation
  * is unavailable. Sending counters follow encryption order, not submit order. */
#ifdef TEST_NONCE_WRAP_INTERLEAVE
 fixture_clock=0xffffff80u;lab_origin=fixture_clock-20000u;
 p->curr_keypair.keypair_millis=fixture_clock-20000u;last_keepalive=fixture_clock-20000u;
#else
 fixture_clock=last_keepalive+20000;
#endif
 signal_timer(0);worker();CHECK(control_ready==2&&phase==9);
 uint64_t queued_counter=p->curr_keypair.sending_counter-1;
 u32 start_encryptions=nonce_encryptions,start_random=rng_pos,start_attempts=attempts,start_submits=submitted;
 alloc_null=1;signal_timer(0);CHECK(control_ready==2&&!stopped);
 CHECK(one_forward(17,17)==0);CHECK(one_forward(17,19)==0);
 CHECK(p->curr_keypair.sending_counter==queued_counter+3&&nonce_encryptions==start_encryptions+2);
 CHECK(rng_pos==start_random&&attempts==start_attempts&&submitted==start_submits);
 fixture_clock+=249;signal_timer(0);worker();CHECK(control_ready==2&&submitted==start_submits);
#ifdef TEST_NONCE_DISCARDED_KEEPALIVE
 fixture_clock++;signal_timer(0);CHECK(control_ready==2);
 fixture_clock+=250;signal_timer(0);CHECK(!control_ready&&!stopped&&submitted==start_submits);
 CHECK(p->curr_keypair.sending_counter==queued_counter+3&&nonce_encryptions==start_encryptions+2);
 CHECK(one_forward(17,21)==0);
 fixture_clock=last_keepalive+20000;signal_timer(0);worker();CHECK(control_ready==2);
 CHECK(p->curr_keypair.sending_counter==queued_counter+5);
 alloc_null=0;signal_timer(0);CHECK(U8TO64_LITTLE(sent+50)==queued_counter+4);
#else
 alloc_null=0;fixture_clock++;signal_timer(0);CHECK(!control_ready&&submitted==start_submits+1);
 CHECK(U8TO64_LITTLE(sent+50)==queued_counter&&nonce_encryptions==start_encryptions+2);
#endif
 CHECK(wireguard_decrypt_packet(decoded,sent+58,16,U8TO64_LITTLE(sent+50),active_server_key));
 CHECK(wireguard_check_replay(active_server_key,U8TO64_LITTLE(sent+50)));
 CHECK(one_forward(17,23)==0);CHECK(!nonce_errors&&nonce_keys==1);
#ifdef TEST_NONCE_REKEY_PRESSURE
 u8 prior_key[32];memcpy(prior_key,p->curr_keypair.sending_key,32);
 fixture_clock=p->curr_keypair.keypair_millis+120000;last_keepalive=fixture_clock;
 signal_timer(0);worker();CHECK(phase==2&&control_ready==1);
 CHECK(recover_alloc(2)==0);CHECK(one_forward(17,25)==0);
 CHECK(make_response()==0);CHECK(complete_response()==0);CHECK(renewals==1);
 CHECK(memcmp(prior_key,p->curr_keypair.sending_key,32)&&p->curr_keypair.sending_counter==1);
 CHECK(nonce_keys==2&&!nonce_errors);CHECK(one_forward(17,27)==0);
#endif
 CHECK(!nonce_errors&&!owned_packet&&!ownership_errors&&submitted==freed);return 0;
#endif
#if defined(TEST_ALLOC_NULL_KEEPALIVE) || defined(TEST_PRESSURE_KEEP_LIMIT) || defined(TEST_PRESSURE_KEY_DEADLINE) || defined(TEST_PRESSURE_LAB_DEADLINE)
 fixture_clock=last_keepalive+20000;signal_timer(0);worker();CHECK(phase==9&&control_ready==2);
#ifdef TEST_ALLOC_NULL_KEEPALIVE
 CHECK(recover_alloc(9)==0);
 CHECK(wireguard_decrypt_packet(decoded,sent+58,16,U8TO64_LITTLE(sent+50),active_server_key));
 CHECK(wireguard_check_replay(active_server_key,U8TO64_LITTLE(sent+50)));
 CHECK(one_forward(17,25)==0);return 0;
#else
 u32 pressure_calls=alloc_calls,pressure_submits=submitted,pressure_random=rng_pos;
 uint64_t pressure_counter=p->curr_keypair.sending_counter;
#ifdef TEST_PRESSURE_KEY_DEADLINE
 fixture_clock=p->curr_keypair.keypair_millis+179900;
#elif defined(TEST_PRESSURE_LAB_DEADLINE)
 lab_origin=fixture_clock-359999u;
#endif
 alloc_null=1;signal_timer(0);CHECK(!stopped&&control_ready==2&&alloc_calls==pressure_calls+1);
#ifdef TEST_PRESSURE_KEEP_LIMIT
 fixture_clock+=250;signal_timer(0);CHECK(!stopped&&control_ready==2&&alloc_calls==pressure_calls+2);
 fixture_clock+=250;signal_timer(0);CHECK(!stopped&&!control_ready&&phase==9&&alloc_calls==pressure_calls+3);
 CHECK(rng_pos==pressure_random&&p->curr_keypair.sending_counter==pressure_counter&&submitted==pressure_submits);
 for(u32 i=0;i<8;i++){signal_timer(0);worker();}CHECK(alloc_calls==pressure_calls+3&&!control_ready);
 CHECK(one_forward(17,25)==0);
 fixture_clock=last_keepalive+19999;signal_timer(0);worker();CHECK(!control_ready);
 fixture_clock++;signal_timer(0);worker();CHECK(control_ready==2&&p->curr_keypair.sending_counter>pressure_counter);
 alloc_null=0;signal_timer(0);CHECK(submitted==pressure_submits+1&&submitted==freed&&!stopped);
 CHECK(wireguard_decrypt_packet(decoded,sent+58,16,U8TO64_LITTLE(sent+50),active_server_key));
 CHECK(wireguard_check_replay(active_server_key,U8TO64_LITTLE(sent+50)));
 CHECK(one_forward(17,27)==0);return 0;
#else
#ifdef TEST_PRESSURE_KEY_DEADLINE
 fixture_clock+=100;signal_timer(0);CHECK(!stopped&&!control_ready&&alloc_calls==pressure_calls+1);
#else
 fixture_clock++;signal_timer(0);CHECK(stopped&&phase==255&&err==0xe9&&!control_ready&&alloc_calls==pressure_calls+1);
#endif
 CHECK(rng_pos==pressure_random&&p->curr_keypair.sending_counter==pressure_counter&&submitted==pressure_submits);
 u32 pressure_tx=f_tx;ordinary(17,13);CHECK(intercept(0,0x35000)==1&&f_tx==pressure_tx);return 0;
#endif
#endif
#endif
#if defined(TEST_LAB_PACKET) || defined(TEST_LAB_TIMER) || defined(TEST_LAB_WORKER) || defined(TEST_LAB_WRAP)
#ifdef TEST_LAB_WRAP
 lab_origin=0xffff0000u;
#endif
 fixture_clock=lab_origin+359999;u32 submits=submitted;
 /* Packet hook must close at the boundary even without a timer/worker. */
#if defined(TEST_LAB_PACKET) || defined(TEST_LAB_WRAP)
 fixture_clock++;ordinary(17,9);CHECK(intercept(0,0x35000)==1);
#elif defined(TEST_LAB_TIMER)
 fixture_clock++;signal_timer(0);
#else
 fixture_clock++;worker();
#endif
 CHECK(stopped&&phase==255&&err==0xe9&&!control_ready&&submitted==submits);
 signal_timer(0);worker();CHECK(submitted==submits);return 0;
#endif

#ifdef TEST_BASELINE
 CHECK(forward_tests()==0);return 0;
#endif
 CHECK(one_forward(17,31)==0);CHECK(one_forward(6,0)==0);CHECK(one_forward(1,11)==0);
 u32 first_index=p->curr_keypair.local_index,first_start=p->curr_keypair.keypair_millis;
#ifdef TEST_WRAP
 first_start=0xffff0000u;p->curr_keypair.keypair_millis=first_start;lab_origin=first_start;
#endif
 fixture_clock=first_start+119999;last_keepalive=fixture_clock;signal_timer(0);worker();CHECK(phase==9&&attempts==1&&!control_ready);
#ifdef TEST_COUNT_REKEY
 p->curr_keypair.sending_counter=REKEY_AFTER_MESSAGES;
#else
 fixture_clock=first_start+120000;
#endif
#ifdef TEST_RNG_FAIL
 rng_pos=sizeof(RANDOM_POOL);
#endif
 signal_timer(0);worker();
#ifdef TEST_RNG_FAIL
 CHECK(!stopped&&phase==9&&err==2&&handshake_failures==1&&!control_ready);
 CHECK(p->curr_keypair.valid&&p->curr_keypair.local_index==first_index);CHECK(one_forward(17,13)==0);
 u32 tries=attempts;signal_timer(0);worker();CHECK(attempts==tries);
 fixture_clock=first_start+180000;ordinary(17,13);CHECK(intercept(0,0x35000)==1);signal_timer(0);worker();CHECK(!p->curr_keypair.valid&&!stopped);return 0;
#endif
 CHECK(phase==2&&attempts==2&&p->curr_keypair.valid&&p->curr_keypair.local_index==first_index);
 CHECK(one_forward(17,19)==0); /* forwarding while initiation is queued */
#if defined(TEST_ALLOC_NULL_REKEY)
 CHECK(recover_alloc(2)==0);CHECK(phase==3);CHECK(one_forward(17,21)==0);
 CHECK(make_response()==0);CHECK(complete_response()==0);CHECK(renewals==1);CHECK(one_forward(17,25)==0);return 0;
#endif
#ifdef TEST_ALLOC_BAD_LAYOUT
 u32 calls=alloc_calls,submits=submitted,payload=W(0x2688),headers=W(0x26a4),success=alloc_success;
 alloc_bad_layout=1;signal_timer(0);CHECK(alloc_success==success+1&&raw_frees==1&&p->curr_keypair.valid);
 return terminal_alloc_check(0xe5,calls+1,submits,payload,headers);
#endif
#if defined(TEST_PRESSURE_INIT_LIMIT) || defined(TEST_PRESSURE_BUDGET_RESET) || defined(TEST_PRESSURE_QUEUE_DEADLINE) || defined(TEST_PRESSURE_NULL_EXPIRE)
 u32 pressure_start=fixture_clock,pressure_calls=alloc_calls,pressure_submits=submitted,pressure_random=rng_pos,pressure_attempts=attempts;
 alloc_null=1;
#ifdef TEST_PRESSURE_NULL_EXPIRE
 expiry_alloc=1;signal_timer(0);CHECK(!stopped&&!control_ready&&phase==3&&alloc_calls==pressure_calls+1&&!owned_packet);
 CHECK(submitted==pressure_submits&&rng_pos==pressure_random&&attempts==pressure_attempts);return 0;
#endif
 signal_timer(0);CHECK(!stopped&&control_ready==1&&alloc_calls==pressure_calls+1);
#ifdef TEST_PRESSURE_QUEUE_DEADLINE
 fixture_clock+=5000;signal_timer(0);CHECK(!stopped&&!control_ready&&phase==3&&alloc_calls==pressure_calls+1);
 CHECK(submitted==pressure_submits&&rng_pos==pressure_random&&attempts==pressure_attempts);CHECK(one_forward(17,25)==0);return 0;
#else
 CHECK(one_forward(17,21)==0);fixture_clock+=250;signal_timer(0);CHECK(control_ready==1&&alloc_calls==pressure_calls+2);
 fixture_clock+=250;signal_timer(0);CHECK(!stopped&&!control_ready&&phase==3&&alloc_calls==pressure_calls+3);
 CHECK(submitted==pressure_submits&&rng_pos==pressure_random&&attempts==pressure_attempts);
 fixture_clock=pressure_start+4999;signal_timer(0);worker();CHECK(attempts==pressure_attempts&&alloc_calls==pressure_calls+3);
 fixture_clock++;signal_timer(0);worker();CHECK(phase==2&&attempts==pressure_attempts+1&&rng_pos>pressure_random);
#ifdef TEST_PRESSURE_BUDGET_RESET
 /* A new control message gets a new bounded budget; not the old exhausted one. */
 signal_timer(0);CHECK(control_ready==1&&alloc_calls==pressure_calls+4&&!stopped);
 fixture_clock+=250;signal_timer(0);CHECK(control_ready==1&&alloc_calls==pressure_calls+5);
 fixture_clock+=250;signal_timer(0);CHECK(!control_ready&&phase==3&&alloc_calls==pressure_calls+6&&!stopped);
 fixture_clock=pressure_start+10000;signal_timer(0);worker();CHECK(phase==2&&attempts==pressure_attempts+2);
#endif

 alloc_null=0;signal_timer(0);CHECK(phase==3&&!stopped);CHECK(make_response()==0);CHECK(complete_response()==0);CHECK(one_forward(17,25)==0);return 0;
#endif
#endif
#if defined(TEST_DEFERRED_RELEASE) || defined(TEST_HELD_RELEASE_EXPIRY) || defined(TEST_SUBMIT_NONZERO)
 u32 submits=submitted,payload=W(0x2688),headers=W(0x26a4),releases=freed;
 defer_release=1;
#ifdef TEST_SUBMIT_NONZERO
 submit_result=7;
#endif
 signal_timer(0);CHECK(phase==3&&control_packet==0x34200&&owned_packet==control_packet&&submitted==submits+1&&freed==releases);
 CHECK(W(0x2688)==payload+580&&W(0x26a4)==headers+8&&!ownership_errors);
 u32 calls=alloc_calls;CHECK(make_response()==0);
 /* Unrelated free observations must not release the outstanding packet. */
 release_before(0x34000);release_after(0x34000);CHECK(control_packet==0x34200&&freed==releases);
#ifdef TEST_HELD_RELEASE_EXPIRY
 fixture_clock=first_start+180000;u32 held_tx=f_tx;
 ordinary(17,13);CHECK(intercept(0,0x35000)==1&&f_tx==held_tx);
 for(u32 i=0;i<8;i++){signal_timer(0);worker();}
 CHECK(alloc_calls==calls&&attempts==2&&submitted==submits+1&&control_packet==owned_packet&&!stopped);
 release_owned(0x34200);defer_release=0;
 CHECK(freed==releases+1&&!control_packet&&W(0x2688)==payload&&W(0x26a4)==headers);
 signal_timer(0);worker();CHECK(phase==2&&attempts==3);
 signal_timer(0);CHECK(make_response()==0);CHECK(complete_response()==0);CHECK(one_forward(17,25)==0);
#else
 fixture_clock=last_send+5001;
 for(u32 i=0;i<8;i++){signal_timer(0);worker();}
 CHECK(alloc_calls==calls&&attempts==2&&phase==3&&!stopped);
 frame(1,&response,92);CHECK(intercept(1,0x35000)==1&&phase==4);
 signal_timer(0);worker();CHECK(phase==9&&renewals==1&&control_ready==2&&control_packet==owned_packet);
 for(u32 i=0;i<8;i++){signal_timer(0);worker();}
 CHECK(alloc_calls==calls&&submitted==submits+1&&freed==releases);
 release_owned(0x34200);CHECK(!control_packet&&freed==releases+1&&!owned_packet);
 CHECK(W(0x2688)==payload&&W(0x26a4)==headers);
 /* Duplicate callback observations (not a second real free) are ignored. */
 release_before(0x34200);release_after(0x34200);CHECK(freed==releases+1&&!control_packet);
 defer_release=0;signal_timer(0);CHECK(!control_ready&&submitted==submits+2&&submitted==freed);
 struct wireguard_keypair*k=&server.peers[0].next_keypair;
 CHECK(wireguard_decrypt_packet(decoded,sent+58,16,U8TO64_LITTLE(sent+50),k));
 CHECK(wireguard_check_replay(k,U8TO64_LITTLE(sent+50)));keypair_update(&server.peers[0],k);active_server_key=&server.peers[0].curr_keypair;
 CHECK(one_forward(17,25)==0);
#endif
 CHECK(!owned_packet&&!ownership_errors&&submitted==freed&&W(0x2688)==payload&&W(0x26a4)==headers);return 0;
#endif

#ifdef TEST_QUEUE_EXPIRE
 fixture_clock+=5000;u32 submits=submitted;signal_timer(0);CHECK(submitted==submits&&phase==3&&!control_ready&&!stopped);
 CHECK(one_forward(17,20)==0);worker();CHECK(phase==2&&attempts==3);return 0;
#endif
 signal_timer(0);CHECK(phase==3&&submitted==freed);
 CHECK(make_response()==0);old_server=server.peers[0].curr_keypair;
 CHECK(one_forward(17,21)==0); /* forwarding while waiting for response */
#ifdef TEST_BAD_MAC
 response.mac1[0]^=1;
#elif defined(TEST_BAD_AEAD)
 ((u8*)&response)[44]^=1;wireguard_blake2s(response.mac1,16,server.peers[0].label_mac1_key,32,&response,60);
#elif defined(TEST_STALE_RESPONSE)
 response=old_response;
#endif
#if defined(TEST_BAD_MAC)||defined(TEST_BAD_AEAD)||defined(TEST_STALE_RESPONSE)
 frame(1,&response,92);CHECK(intercept(1,0x35000)==1&&phase==4);signal_timer(0);worker();
 CHECK(phase==3&&!stopped&&handshake_failures==1&&p->curr_keypair.local_index==first_index);CHECK(one_forward(17,23)==0);
 fixture_clock=last_send+5000;signal_timer(0);worker();CHECK(phase==2&&attempts==3);signal_timer(0);CHECK(make_response()==0);CHECK(complete_response()==0);CHECK(renewals==1);CHECK(one_forward(17,25)==0);return 0;
#endif
#ifdef TEST_CLAIM_RACE
 fixture_clock=last_send+5000;inject_claim=1;signal_timer(0);worker();
 CHECK(phase==4&&attempts==2&&inject_claim==0);
 CHECK(complete_response()==0&&renewals==1);CHECK(one_forward(17,23)==0);return 0;
#endif
#ifdef TEST_RETRY
 fixture_clock=last_send+4999;signal_timer(0);worker();CHECK(phase==3&&attempts==2);
 fixture_clock++;signal_timer(0);worker();CHECK(phase==2&&attempts==3);CHECK(one_forward(17,23)==0);
 signal_timer(0);CHECK(make_response()==0);
#endif
#ifdef TEST_RETRY_LIMIT
 for(u32 i=0;i<18;i++){
  fixture_clock=last_send+5000;signal_timer(0);worker();
  if(i<17){CHECK(phase==2&&!stopped);signal_timer(0);}else CHECK(phase==9&&!stopped&&!p->handshake.valid);
 }
 u32 tries=attempts;fixture_clock+=10000;signal_timer(0);worker();CHECK(attempts==tries&&phase==9);
 ordinary(17,13);CHECK(intercept(0,0x35000)==1);signal_timer(0);worker();CHECK(phase==2&&attempts==tries+1);
 signal_timer(0);CHECK(make_response()==0);CHECK(complete_response()==0);CHECK(one_forward(17,27)==0);return 0;
#endif
 frame(1,&response,92);CHECK(intercept(1,0x35000)==1&&phase==4);CHECK(one_forward(17,23)==0);old_server=server.peers[0].curr_keypair;
#ifdef TEST_PUBLISH_EXPIRY
 inject_publish=1;signal_timer(0);worker();CHECK(!stopped&&phase==9&&control_ready==2);
 u32 before_publish=submitted;signal_timer(0);CHECK(!control_ready&&submitted==before_publish&&!stopped);return 0;
#endif
#ifdef TEST_ALLOC_EXPIRE
 signal_timer(0);worker();CHECK(phase==9&&control_ready==2);u32 submits=submitted,bytes=W(0x2688),headers=W(0x26a4);expiry_alloc=1;
 signal_timer(0);CHECK(!stopped&&submitted==submits&&!control_ready&&!control_packet&&W(0x2688)==bytes&&W(0x26a4)==headers);return 0;
#endif
 /* Worker has not processed buffered response; complete_response replays frame,
  * which is ignored while phase4, then processes the already-buffered response. */
 CHECK(complete_response()==0);CHECK(renewals==1&&p->prev_keypair.local_index==first_index&&p->curr_keypair.local_index!=first_index);
 CHECK(one_forward(17,25)==0);CHECK(one_forward(6,0)==0);CHECK(one_forward(1,11)==0);
#ifdef TEST_COUNT_REJECT
 p->curr_keypair.sending_counter=REJECT_AFTER_MESSAGES;u32 limit_tx=f_tx;ordinary(17,9);CHECK(intercept(0,0x35000)==1&&f_tx==limit_tx);
 old_server.sending_counter=REJECT_AFTER_MESSAGES;CHECK(late_packet(&old_server,0)==0);return 0;
#endif
 CHECK(late_packet(&old_server,1)==0);
 fixture_clock=first_start+179999;CHECK(late_packet(&old_server,1)==0);
 fixture_clock++;CHECK(late_packet(&old_server,0)==0);CHECK(one_forward(17,29)==0);
 last_keepalive=fixture_clock;signal_timer(0);worker();CHECK(!p->prev_keypair.valid);
 /* Delay every timer/worker past new-key expiry: the packet hook itself must reject. */
 fixture_clock=p->curr_keypair.keypair_millis+180000;u32 tx=f_tx;ordinary(17,9);CHECK(intercept(0,0x35000)==1&&f_tx==tx);
 CHECK(late_packet(active_server_key,0)==0);signal_timer(0);worker();CHECK(!p->curr_keypair.valid&&phase==2&&!stopped);
 signal_timer(0);CHECK(make_response()==0);CHECK(complete_response()==0);CHECK(one_forward(17,31)==0);
 CHECK(submitted==freed&&!control_packet);return 0;
}

static u32 frees;
void fake_free(u32 ptr){if(ptr==0x34200){if(owned_packet!=ptr){ownership_errors++;return;}raw_frees++;release_owned(ptr);return;}if(ptr==0x35000)frees++;else frees=999;}
extern int packet1(u32,u32,u32);
static const u8 client[4]={192,168,100,100};
static u16 be16(const u8*p){return ((u16)p[0]<<8)|p[1];}
static u16 transport_sum(u8*ip){
 u32 len=be16(ip+2)-20,x=0;if(ip[9]!=1){for(u32 i=12;i<20;i+=2)x+=be16(ip+i);x+=len+ip[9];}
 for(u32 i=0;i<len;i+=2)x+=((u16)ip[20+i]<<8)|(i+1<len?ip[21+i]:0);while(x>>16)x=(x&65535)+(x>>16);return ~x;
}
static void fix_sums(u8*ip){u32 off=ip[9]==6?16:ip[9]==17?6:2;ip[20+off]=ip[21+off]=0;u16 x=transport_sum(ip);put16(ip+20+off,ip[9]==17&&!x?65535:x);ip[10]=ip[11]=0;put16(ip+10,sum(ip,20));}
static u8*ordinary(u32 proto,u32 payload){
 u8*b=frame(0,0,0),*ip=b+14,*t=ip+20;u32 len=20+(proto==6?24:8)+payload;
 memset(ip,0,len);ip[0]=0x45;put16(ip+2,len);ip[8]=64;ip[9]=proto;memcpy(ip+12,client,4);memcpy(ip+16,INNER_DEST,4);
 for(u32 i=0;i<payload;i++)t[(proto==6?24:8)+i]=(u8)(i^0xa5);
 if(proto==1){t[0]=8;put16(t+4,0x1234);put16(t+6,9);}
 else{put16(t,54321);put16(t+2,proto==17?53:443);if(proto==17)put16(t+4,8+payload);else{t[12]=0x60;t[13]=2;put16(t+14,8192);t[20]=2;t[21]=4;put16(t+22,1460);}}
 fix_sums(ip);*(u16*)0x35014=14+len;return b;
}
static int one_forward(u32 proto,u32 payload){
 u32 before=f_tx,before_rx=f_rx;u8*b=ordinary(proto,payload);u32 inner_len=be16(b+16),oldend=(u32)b+14+inner_len;
 CHECK(intercept(0,0x35000)==0&&f_tx==before+1);
 b=(u8*)*(u32*)0x35010;u32 len=*(u16*)0x35014;CHECK((u32)b+len<=oldend&&oldend-(u32)b-len<=3&&((u32)b&3)==fixture_alignment&&sum(b+14,20)==0);
 CHECK(!memcmp(b+30,ENDPOINT_IP,4)&&be16(b+36)==ENDPOINT_PORT);
 CHECK(wireguard_decrypt_packet(decoded,b+58,len-58,U8TO64_LITTLE(b+50),active_server_key));
 CHECK(!memcmp(decoded+12,INNER_SOURCE,4)&&!memcmp(decoded+16,INNER_DEST,4)&&sum(decoded,20)==0&&transport_sum(decoded)==0);
 CHECK(decoded[8]==63);if(proto==6)CHECK(be16(decoded+42)==1380);
 memcpy(decoded+12,INNER_DEST,4);memcpy(decoded+16,INNER_SOURCE,4);
 if(proto==1)decoded[20]=0;else{u16 port=be16(decoded+20);put16(decoded+20,be16(decoded+22));put16(decoded+22,port);}
 decoded[8]=64;fix_sums(decoded);u32 padded=(inner_len+15)&~15u;
 memset(reply,0,16);reply[0]=4;U32TO8_LITTLE(reply+4,active_server_key->remote_index);U64TO8_LITTLE(reply+8,active_server_key->sending_counter);
 wireguard_encrypt_packet(reply+16,decoded,padded,active_server_key);
 b=frame(1,reply,padded+32);CHECK(intercept(1,0x35000)==0&&f_rx==before_rx+1);
 u8*out=(u8*)*(u32*)0x35010;CHECK(out==b+44&&*(u16*)0x35014==14+inner_len);
 CHECK(!memcmp(out+30,client,4)&&!memcmp(out+26,INNER_DEST,4)&&sum(out+14,20)==0&&transport_sum(out+14)==0);
 b=frame(1,reply,padded+32);u32 f=frees;CHECK(packet1(0,0,0x35000)==0&&frees==f+1); /* replay consumed exactly once */
 return 0;
}
static int forward_tests(void){
 for(fixture_alignment=0;fixture_alignment<=2;fixture_alignment+=2){
  for(u32 payload=32;payload<36;payload++)CHECK(one_forward(17,payload)==0);
  CHECK(one_forward(1,21)==0);CHECK(one_forward(6,0)==0);CHECK(one_forward(17,1392)==0);
 }fixture_alignment=0;
 u32 before=f_tx;u8*b=ordinary(17,40);b[12]=0x86;b[13]=0xdd;CHECK(intercept(0,0x35000)==1&&f_tx==before);
 b=ordinary(17,40);b[29]=101;CHECK(intercept(0,0x35000)==1&&f_tx==before);
 b=ordinary(17,40);*(u32*)0x35008=(u32)b-100;u32 original=*(u32*)0x35010;CHECK(intercept(0,0x35000)==1&&f_tx==before&&*(u32*)0x35010==original);
 b=ordinary(17,1393);CHECK(intercept(0,0x35000)==1&&f_tx==before);
 b=ordinary(1,10);b[23]=99;CHECK(intercept(0,0x35000)==1&&f_tx==before);
 b=ordinary(1,10);b[20]=0x20;CHECK(intercept(0,0x35000)==1&&f_tx==before);
 b=ordinary(1,10);fixture_device()->peers[0].curr_keypair.keypair_millis=wireguard_sys_now()-180001;CHECK(intercept(0,0x35000)==1&&f_tx==before);
 return 0;
}

int tests(void){
 int result=scenario();
 CHECK(!nonce_errors);
 return result;
}

void print_fail(unsigned ignored){(void)ignored;unsigned n=failure_line;char msg[]="FAIL line=00000000\n";for(unsigned i=0;i<8;i++)msg[10+i]="0123456789abcdef"[(n>>(28-4*i))&15];register unsigned r0 __asm__("r0")=4;register char*r1 __asm__("r1")=msg;__asm__ volatile("bkpt #0xab" : "+r"(r0):"r"(r1):"memory");}
