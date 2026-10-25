/* Synthetic adapter integration tests; never linked into live candidate. */
#include "wireguard.h"
#include "crypto.h"
#include <string.h>
#include "native-config.h"
typedef uint32_t u32;typedef uint16_t u16;typedef uint8_t u8;
extern void snapshot(void);extern int intercept(u32,u32,u32,u32);
#define intercept(d,p) intercept(d,p,0x33c00,0x33d00)
extern u32 control_ready,control_packet,attempts,submitted,freed,keepalive_tx,last_send,last_keepalive;extern void release_before(u32),release_after(u32);
volatile u32 fixture_clock,fixture_step=10;
static u32 alloc_calls,expiry_alloc,inject_publish;
extern volatile u32 stopped;extern void emit_control(void);
void fixture_before_publish(u32 next){if(next==9&&inject_publish){inject_publish=0;fixture_clock+=60000;emit_control();}}
static u8 sent[190];static u32 sent_bytes;
#define W(a) (*(volatile u32*)(a))
u32 fake_alloc(u32 n){alloc_calls++;if(expiry_alloc)fixture_clock+=60000;if(n!=512)return 0;u32 p=0x34200;memset((void*)p,0,68);W(p+8)=p+68;W(p+12)=p+580;W(p+16)=p+68;*(u16*)(p+20)=512;*(u8*)(p+29)=1;W(0x2688)+=580;W(0x26a4)+=8;return p;}
u32 fake_submit(u32 src,u32 dst,u32 p){(void)src;(void)dst;sent_bytes=*(u16*)(p+20);if(sent_bytes<=190)memcpy(sent,(void*)W(p+16),sent_bytes);release_before(p);W(0x2688)-=580;W(0x26a4)-=8;release_after(p);return 0;}extern u32 f_tx,f_rx,f_drop,session_start;extern volatile u32 phase;extern u32 err,rng_pos;extern void worker(void),signal_timer(void*);extern char version[];
static struct wireguard_device server;
static u32 fixture_alignment;
static u8 decoded[1700],reply[1740];
#define CHECK(x) do{if(!(x))return __LINE__;}while(0)
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
int tests(void){
 W(0x33d18)=0x33e00;W(0x33e18)=0x33f00;W(0x33f04)=0x34000;W(0x33f0c)=0x34100;W(0x34148)=64;W(0x33f3c)=0x33c00;
 u8*b=ordinary(1,0);b[20]=0x20;CHECK(intercept(0,0x35000)==1&&phase==0);
 CHECK(intercept(0,0x40000000)==0&&phase==0);
 b=ordinary(1,0);CHECK(intercept(0,0x35000)==1&&phase==1);
 snapshot();snapshot();CHECK(phase==1&&rng_pos==0); /* status cannot initialize */
 worker();CHECK(phase==1);signal_timer(0);
 __asm__ volatile("cpsid i":::"memory");worker();CHECK(phase==1);
#if defined(TEST_RNG_EMPTY) || defined(TEST_RNG_POSITION_INVALID)
 rng_pos=sizeof(RANDOM_POOL);
#ifdef TEST_RNG_POSITION_INVALID
 rng_pos=0xffffffffu;
#endif
#endif
 __asm__ volatile("cpsie i":::"memory");worker();
#if defined(TEST_RNG_EMPTY) || defined(TEST_RNG_POSITION_INVALID)
 CHECK(stopped&&phase==255&&err==1&&!control_ready&&!control_packet&&submitted==0&&alloc_calls==0);
 signal_timer(0);worker();CHECK(submitted==0);return 0;
#endif
 CHECK(phase==2);
#ifdef TEST_EXPIRED_INIT
 fixture_step=0;fixture_clock+=5000;u32 a=alloc_calls;signal_timer(0);
 CHECK(stopped&&phase==255&&err==0xe7&&!control_ready&&alloc_calls==a&&submitted==0);
 worker();CHECK(phase==255);return 0;
#endif
 CHECK(control_ready==1&&submitted==0);
 /* No second client packet. Timer submits the prepared initiation itself. */
 signal_timer(0);CHECK(phase==3&&submitted==1&&freed==1&&control_packet==0);
 b=sent;CHECK(sent_bytes==190&&sum(b+14,20)==0&&!memcmp(b+30,ENDPOINT_IP,4));
#ifdef TEST_RETRY
 u8 first[148];memcpy(first,sent+42,148);
 for(u32 i=2;i<=3;i++){last_send=wireguard_sys_now()-5001;signal_timer(0);worker();CHECK(phase==2&&attempts==i);signal_timer(0);CHECK(phase==3&&submitted==i&&freed==i);CHECK(memcmp(first,sent+42,148)!=0);}
 last_send=wireguard_sys_now()-5001;signal_timer(0);worker();CHECK(phase==255&&err==0xe6&&attempts==3);return 0;
#endif
 CHECK(wireguard_device_init(&server,SERVER_PRIVATE));CHECK(wireguard_peer_init(&server,&server.peers[0],CLIENT_PUBLIC,PRESHARED_KEY));
 struct message_handshake_initiation init;memcpy(&init,b+42,148);CHECK(wireguard_check_mac1(&server,(u8*)&init,116,init.mac1));
 CHECK(wireguard_process_initiation_message(&server,&init)==&server.peers[0]);
 struct message_handshake_response response;CHECK(wireguard_create_handshake_response(&server,&server.peers[0],&response));wireguard_start_session(&server.peers[0],false);
 b=ordinary(17,10);CHECK(intercept(0,0x35000)==1&&phase==3);
 b=frame(1,&response,92);b[20]=0x20;CHECK(intercept(1,0x35000)==1&&phase==3);
 b=frame(1,&response,92);*(u16*)0x35014=133;CHECK(intercept(1,0x35000)==1&&phase==3);
#ifdef TEST_BAD_RESPONSE
 ((u8*)&response)[44]^=1;
 wireguard_blake2s(response.mac1,16,server.peers[0].label_mac1_key,32,&response,60);
 static struct wireguard_device verifier;CHECK(wireguard_device_init(&verifier,PRIVATE_KEY));CHECK(wireguard_check_mac1(&verifier,(u8*)&response,60,response.mac1));
#endif
 b=frame(1,&response,92);CHECK(intercept(1,0x35000)==1&&phase==4);snapshot();CHECK(phase==4);
 
#ifdef TEST_PUBLISH_RACE
 inject_publish=1;
#endif
 signal_timer(0);worker();
#ifdef TEST_PUBLISH_RACE
 CHECK(stopped&&phase==255&&err==0xe7&&!control_ready&&submitted==1);
 signal_timer(0);worker();CHECK(phase==255&&submitted==1);return 0;
#endif
#ifdef TEST_BAD_RESPONSE
 CHECK(phase==255&&err==3);b=ordinary(1,56);CHECK(intercept(0,0x35000)==1&&phase==255);return 0;
#endif
 CHECK(phase==9&&err==0&&control_ready==2);
#if defined(TEST_EXPIRED_KEEPALIVE) || defined(TEST_WRAP_EXPIRY) || defined(TEST_ALLOC_EXPIRY)
 fixture_step=0;u32 a=alloc_calls,payload=W(0x2688),headers=W(0x26a4);
#ifdef TEST_WRAP_EXPIRY
 session_start=0xfffff000u;
#endif
 fixture_clock=session_start+60000;
#ifdef TEST_ALLOC_EXPIRY
 fixture_clock=session_start+59999;expiry_alloc=1;
#endif
 signal_timer(0);CHECK(stopped&&phase==255&&err==0xe7&&submitted==1&&!control_ready&&!control_packet);
 CHECK(W(0x2688)==payload&&W(0x26a4)==headers);
#ifdef TEST_ALLOC_EXPIRY
 CHECK(alloc_calls==a+1);
#else
 CHECK(alloc_calls==a);
#endif
 worker();signal_timer(0);CHECK(phase==255&&submitted==1);return 0;
#endif
#ifdef TEST_LIVE_BOUNDARY
 fixture_step=0;fixture_clock=session_start+59999;signal_timer(0);
 CHECK(!stopped&&submitted==2&&freed==2&&keepalive_tx==1);return 0;
#endif
 signal_timer(0);CHECK(submitted==2&&freed==2&&keepalive_tx==1&&sent_bytes==74);
 CHECK(U8TO32_LITTLE(sent+42)==4&&U8TO64_LITTLE(sent+50)==0);
 CHECK(wireguard_decrypt_packet(decoded,sent+58,16,0,&server.peers[0].next_keypair));
 last_keepalive=wireguard_sys_now()-20001;signal_timer(0);worker();CHECK(control_ready==2&&phase==9);signal_timer(0);
 CHECK(keepalive_tx==2&&submitted==3&&freed==3&&U8TO64_LITTLE(sent+50)==1);
 CHECK(wireguard_decrypt_packet(decoded,sent+58,16,1,&server.peers[0].next_keypair));
 CHECK(forward_tests()==0);
 return 0;
}

static u32 frees;
void fake_free(u32 ptr){if(ptr==0x34200){W(0x2688)-=580;W(0x26a4)-=8;return;}if(ptr==0x35000)frees++;else frees=999;}
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
 CHECK(wireguard_decrypt_packet(decoded,b+58,len-58,U8TO64_LITTLE(b+50),&server.peers[0].next_keypair));
 CHECK(!memcmp(decoded+12,INNER_SOURCE,4)&&!memcmp(decoded+16,INNER_DEST,4)&&sum(decoded,20)==0&&transport_sum(decoded)==0);
 CHECK(decoded[8]==63);if(proto==6)CHECK(be16(decoded+42)==1380);
 memcpy(decoded+12,INNER_DEST,4);memcpy(decoded+16,INNER_SOURCE,4);
 if(proto==1)decoded[20]=0;else{u16 port=be16(decoded+20);put16(decoded+20,be16(decoded+22));put16(decoded+22,port);}
 decoded[8]=64;fix_sums(decoded);u32 padded=(inner_len+15)&~15u;
 memset(reply,0,16);reply[0]=4;U32TO8_LITTLE(reply+4,server.peers[0].next_keypair.remote_index);U64TO8_LITTLE(reply+8,server.peers[0].next_keypair.sending_counter);
 wireguard_encrypt_packet(reply+16,decoded,padded,&server.peers[0].next_keypair);
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
 b=ordinary(1,10);session_start=wireguard_sys_now()-60001;CHECK(intercept(0,0x35000)==1&&f_tx==before);
 return 0;
}
