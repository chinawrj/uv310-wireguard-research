/* Synthetic provider can fail after partial writes. Never target entropy data. */
#include "wireguard.h"
#include "crypto.h"
#include "checked-random.h"
#include "native-config.h"
#include <string.h>
static struct wireguard_device client,server;
static unsigned calls,fail_at,stream,clock_ms=1000,draws;
volatile unsigned failure_line;
#define CHECK(x) do{if(!(x)){failure_line=__LINE__;return failure_line;}}while(0)
bool wireguard_random_bytes_checked(void *v,size_t n){
 unsigned char*p=v;calls++;
 if(calls==fail_at){memset(p,0xa7,n/2);return false;}
 if(n==4){U32TO8_LITTLE(p,0x22340000u+(++draws));return true;}
 for(size_t i=0;i<n;i++)p[i]=(unsigned char)(++stream*73+19);
 return true;
}
uint32_t wireguard_sys_now(void){return clock_ms;}
void wireguard_tai64n_now(uint8_t*v){memcpy(v,TAI64N,12);}
bool wireguard_is_under_load(void){return false;}
static int zero(const void*p,size_t n){const unsigned char*b=p;for(size_t i=0;i<n;i++)if(b[i])return 0;return 1;}
static int setup(void){
 calls=fail_at=stream=draws=0;clock_ms=1000;wireguard_init();
 memset(&client,0,sizeof(client));memset(&server,0,sizeof(server));
 CHECK(wireguard_device_init(&client,PRIVATE_KEY));CHECK(wireguard_peer_init(&client,&client.peers[0],PEER_KEY,PRESHARED_KEY));
 CHECK(wireguard_device_init(&server,SERVER_PRIVATE));CHECK(wireguard_peer_init(&server,&server.peers[0],CLIENT_PUBLIC,PRESHARED_KEY));return 0;
}
static int handshake_failure(unsigned responder,unsigned index){
 CHECK(setup()==0);struct message_handshake_initiation init;struct message_handshake_response response;
 struct wireguard_device*d=&client;
 if(responder){CHECK(wireguard_create_handshake_initiation(&client,&client.peers[0],&init));CHECK(wireguard_process_initiation_message(&server,&init)==&server.peers[0]);d=&server;}
 struct wireguard_peer*p=&d->peers[0];p->curr_keypair.valid=true;memset(p->curr_keypair.sending_key,0x39,32);
 struct wireguard_keypair old=p->curr_keypair;
 unsigned before=calls;fail_at=calls+1+index;
 int ok=responder?wireguard_create_handshake_response(d,p,&response):wireguard_create_handshake_initiation(d,p,&init);
 CHECK(!ok);CHECK(calls==before+1+index);CHECK(zero(&p->handshake,sizeof(p->handshake)));
 CHECK(responder?zero(&response,sizeof(response)):zero(&init,sizeof(init)));
 CHECK(memcmp(&old,&p->curr_keypair,sizeof(old))==0);return 0;
}
static int cookie_failure(unsigned refresh){
 CHECK(setup()==0);struct message_cookie_reply reply;unsigned char mac1[16]={1},source[6]={192,0,2,1,1,2};
 if(refresh)clock_ms+=120001;
 unsigned before=calls;fail_at=calls+1+refresh;memset(&reply,0x77,sizeof(reply));
 CHECK(!wireguard_create_cookie_reply(&server,&reply,mac1,7,source,sizeof(source)));
 CHECK(calls==before+1+refresh&&zero(&reply,sizeof(reply)));
 if(refresh)CHECK(zero(server.cookie_secret,sizeof(server.cookie_secret)));
 fail_at=0;CHECK(wireguard_create_cookie_reply(&server,&reply,mac1,7,source,sizeof(source)));
 CHECK(reply.type==3&&reply.receiver==7&&!zero(reply.enc_cookie,sizeof(reply.enc_cookie)));return 0;
}
int tests(void){
 wireguard_init();memset(&client,0x77,sizeof(client));calls=0;fail_at=1;
 CHECK(!wireguard_device_init(&client,PRIVATE_KEY));CHECK(calls==1&&zero(&client,sizeof(client)));
 for(unsigned r=0;r<2;r++)for(unsigned i=0;i<2;i++)CHECK(handshake_failure(r,i)==0);
 CHECK(cookie_failure(0)==0);CHECK(cookie_failure(1)==0);
 CHECK(setup()==0);unsigned char data[8]={1,2,3},source[6]={192,0,2,1,1,2},cookie[16],mac2[16];
 wireguard_blake2s(cookie,16,server.cookie_secret,32,source,sizeof(source));wireguard_blake2s(mac2,16,cookie,16,data,sizeof(data));
 CHECK(wireguard_check_mac2(&server,data,sizeof(data),source,sizeof(source),mac2));
 clock_ms+=120001;fail_at=calls+1;unsigned before=calls;
 CHECK(!wireguard_check_mac2(&server,data,sizeof(data),source,sizeof(source),mac2));
 CHECK(calls==before+1&&zero(server.cookie_secret,sizeof(server.cookie_secret)));return 0;
}
void print_fail(unsigned n){char msg[]="FAIL line=00000000\n";for(unsigned i=0;i<8;i++)msg[10+i]="0123456789abcdef"[(n>>(28-4*i))&15];register unsigned r0 __asm__("r0")=4;register char*r1 __asm__("r1")=msg;__asm__ volatile("bkpt #0xab" : "+r"(r0):"r"(r1):"memory");}
