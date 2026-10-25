/* Deterministic synthetic fixtures, never linked into a live image. */
#include "wireguard.h"
#include "crypto.h"
#include "native-config.h"
#include <string.h>
static struct wireguard_device client,server;
static unsigned mode,draws,stream,check_count;
volatile unsigned failure_line;
#define CHECK(x) do{check_count++;if(!(x)){failure_line=__LINE__;return failure_line;}}while(0)
bool wireguard_random_bytes_checked(void*v,size_t n){
 unsigned char*p=v;
 if(n==4){unsigned k=++draws,x=0x12340000u+k;
  if(mode==1||(mode==5&&k<=16)||(mode==4&&k<16))x=0;
  if(mode==2)x=0xffffffffu;
  if(mode==3)x=0x11223344u;
  U32TO8_LITTLE(p,x);return true;
 }
 for(size_t i=0;i<n;i++)p[i]=(unsigned char)(++stream*73+19);
 return true;
}
uint32_t wireguard_sys_now(void){return 1000;}
void wireguard_tai64n_now(uint8_t *v){memcpy(v,TAI64N,12);}
bool wireguard_is_under_load(void){return false;}
static int zero(const void*p,size_t n){const unsigned char*b=p;for(size_t i=0;i<n;i++)if(b[i])return 0;return 1;}
static int setup(void){
 mode=draws=stream=0;wireguard_init();
 CHECK(wireguard_device_init(&client,PRIVATE_KEY));CHECK(wireguard_peer_init(&client,&client.peers[0],PEER_KEY,PRESHARED_KEY));
 CHECK(wireguard_device_init(&server,SERVER_PRIVATE));CHECK(wireguard_peer_init(&server,&server.peers[0],CLIENT_PUBLIC,PRESHARED_KEY));return 0;
}
static int exercise(unsigned m,unsigned responder,unsigned slot){
 CHECK(setup()==0);struct message_handshake_initiation init;
 struct message_handshake_response response;
 struct wireguard_device*d=&client;
 if(responder){CHECK(wireguard_create_handshake_initiation(&client,&client.peers[0],&init));CHECK(wireguard_process_initiation_message(&server,&init)==&server.peers[0]);d=&server;}
 struct wireguard_peer*p=&d->peers[0];
 p->curr_keypair.valid=true;memset(p->curr_keypair.sending_key,0x37,32);
 if(m==3){
  if(slot==0)p->curr_keypair.local_index=0x11223344;
  if(slot==1)p->prev_keypair.local_index=0x11223344;
  if(slot==2)p->next_keypair.local_index=0x11223344;
  if(slot==3)p->handshake.local_index=0x11223344;
 }
 struct wireguard_keypair preserved=p->curr_keypair;
 mode=m;draws=0;
 int ok=responder?wireguard_create_handshake_response(d,p,&response):wireguard_create_handshake_initiation(d,p,&init);
 CHECK(draws==16);
 CHECK(memcmp(&p->curr_keypair,&preserved,sizeof(preserved))==0);
 if(m==4){CHECK(ok);CHECK(responder?response.sender==0x12340010:init.sender==0x12340010);CHECK(p->handshake.valid);}
 else {CHECK(!ok);CHECK(zero(&p->handshake,sizeof(p->handshake)));CHECK(responder?zero(&response,sizeof(response)):zero(&init,sizeof(init)));}
 return 0;
}
int tests(void){
 for(unsigned r=0;r<2;r++){
  CHECK(exercise(1,r,0)==0);CHECK(exercise(2,r,0)==0);
  for(unsigned slot=0;slot<4;slot++)CHECK(exercise(3,r,slot)==0);
  CHECK(exercise(4,r,0)==0);CHECK(exercise(5,r,0)==0);
 }
 return 0;
}

void print_fail(unsigned n){char msg[]="FAIL line=00000000\n";for(unsigned i=0;i<8;i++)msg[10+i]="0123456789abcdef"[(n>>(28-4*i))&15];register unsigned r0 __asm__("r0")=4;register char*r1 __asm__("r1")=msg;__asm__ volatile("bkpt #0xab" : "+r"(r0):"r"(r1):"memory");}
