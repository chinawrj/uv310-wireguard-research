/* Offline prototype: fresh dedicated host seed, one lifetime, no reseeding.
 * Uses existing ChaCha20 primitive unchanged. Not a certified DRBG. */
#include "seeded_rng.h"
#include <string.h>
#define BLOCK_BUDGET 65536u
void seeded_rng_close(struct seeded_rng *r){
 if(!r)return;
 volatile uint8_t*p=(volatile uint8_t*)&r->cipher;
 for(size_t i=0;i<sizeof(r->cipher);i++)p[i]=0;
 r->state=2;
}
bool seeded_rng_init(struct seeded_rng*r,const uint8_t seed[32]){
 if(!r||!seed||r->state!=0)return false;
 /* Dedicated seed must not be a WG identity/session key or reused elsewhere. */
 chacha20_init(&r->cipher,seed,0);
 r->state=1;return true;
}
bool seeded_rng_read(struct seeded_rng*r,void*out,size_t n){
 if(!r||(!out&&n)||n>64)return false;
 if(r->state!=1||r->cipher.state[12]>=BLOCK_BUDGET){
  if(n)memset(out,0,n);
  seeded_rng_close(r);return false;
 }
 if(!n)return true;
 /* Consume a complete block per request; unused suffix is deliberately lost. */
 memset(out,0,n);chacha20(&r->cipher,out,out,(uint32_t)n);return true;
}
