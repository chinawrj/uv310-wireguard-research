#ifndef UV310_SEEDED_RNG_H
#define UV310_SEEDED_RNG_H
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "chacha20.h"
/* Zero-initialize once. Caller must serialize access; not interrupt safe. */
struct seeded_rng { struct chacha20_ctx cipher; uint32_t state; };
bool seeded_rng_init(struct seeded_rng *,const uint8_t seed[32]);
bool seeded_rng_read(struct seeded_rng *,void *,size_t);
void seeded_rng_close(struct seeded_rng *);
#endif
