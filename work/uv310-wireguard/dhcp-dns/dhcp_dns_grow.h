#ifndef UV310_DHCP_DNS_GROW_H
#define UV310_DHCP_DNS_GROW_H
#include "dhcp_dns.h"
/* Exclusive contiguous buffer, capacity >= *size, all pointers disjoint except
 * frame's own bytes. On success updates *size; caller must commit packet length.
 * Negative results preserve every byte and *size. At most six bytes of growth.
 * Retains Ethernet trailing bytes by shifting them, no heap or buffer replacement.
 * Caller must prove stock packet ownership/capacity before calling. */
int dhcp_dns_rewrite_grow(uint8_t *frame, size_t *size, size_t capacity,
                          const uint8_t server[4], const uint8_t resolver[4]);
#endif
