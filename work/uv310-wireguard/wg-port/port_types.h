#pragma once
#include <stdint.h>
/* Protocol-core compilation only. No lwIP implementation or UV310 ABI claim.
 * IPv4 endpoint fields are storage; this file supplies NO packet IO. */
typedef uint16_t u16_t;
typedef struct { uint32_t addr; } ip_addr_t;
struct netif;
struct udp_pcb;
