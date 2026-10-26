#ifndef UV310_DHCP_DNS_H
#define UV310_DHCP_DNS_H
#include <stddef.h>
#include <stdint.h>
enum dhcp_dns_result {
    DHCP_DNS_UNCHANGED = 0,
    DHCP_DNS_REWRITTEN = 1,
    DHCP_DNS_REJECT = -1,
    DHCP_DNS_NO_SPACE = -2,
    DHCP_DNS_BAD_CONFIG = -3
};
/* Prototype only: caller must supply an exclusively owned, contiguous Ethernet
 * frame on the stock-server -> Wi-Fi path. Configuration arrays must not alias
 * frame. No allocation, resize, device access, routing, or DNS proxying occurs.
 * Negative results leave every byte unchanged and require caller policy.
 * UNCHANGED means outside this transformer, NOT a VPN safety verdict.
 * IPv4 UDP fragments from server are rejected because ports may be unavailable.
 */
int dhcp_dns_rewrite(uint8_t *frame, size_t size,
                     const uint8_t server[4], const uint8_t resolver[4]);
#endif
