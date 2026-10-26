/* Optional LTO experiment: keep these two large handshake functions separate.
 * No protocol changes. Include only when compiling rng-provider/wireguard.c.
 */
#ifndef UV310_HANDSHAKE_NOINLINE_H
#define UV310_HANDSHAKE_NOINLINE_H
#include "wireguard.h"
bool wireguard_process_handshake_response(struct wireguard_device *device, struct wireguard_peer *peer, struct message_handshake_response *src) __attribute__((noinline));
bool wireguard_create_handshake_initiation(struct wireguard_device *device, struct wireguard_peer *peer, struct message_handshake_initiation *dst) __attribute__((noinline));
#endif
