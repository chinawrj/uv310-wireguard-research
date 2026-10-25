#ifndef UV310_CHECKED_RANDOM_H
#define UV310_CHECKED_RANDOM_H
#include <stdbool.h>
#include <stddef.h>
/* Return true only after ALL bytes were supplied by a qualified provider.
 * False may follow partial writes: callers wipe and reject the result.
 * The provider must return in bounded time. This interface does not prove entropy. */
bool wireguard_random_bytes_checked(void *out, size_t bytes);
#endif
