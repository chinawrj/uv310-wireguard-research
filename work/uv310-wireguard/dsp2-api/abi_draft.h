/* Documentation-only layouts for pinned UV310 ALKU7.3.2 DSP2.
 * No callable addresses, loader, hooks, or hardware implementation.
 * uint32_t values below are DSP addresses, NEVER host pointers.
 * Unknown bytes are retained; these are views, not allocation templates.
 */
#ifndef UV310_DSP2_ABI_DRAFT_H
#define UV310_DSP2_ABI_DRAFT_H
#include <stdint.h>
#include <stddef.h>
typedef uint32_t dsp2_va32;
struct dsp2_ioctl_view {
    uint32_t command;
    dsp2_va32 buffer;
    uint32_t length;
    uint8_t set;
    uint8_t unknown_0d_17[11];
    uint32_t driver_magic;
};
struct dsp2_config_pair_view {
    uint32_t operation;
    dsp2_va32 value;
};
struct dsp2_control_request_view {
    uint8_t queue_link_unknown[8];
    dsp2_va32 pairs;
    uint32_t count;
    dsp2_va32 completion_task;
    uint32_t completion_signal;
    uint8_t result;
    /* Allocation extent, alignment, owner and timeout lifecycle not proven. */
};
struct dsp2_dhd_packet_view {
    dsp2_va32 next;
    uint8_t unknown_04_0f[12];
    dsp2_va32 data;
    dsp2_va32 tail_candidate;
    uint32_t length;
    uint32_t priority_and_unknown_bits;
    uint8_t unknown_20_43[36];
    dsp2_va32 allocator_object;
    dsp2_va32 auxiliary_chain;
};
struct dsp2_ipnet_packet_view {
    uint8_t unknown_00_4b[76];
    uint32_t length;
    uint32_t unknown_50;
    uint8_t unknown_54_8b[56];
    dsp2_va32 tail;
    dsp2_va32 end;
    dsp2_va32 base_candidate;
    dsp2_va32 data;
    uint32_t unknown_9c;
    uint32_t references;
};
struct dsp2_rx_ring_view {
    uint8_t unknown_00_2f[48];
    uint32_t producer;
    uint32_t consumer;
    dsp2_va32 slots[256];
};
_Static_assert(sizeof(struct dsp2_ioctl_view)==28, "ioctl layout");
_Static_assert(offsetof(struct dsp2_ioctl_view,driver_magic)==24, "magic offset");
_Static_assert(sizeof(struct dsp2_config_pair_view)==8, "operation pair layout");
_Static_assert(offsetof(struct dsp2_control_request_view,result)==24, "request result");
_Static_assert(offsetof(struct dsp2_dhd_packet_view,data)==16, "DHD data");
_Static_assert(offsetof(struct dsp2_dhd_packet_view,length)==24, "DHD length");
_Static_assert(offsetof(struct dsp2_dhd_packet_view,allocator_object)==68, "DHD allocator");
_Static_assert(offsetof(struct dsp2_ipnet_packet_view,length)==76, "IPnet length");
_Static_assert(offsetof(struct dsp2_ipnet_packet_view,tail)==140, "IPnet tail");
_Static_assert(offsetof(struct dsp2_ipnet_packet_view,data)==152, "IPnet data");
_Static_assert(offsetof(struct dsp2_ipnet_packet_view,references)==160, "IPnet refcount");
_Static_assert(offsetof(struct dsp2_rx_ring_view,slots)==56, "RX ring slots");
#endif
