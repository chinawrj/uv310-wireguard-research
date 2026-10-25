.syntax unified
.cpu cortex-m3
.thumb
.section .hook,"ax",%progbits
 b.w native_probe
.section .probe,"ax",%progbits
.global native_probe, packet0, packet1, tail0, tail1
.thumb_func
native_probe:
 push.w {r0,r1,r2,r3,r12,lr}
 bl snapshot
 pop.w {r0,r1,r2,r3,r12,lr}
 push {r0,r1,r2,lr}
 ldr r2, =0x19b9a
 b.w original_continuation
.balign 4
.ltorg
.thumb_func
packet0:
 push.w {r0,r1,r2,r3,r12,lr}
 mov r3,r1
 mov r1,r2
 mov r2,r0
 movs r0,#0
 bl intercept
 cmp r0,#1
 beq consume_packet
 pop.w {r0,r1,r2,r3,r12,lr}
tail0: b.w original_sdpcm
.thumb_func
packet1:
 push.w {r0,r1,r2,r3,r12,lr}
 mov r1,r2
 movs r0,#1
 movs r2,#0
 movs r3,#0
 bl intercept
 cmp r0,#1
 beq consume_packet
 pop.w {r0,r1,r2,r3,r12,lr}
tail1: b.w original_wl

.thumb_func
consume_packet:
 ldr r0,[sp,#8]
 bl raw_packet_free
 pop.w {r0,r1,r2,r3,r12,lr}
 movs r0,#0
 bx lr
.global raw_packet_free
.thumb_func
raw_packet_free: b.w original_raw_free

.global timer_hook,timer_tail,idle_hook,idle_tail
.thumb_func
timer_hook:
 push.w {r0,r1,r2,r3,r12,lr}
 bl signal_timer
 pop.w {r0,r1,r2,r3,r12,lr}
timer_tail: b.w original_timer_body
.thumb_func
idle_hook:
 push.w {r0,r1,r2,r3,r12,lr}
 mrs r0,apsr
 push {r0,r1}
 bl worker
 pop {r0,r1}
 msr APSR_nzcvq,r0
 pop.w {r0,r1,r2,r3,r12,lr}
idle_tail: b.w original_idle_body

.global raw_alloc,submit
.thumb_func
raw_alloc: b.w original_alloc
.thumb_func
submit: b.w original_sdpcm

/* Preserve argument/return registers and condition flags around observation. */
.global free_hook
.thumb_func
free_hook:
 push.w {r0,r1,r2,r3,r12,lr}
 mrs r0,apsr
 push {r0,r1}
 ldr r0,[sp,#8]
 bl release_before
 pop {r0,r1}
 msr APSR_nzcvq,r0
 pop.w {r0,r1,r2,r3,r12,lr}
 push {r4,lr}
 mov r4,r0
 bl original_heap_free_body
 push.w {r0,r1,r2,r3,r12,lr}
 mrs r0,apsr
 push {r0,r1}
 mov r0,r4
 bl release_after
 pop {r0,r1}
 msr APSR_nzcvq,r0
 pop.w {r0,r1,r2,r3,r12,lr}
 pop {r4,pc}
