.syntax unified
.cpu cortex-m3
.thumb
.section .vectors,"a",%progbits
.word 0x20010000
.word start
.section .start,"ax",%progbits
.global start
.thumb_func
start:
 bl tests
 cmp r0,#0
 bne fail
 ldr r1,=passed
 b finish
fail:
 ldr r1,=failed
finish:
 movs r0,#4
 bkpt #0xab
 movs r0,#0x18
 ldr r1,=0x20026
 bkpt #0xab
 b .
.balign 4
passed: .asciz "PASS native adapter: handshake, client packet forwarding, NAT, checksums, bounds, rejection\n"
failed: .asciz "FAIL native adapter\n"
