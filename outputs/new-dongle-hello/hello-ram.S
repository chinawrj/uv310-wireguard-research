/* Candidate for the audited qtools ARM EXEC ABI; not a Linux executable.
 * R0: code pointer, R1: reply buffer, R4: reply length on return.
 * Writes only to the supplied reply buffer. No flash or MMIO accesses.
 */
.syntax unified
.arch armv5te
.arm
.text
.global hello_ram
hello_ram:
    adr r0, message
    mov r2, #message_end-message
    mov r4, r2
copy_byte:
    ldrb r3, [r0], #1
    strb r3, [r1], #1
    subs r2, r2, #1
    bne copy_byte
    bx lr
message:
    .byte 0x12
    .ascii "Hello World from UV310 ARM RAM!\n"
message_end:
.balign 4
