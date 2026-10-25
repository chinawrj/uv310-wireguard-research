ENTRY(start)
original_alloc = fake_alloc;
original_heap_free_body = 0x8062e1;
original_timer_body = 0x80611d;
original_idle_body = 0x80655d;
original_raw_free = fake_free;
original_continuation = 0x9dfd;
original_sdpcm = fake_submit;
original_wl = 0x80fc35;
SECTIONS {
 .vectors 0 : { KEEP(*(.vectors)) }
 .start 0x1000 : { *(.start) }
 .hook 0x9df8 : { KEEP(*(.hook)) }
 .tests 0x10000 : { *tests.o(.text* .rodata*) }
 .probe 0x2f340 : { KEEP(*(.probe)) *(.text*) *(.rodata*) }
 .state : ALIGN(8) { __state_start = .; *native.o(.data* .bss*) *wireguard.o(.data* .bss*) *crypto.o(.data* .bss*) __state_end = .; }
 .version : ALIGN(4) { KEEP(*(.version)) }
 __image_end = .;
 .teststate 0x36000 : { *(.data*) *(.bss*) *(COMMON) }
 /DISCARD/ : { *(.ARM.exidx*) *(.comment) }
}
