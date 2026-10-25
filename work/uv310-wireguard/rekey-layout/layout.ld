ENTRY(native_probe)
original_alloc = 0x806bc5; original_heap_free_body = 0x8062e1; original_timer_body = 0x80611d;
original_idle_body = 0x80655d; original_raw_free = 0x806c4d; original_continuation = 0x9dfd;
original_sdpcm = 0x80aa55; original_wl = 0x80fc35;
SECTIONS {
 .hook 0x9df8 : { KEEP(*(.hook)) }
 .probe 0x2f340 : { KEEP(*(.probe)) *(.text*) *(.rodata*) }
 .state : ALIGN(8) { __state_start = .; *(.data*) *(.bss*) *(COMMON) __state_end = .; }
 .version : ALIGN(4) { KEEP(*(.version)) }
 __image_end = .;
 /DISCARD/ : { *(.ARM.exidx*) *(.comment) }
}