OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY {
    TEXT (rx) : ORIGIN = 0x00000400, LENGTH = 0x007FFC00
    DATA (rw) : ORIGIN = 0x02000000, LENGTH = 0x0E000000
}

__stack_top = 0x02000000;
__stack_bottom = 0x01000000;
__input_start = 0x00800000;
__input_end = 0x00C00000;
__halt_flag = __input_end;
__output_len = __halt_flag + 4;
__output_data = __halt_flag + 8;
__output_end = __stack_bottom;

SECTIONS {
    .text : ALIGN(4) {
        __text_start = .;
        KEEP(*(.text._start))
        *(.text .text.*)
        __text_end = .;
    } > TEXT
    .rodata : ALIGN(8) {
        __data_start = .;
        *(.rodata .rodata.* .srodata .srodata.*)
    } > DATA
    .data : ALIGN(8) {
        *(.data .data.* .sdata .sdata.*)
    } > DATA
    .bss (NOLOAD) : ALIGN(8) {
        *(.bss .bss.* .sbss .sbss.* COMMON)
    } > DATA
    __text_len = __text_end - __text_start;
    __data_end = .;
    __heap_start = ALIGN(__data_end, 16);
    __heap_end = ORIGIN(DATA) + LENGTH(DATA);
    /* The proof memory range includes allocated heap words, not just ELF
       sections. Keep __data_end as the initialized-data boundary used above. */
    __data_len = __heap_end - __data_start;
    PROVIDE(__global_pointer$ = ORIGIN(DATA) + 0x800);
    .note.stwo.zkvm 0 : { KEEP(*(.note.stwo.zkvm)) }
    /DISCARD/ : { *(.comment .eh_frame .eh_frame_hdr .note.GNU-stack) }
}
