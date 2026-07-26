/* ACT4 RV32IM memory map adapted to the stwo-zig release ELF contract. */
TEST_BASE = 0x00010000;
STACK_SIZE = 0x00020000;
IO_BASE = 0x00100000;
NUM_HARTS = 1;

OUTPUT_ARCH("riscv")
ENTRY(rvtest_entry_point)

PROVIDE(__stack_size = STACK_SIZE);
PROVIDE(__num_harts = NUM_HARTS);

SECTIONS
{
  . = TEST_BASE;
  __text_start = .;
  /*
   * ACT4 gives some input code sections large alignment requirements for test
   * layout. Keep that alignment inside each section, where the assembler emits
   * RV32I nops, but do not let the linker create zero-filled inter-section gaps
   * inside the zkVM's declared program commitment.
   */
  .text.init   : SUBALIGN(4) { *(.text.init) }
  .text.rvtest : SUBALIGN(4) { *(.text.rvtest) *(.text.rvtest.*) }

  /*
   * The adapter keeps its signature and DUT helpers byte-identical, so this
   * section can remain contiguous with executable code without shifting any
   * test-visible data between the two ACT4 builds.
   */
  .text.rvmodel : SUBALIGN(4) {
    *(.text.rvmodel) *(.text.rvmodel.*) *(.text) *(.text.*)
  }
  . = ALIGN(4);
  __text_end = .;
  __text_len = __text_end - __text_start;

  . = ALIGN(0x1000);
  __data_start = .;
  .rodata : { *(.rodata) *(.rodata.*) *(.srodata) *(.srodata.*) }
  .data   : { *(.data) *(.data.*) *(.sdata) *(.sdata.*) }
  . = ALIGN(16);
  .bss : {
    __bss_start = .;
    *(.sbss) *(.sbss.*) *(.bss) *(.bss.*) *(COMMON)
    . = ALIGN(16);
    __bss_end = .;
  }
  __data_end = .;
  __data_len = __data_end - __data_start;

  . = ALIGN(16);
  __stack_bottom = .;
  . += __stack_size * __num_harts;
  __stack_top = .;
  ASSERT(__stack_top <= IO_BASE, "ACT4 image overlaps the zkVM I/O window")

  .tohost IO_BASE : { *(.tohost) }
  __halt_flag = tohost;
  __input_start = __output_len;
  __input_end = __input_start;
  __output_end = 0x00110000;
  __global_pointer$ = __data_start + 0x800;

  . = ALIGN(0x1000);
  _end = .;
}
