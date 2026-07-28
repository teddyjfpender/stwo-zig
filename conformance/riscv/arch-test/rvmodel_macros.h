// ACT4 DUT boundary for the stwo-zig RV32IM zkVM.
#ifndef STWO_RISCV_ACT4_RVMODEL_MACROS_H
#define STWO_RISCV_ACT4_RVMODEL_MACROS_H

// Signature-generation and self-checking ELFs must have byte-identical
// model-helper code so their test-visible addresses agree. Suppress ACT4's
// generic Sail helper overrides; the pinned Sail emulator understands this
// HTIF-compatible tohost definition directly.
#define _SAIL_MACROS_H

#define RVMODEL_DATA_SECTION                                      \
  .pushsection .tohost, "aw", @progbits;                         \
  .balign 8; .global tohost; tohost: .dword 0;                   \
  .balign 8; .global fromhost; fromhost: .dword 0;               \
  .global __output_len; __output_len: .word 0;                   \
  .global __output_data; __output_data:;                         \
  .popsection

// The zkVM has no privileged/CSR environment. ACT4's unprivileged I/M test
// bodies need only deterministic integer-register initialization.
#define RVMODEL_BOOT
#define RVMODEL_BOOT_TO_MMODE

// A passing self-check writes the zkVM halt flag. A failing self-check executes
// a valid JAL to a two-byte-aligned target, which RV32I execution and its AIR
// constraints reject under IALIGN=32, so it can never yield a proof.
#define RVMODEL_HALT_PASS                                         \
  la t1, __output_len;                                            \
  sw zero, 0(t1);                                                 \
  li t0, 1;                                                       \
  la t1, tohost;                                                  \
  sw t0, 0(t1);                                                   \
  sw zero, 4(t1)

#define RVMODEL_HALT_FAIL                                         \
  .word 0x0020006f

// The formal lane is intentionally silent. Test failure is represented by a
// rejected instruction, not by an uncommitted console side channel.
#define RVMODEL_IO_INIT(_R1, _R2, _R3)
#define RVMODEL_IO_WRITE_STR(_R1, _R2, _R3, _STR_PTR)

#define RVMODEL_INTERRUPT_LATENCY 1
#define RVMODEL_TIMER_INT_SOON_DELAY 1
#define RVMODEL_MAX_CYCLES_PER_TIMER_TICK 1
#define RVMODEL_SET_MEXT_INT(_R1, _R2)
#define RVMODEL_CLR_MEXT_INT(_R1, _R2)
#define RVMODEL_SET_MSW_INT(_R1, _R2)
#define RVMODEL_CLR_MSW_INT(_R1, _R2)
#define RVMODEL_SET_SEXT_INT(_R1, _R2)
#define RVMODEL_CLR_SEXT_INT(_R1, _R2)
#define RVMODEL_SET_SSW_INT(_R1, _R2)
#define RVMODEL_CLR_SSW_INT(_R1, _R2)

#endif
