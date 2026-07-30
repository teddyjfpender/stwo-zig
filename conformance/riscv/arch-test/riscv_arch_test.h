// ACT4 top-level boundary for the stwo-zig RV32IM zkVM.
//
// This follows the include order of the pinned upstream
// tests/env/riscv_arch_test.h. The two overrides below deliberately remove
// diagnostics that are unreachable on a passing self-check but would otherwise
// place pointer data and unsupported reporter instructions in executable
// sections. They do not change any test operation or expected signature.

#include "rvtest_config.h"
#undef H_SUPPORTED
#include "derived_config.h"
#include "encoding.h"
#include "utils.h"
#include "rvmodel_macros.h"

// ACT4 places two diagnostic pointers after each failure jump. Preserve their
// exact one-word footprint, but encode an RV32I nop instead of executable-section
// data. The reassignable assembler symbol consumes the original object-like
// macro argument without emitting a relocation or another word.
#undef RVTEST_WORD_PTR
#define RVTEST_WORD_PTR .word 0x00000013; .set stwo_ignored_diagnostic_ptr,

#ifndef RVTEST_SELFCHECK
  #include "sail_macros.h"
#endif
#include "check_defines.h"
#include "signature.h"
#include "rvtest_macros.h"
#if UDB_NUM_PMP_ENTRIES > 0
  #include "rvtest_pmp_macros.h"
#endif
#ifdef RVTEST_VECTOR
  #include "rvtest_macros_vector.h"
#endif
#ifdef RVTEST_HYPERVISOR
  #include "rvtest_macros_hypervisor.h"
#endif
#include "rvtest_trap_handler.h"
#include "rvtest_failure_code.h"

// The zkVM has no diagnostic console or privileged trap boundary. Every I/M
// self-check failure therefore executes a valid JAL whose two-byte-aligned
// target is outside the RV32I IALIGN=32 profile. The program commitment admits
// the encoding, while execution and its AIR constraints both reject the edge.
// All four labels are retained because the upstream signature macros select
// scratch-register pairs independently.
.purgem RVTEST_FAILURE_CODE
.macro RVTEST_FAILURE_CODE
  failedtest_x5_x4:
  failedtest_x8_x7:
  failedtest_x14_x13:
  failedtest_trap_x7_x9:
    .word 0x0020006f
.endm

#include "rvtest_setup.h"
