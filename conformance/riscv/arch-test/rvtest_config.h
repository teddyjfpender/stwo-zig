// RV32IM-only ACT4 compile-time profile for the stwo-zig zkVM.
//
// The pinned ACT4 UDB configuration is used to select upstream I/M tests.
// This deliberately smaller header controls what the generated assembly may
// execute on the DUT: no privilege, CSR, compressed, atomic, or FENCE.I code.
#ifndef STWO_RISCV_ACT4_CONFIG_H
#define STWO_RISCV_ACT4_CONFIG_H

#define I_SUPPORTED
#define M_SUPPORTED

#define UDB_MXLEN 32
#define UDB_MXLEN_32
#define UDB_NUM_PMP_ENTRIES 0
#define UDB_NUM_USABLE_PMP_ENTRIES 0

#endif
