#pragma once
#include <stdint.h>
// Borrowed device allocations, all owned by the supplied execution context.
// metadata is the native Source.Metadata layout: values[5]u64 (A,B,C,oldRD,
// nextPC), clocks[3]u32, rom_row u32, exactly 56 bytes/active retirement.
// ROM is the immutable compact ROM, column-major in native physical order.
// Output stays resident: 37 MAIN columns and native range/ROM multiplicities.
// Counts and status must be zeroed by the caller before enqueue. Nonzero status
// forbids publishing any output; this formatter does not verify ISA semantics.
struct StwoRv64CpuWitness {
  const uint32_t *metadata;
  const uint32_t *rom;
  uint32_t *main;
  uint32_t *counts16;
  uint32_t *counts8;
  uint32_t *rom_counts;
  uint32_t *status;
  uint32_t count, log, rom_log, final_pc;
};
extern "C" int stwo_rv64_cpu_witness_on(void *, uint32_t,
                                       const StwoRv64CpuWitness *);
