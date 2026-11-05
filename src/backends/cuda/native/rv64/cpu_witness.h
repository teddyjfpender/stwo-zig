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
  // Optional U8-pair multiplicities: (gap_hi0,gap_hi1), (gap_hi2,0).
  // Pair mode is admitted only for the 24-bit clock (log <=22).
  uint32_t *pair_counts;
};
extern "C" int stwo_rv64_cpu_witness_on(void *, uint32_t,
                                       const StwoRv64CpuWitness *);
// 16 B records {u64 result, u32 ROM row, u32 next-PC}; one 384 B seed
// {u64 values[32], u32 clocks[32]} per chunk. Output is the original 56 B ABI.
struct StwoRv64CpuUnpack {
  const uint32_t *records, *seeds, *rom;
  uint32_t *metadata, *status;
  uint32_t count, rom_log, chunk_rows, reserved;
};
extern "C" int stwo_rv64_cpu_unpack_on(void *, uint32_t,
                                      const StwoRv64CpuUnpack *);
