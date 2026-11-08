#include "custody.cuh"
#include "cpu_witness.h"
namespace stwo::cuda::rv64 {
// Repeated clock gaps are common. One global atomic per distinct bin/warp
// avoids serialising padding and tight register-dependency runs on a hot bin.
__device__ void count_bin(uint32_t *counts, uint32_t bin) {
  const uint32_t mask = __activemask();
  const uint32_t peers = __match_any_sync(mask, bin);
  if ((threadIdx.x & 31u) == uint32_t(__ffs(peers) - 1))
    atomicAdd(counts + bin, __popc(peers));
}
__device__ uint32_t physical_row(uint32_t logical, uint32_t log) {
  const uint32_t n = 1u << log;
  const uint32_t circle = logical & 1 ? n - 1 - logical / 2 : logical / 2;
  return __brev(circle) >> (32 - log);
}
// One warp per short chunk; each lane owns one register and its access clock.
// This breaks the whole-segment register dependency into independent chunks.
// Slots are visited in CPU order, including aliased rs1/rs2/rd accesses.
__global__ void cpu_unpack(StwoRv64CpuUnpack j) {
  const uint32_t chunk = blockIdx.x * (blockDim.x / 32) + threadIdx.x / 32;
  const uint32_t reg = threadIdx.x & 31;
  const uint32_t start = chunk * j.chunk_rows;
  if (start >= j.count) return;
  const uint32_t *seed = j.seeds + uint64_t(chunk) * 96;
  uint64_t value = uint64_t(seed[2 * reg]) | (uint64_t(seed[2 * reg + 1]) << 32);
  uint32_t clock = seed[64 + reg];
  const uint32_t rom_n = 1u << j.rom_log;
  for (uint32_t row = start; row < min(start + j.chunk_rows, j.count); ++row) {
    const uint32_t *r = j.records + uint64_t(row) * 4;
    uint32_t *m = j.metadata + uint64_t(row) * 14;
    const uint32_t rr = r[2];
    if (rr >= rom_n) {
      if (!reg) atomicOr(j.status, 2u);
      continue;
    }
    const uint32_t rp = physical_row(rr, j.rom_log);
#pragma unroll
    for (uint32_t slot = 0; slot < 3; ++slot) {
      const uint32_t id = j.rom[uint64_t(10 + slot) * rom_n + rp];
      if (id == reg) {
        const uint32_t dest = slot == 2 ? 6 : 2 * slot;
        m[dest] = reg ? uint32_t(value) : 0;
        m[dest + 1] = reg ? uint32_t(value >> 32) : 0;
        m[10 + slot] = reg ? clock : 0;
        if (reg) clock = 4 * row + slot + 1;
      }
      if (id >= 32 && !reg) atomicOr(j.status, 2u);
    }
    const uint32_t rd = j.rom[uint64_t(12) * rom_n + rp];
    if (reg && reg == rd) value = uint64_t(r[0]) | (uint64_t(r[1]) << 32);
    if (!reg) {
      m[4] = r[0]; m[5] = r[1];
      m[8] = r[3]; m[9] = 0; m[13] = rr;
    }
  }
}
__global__ void cpu_witness(StwoRv64CpuWitness j) {
  const uint32_t physical = blockIdx.x * blockDim.x + threadIdx.x;
  const uint32_t n = 1u << j.log;
  if (physical >= n) return;
  const uint32_t circle = __brev(physical) >> (32 - j.log);
  const uint32_t logical = circle < n / 2 ? 2 * circle : 2 * (n - 1 - circle) + 1;
  uint32_t row[37]{};
  uint64_t next = j.final_pc;
#pragma unroll
  for (uint32_t slot = 0; slot < 3; ++slot) {
    const uint32_t gap = 4 * logical + slot;
    row[26 + slot] = gap & 65535;
    row[29 + slot] = gap >> 16;
  }
  if (logical < j.count) {
    const uint32_t *m = j.metadata + uint64_t(logical) * 14;
    uint64_t value[5];
#pragma unroll
    for (uint32_t i = 0; i < 5; ++i)
      value[i] = uint64_t(m[2 * i]) | (uint64_t(m[2 * i + 1]) << 32);
    next = value[4];
    const uint32_t rom_n = 1u << j.rom_log;
    bool valid = m[13] < rom_n && next && next < (1u << 31) && !(next & 3);
    if (valid) {
      const uint32_t rp = physical_row(m[13], j.rom_log);
      const auto rom = [=](uint32_t c) { return j.rom[uint64_t(c) * rom_n + rp]; };
      valid = rom(0) == 1 && rom(21) <= 1 && rom(23) <= 1 && rom(24) <= 1;
      valid = valid && (rom(23) || next == rom(5));
      valid = valid && rom(29) == uint32_t(rom(21) && value[2] != 0);
      row[6] = 1;
      row[2] = rom(9);
#pragma unroll
      for (uint32_t slot = 0; slot < 3; ++slot) {
        const uint32_t id = rom(10 + slot), tick = 4 * logical + slot + 1;
        const uint32_t clock = m[10 + slot];
        valid = valid && id < 32 && clock < tick && (id || clock == 0);
        row[3 + slot] = id;
        row[7 + slot] = id != 0;
        const uint32_t gap = clock < tick ? tick - clock - 1 : 0;
        row[26 + slot] = gap & 65535;
        row[29 + slot] = gap >> 16;
      }
      valid = valid && (row[3] || value[0] == 0) && (row[4] || value[1] == 0) && (row[5] || value[3] == 0);
#pragma unroll
      for (uint32_t i = 0; i < 4; ++i) {
        row[10 + i] = (value[0] >> (16 * i)) & 65535;
        // Immediate FUNCTION rows have no rs2 read. The authenticated ROM
        // supplies B; on a genuine x0 read that immediate is simply zero.
        row[14 + i] = row[4] ? ((value[1] >> (16 * i)) & 65535) : rom(16 + i);
        row[18 + i] = (value[2] >> (16 * i)) & 65535;
        row[22 + i] = (value[3] >> (16 * i)) & 65535;
      }
      row[32] = rom(20); row[33] = rom(22);
      row[34] = rom(21); row[35] = rom(23); row[36] = rom(24);
      if (valid) atomicAdd(j.rom_counts + rp, 1u);
    }
    if (!valid) atomicOr(j.status, 1u);
  }
  row[0] = next & 65535;
  row[1] = (next >> 16) & 65535;
#pragma unroll
  for (uint32_t c = 0; c < 37; ++c)
    j.main[uint64_t(c) * n + physical] = row[c];
#pragma unroll
  for (uint32_t slot = 0; slot < 3; ++slot) {
    count_bin(j.counts16, row[26 + slot]);
    if (j.log > 22) count_bin(j.counts16, 128 * row[29 + slot]);
    else count_bin(j.counts8, row[29 + slot]);
  }
  if (j.pair_counts) {
    count_bin(j.pair_counts, row[29] * 256 + row[30]);
    count_bin(j.pair_counts, row[31] * 256);
  }
}
} // namespace stwo::cuda::rv64
extern "C" int stwo_rv64_cpu_unpack_on(void *ctx, uint32_t lane,
                                      const StwoRv64CpuUnpack *job) {
  using namespace stwo::cuda::rv64;
  if (!job || !job->chunk_rows || job->chunk_rows > 4096 ||
      job->rom_log < 5 || job->rom_log > 22 || job->reserved ||
      job->count >= (1u << 23)) return int(cudaErrorInvalidValue);
  const auto j = *job;
  Custody c(ctx, lane);
  const uint64_t chunks = (uint64_t(j.count) + j.chunk_rows - 1) / j.chunk_rows;
  if (!c.range(j.records, uint64_t(j.count) * 4, false) ||
      !c.range(j.seeds, chunks * 96, false) ||
      !c.range(j.rom, uint64_t(32) << j.rom_log, false) ||
      !c.range(j.metadata, uint64_t(j.count) * 14, true) ||
      !c.range(j.status, 1, true)) return c.status;
  if (chunks) cpu_unpack<<<(chunks + 3) / 4, 128, 0, c.stream>>>(j);
  return int(cudaPeekAtLastError());
}
extern "C" int stwo_rv64_cpu_witness_on(void *ctx, uint32_t lane,
                                       const StwoRv64CpuWitness *job) {
  using namespace stwo::cuda::rv64;
  if (!job || job->log < 5 || job->log > 23 || job->rom_log < 5 || job->rom_log > 22 ||
      job->count >= (1u << job->log) || (job->pair_counts && job->log > 22) ||
      !job->final_pc || job->final_pc >= (1u << 31) || (job->final_pc & 3))
    return int(cudaErrorInvalidValue);
  const auto j = *job;
  Custody c(ctx, lane);
  if ((j.count && !c.range(j.metadata, uint64_t(j.count) * 14, false)) ||
      !c.range(j.rom, uint64_t(32) << j.rom_log, false) ||
      !c.range(j.main, uint64_t(37) << j.log, true) ||
      !c.range(j.counts16, 65536, true) || !c.range(j.counts8, 256, true) ||
      !c.range(j.rom_counts, uint64_t(1) << j.rom_log, true) || !c.range(j.status, 1, true) ||
      (j.pair_counts && !c.range(j.pair_counts, 65536, true)))
    return c.status;
  cpu_witness<<<((1u << j.log) + 127) / 128, 128, 0, c.stream>>>(j);
  return int(cudaPeekAtLastError());
}
