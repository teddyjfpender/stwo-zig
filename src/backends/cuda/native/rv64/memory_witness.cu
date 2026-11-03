#include "custody.cuh"
#include "memory_witness.h"
namespace stwo::cuda::rv64 {
namespace {
__device__ uint32_t logical_row(uint32_t physical, uint32_t log) {
  const uint32_t n = 1u << log, circle = __brev(physical) >> (32 - log);
  return circle < n / 2 ? 2 * circle : 2 * (n - 1 - circle) + 1;
}
__device__ void word(uint32_t *out, uint64_t value) {
#pragma unroll
  for (uint32_t i = 0; i < 4; ++i) out[i] = (value >> (16 * i)) & 65535;
}
__global__ void memory_witness(StwoRv64MemoryWitness j) {
  const uint32_t physical = blockIdx.x * blockDim.x + threadIdx.x, n = 1u << j.log;
  if (physical >= n) return;
  const uint32_t logical = logical_row(physical, j.log);
  uint32_t v[79]{};
  if (logical < j.count) {
    const uint32_t *e = j.events + uint64_t(logical) * 16;
    const uint64_t a = uint64_t(e[0]) | uint64_t(e[1]) << 32;
    const uint64_t immediate = uint64_t(e[2]) | uint64_t(e[3]) << 32;
    const uint64_t b = uint64_t(e[4]) | uint64_t(e[5]) << 32;
    const uint64_t c = uint64_t(e[6]) | uint64_t(e[7]) << 32;
    const uint64_t before = uint64_t(e[8]) | uint64_t(e[9]) << 32;
    const uint32_t old_epoch = e[10], epoch = e[11], old_tick = e[12],
                   tick = e[13], rights = e[14], flag = e[15];
    const uint32_t widths[] = {1, 1, 2, 2, 4, 4, 8, 1, 2, 4, 8};
    const bool valid_flag = flag < 11 && (!j.dword || flag == 6 || flag == 10);
    const uint32_t width = valid_flag ? widths[flag] : 1;
    const bool store = flag >= 7, sign = flag == 0 || flag == 2 || flag == 4, same = old_epoch == epoch;
    const uint64_t ea = a + immediate, address = ea & ~uint64_t(7);
    const uint32_t offset = uint32_t(ea) & 7, shift = 8 * offset;
    const uint64_t mask = width == 8 ? ~uint64_t(0) : (uint64_t(1) << (8 * width)) - 1;
    const uint64_t selected = (before >> shift) & mask;
    const uint64_t loaded = sign && (selected >> (8 * width - 1)) ? selected | ~mask : selected;
    const bool valid = valid_flag && old_epoch <= 65535 && epoch <= 65535 &&
        old_epoch <= epoch && old_tick < (1u << 24) && tick && tick < (1u << 24) &&
        (!same || old_tick < tick) && rights <= 3 && (rights & (store ? 2u : 1u)) &&
        !(ea & (width - 1)) && (store ? c == 0 : b == 0 && c == loaded);
    if (!valid) atomicOr(j.status, 1u);
    else {
      const uint64_t after = store ? (before & ~(mask << shift)) | ((b & mask) << shift) : before;
      v[0] = 1; v[1] = store; v[2] = same; v[3] = tick;
      word(v + 4, address); v[8] = old_epoch; v[9] = epoch;
      v[10] = old_tick & 65535; v[11] = old_tick >> 16;
      v[12] = tick & 65535; v[13] = tick >> 16;
      word(v + 14, before); word(v + 18, after);
      v[22] = rights & 1; v[23] = rights >> 1;
      if (same) {
        const uint32_t gap = tick - old_tick - 1;
        v[25] = gap & 65535; v[26] = gap >> 16;
        v[27] = ((old_tick & 65535) + (gap & 65535) + 1) >> 16;
      } else v[24] = epoch - old_epoch - 1;
      word(v + 28, a); word(v + 32, immediate); word(v + 36, b);
      word(v + 40, c); word(v + 44, ea);
      v[49 + flag] = 1; v[60 + offset] = 1;
      v[68] = uint32_t(address & 65535) / 8;
      const uint32_t top = offset / 2 + (width == 1 ? 0 : width / 2 - 1);
      const uint32_t limb = (before >> (16 * top)) & 65535;
      const uint32_t byte = (limb >> (8 * (offset & 1))) & 255;
      v[69] = limb; v[70] = byte; v[71] = byte >> 7; v[72] = limb >> 15;
      v[73] = b & 255; v[74] = (b >> 8) & 255;
      uint32_t carry = 0;
#pragma unroll
      for (uint32_t i = 0; i < 4; ++i) {
        carry = (v[28 + i] + v[32 + i] + carry) >> 16;
        v[75 + i] = carry;
      }
    }
  }
  const uint32_t range16[] = {12, 24, 25, 68};
#pragma unroll
  for (uint32_t i = 0; i < 4; ++i) atomicAdd(j.range16 + v[range16[i]], 1u);
  if (j.fused_pairs) {
    atomicAdd(j.pairs + (v[13] * 256 + v[26]), 1u);
    if (!j.dword) atomicAdd(j.pairs + (v[73] * 256 + v[74]), 1u);
  } else {
    atomicAdd(j.range8 + v[13], 1u); atomicAdd(j.range8 + v[26], 1u);
    if (!j.dword) { atomicAdd(j.range8 + v[73], 1u); atomicAdd(j.range8 + v[74], 1u); }
  }
  if (j.dword) {
    constexpr uint32_t stored[] = {0,1,2,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,36,37,38,39,68,75,76,77,78};
#pragma unroll
    for (uint32_t i = 0; i < 39; ++i) j.main[uint64_t(i) * n + physical] = v[stored[i]];
  } else {
    uint32_t offset = 0;
#pragma unroll
    for (uint32_t i = 0; i < 8; ++i) offset += i * v[60 + i];
    atomicAdd(j.selection + (2 * v[69] + (offset & 1)), 1u);
    uint32_t stored = 0;
#pragma unroll
    for (uint32_t i = 0; i < 79; ++i) {
      if (i == 1 || i == 3 || i == 4 || (i >= 44 && i <= 48) || i == 73) continue;
      j.main[uint64_t(stored++) * n + physical] = v[i];
    }
  }
}
__global__ void boundary_witness(const uint32_t *cells, uint32_t count,
                                  uint32_t log, uint32_t *main, uint32_t *status) {
  const uint32_t p = blockIdx.x * blockDim.x + threadIdx.x, n = 1u << log;
  if (p >= n) return;
  const uint32_t logical = logical_row(p, log);
  uint32_t row[14]{};
  if (logical < count) {
    const uint32_t *cell = cells + uint64_t(logical) * 8;
    const uint64_t address = uint64_t(cell[0]) | uint64_t(cell[1]) << 32;
    if ((address & 7) || cell[4] > 65535 || cell[5] >= (1u << 24) || cell[6] > 3 || cell[7]) atomicOr(status, 1u);
    row[0] = 1; word(row + 1, address);
    word(row + 5, uint64_t(cell[2]) | uint64_t(cell[3]) << 32);
    row[9] = cell[4]; row[10] = cell[5] & 65535; row[11] = cell[5] >> 16;
    row[12] = cell[6] & 1; row[13] = cell[6] >> 1;
  }
#pragma unroll
  for (uint32_t c = 0; c < 14; ++c) main[uint64_t(c) * n + p] = row[c];
}
__global__ void multiplicities(const uint32_t *counts, const uint32_t *pairs,
                                uint32_t log, uint32_t kind, uint32_t *main,
                                uint32_t *status) {
  const uint32_t p = blockIdx.x * blockDim.x + threadIdx.x, n = 1u << log;
  if (p >= n) return;
  const uint32_t logical = logical_row(p, log);
  const uint32_t width = kind == 4 ? 16 : kind == 3 || kind == 5 ? 2 : 1;
  for (uint32_t column = 0; column < width; ++column) {
    const uint32_t value = kind == 3 ? (column ? pairs[logical] : counts[logical])
        : kind == 4 ? counts[16 * logical + column]
        : kind == 5 ? counts[2 * logical + column]
        : counts[kind == 6 ? p : logical];
    if (value >= 0x7fffffffu) atomicOr(status, 1u);
    main[uint64_t(column) * n + p] = value;
  }
}
} // namespace
} // namespace stwo::cuda::rv64
extern "C" int stwo_rv64_memory_witness_on(void *ctx, uint32_t lane,
                                           const StwoRv64MemoryWitness *j) {
  using namespace stwo::cuda::rv64;
  if (!j || j->log < 5 || j->log > 22 || j->count >= (1u << j->log) || j->dword > 1 || j->fused_pairs > 1) return int(cudaErrorInvalidValue);
  Custody c(ctx, lane);
  if ((j->count && !c.range(j->events, uint64_t(j->count) * 16, false)) ||
      !c.range(j->main, uint64_t(j->dword ? 39 : 70) << j->log, true) ||
      !c.range(j->range16, 65536, true) || !c.range(j->status, 1, true) ||
      (j->fused_pairs ? !c.range(j->pairs, 65536, true) : !c.range(j->range8, 256, true)) ||
      (!j->dword && !c.range(j->selection, 131072, true))) return c.status;
  memory_witness<<<((1u << j->log) + 127) / 128, 128, 0, c.stream>>>(*j);
  return int(cudaPeekAtLastError());
}
extern "C" int stwo_rv64_boundary_witness_on(void *ctx, uint32_t lane,
                                             const uint32_t *cells, uint32_t count,
                                             uint32_t log, uint32_t *main, uint32_t *status) {
  using namespace stwo::cuda::rv64;
  if (log < 5 || log > 22 || count >= (1u << log)) return int(cudaErrorInvalidValue);
  Custody c(ctx, lane);
  if ((count && !c.range(cells, uint64_t(count) * 8, false)) || !c.range(main, uint64_t(14) << log, true) || !c.range(status, 1, true)) return c.status;
  boundary_witness<<<((1u << log) + 127) / 128, 128, 0, c.stream>>>(cells, count, log, main, status);
  return int(cudaPeekAtLastError());
}
extern "C" int stwo_rv64_multiplicity_witness_on(void *ctx, uint32_t lane,
                                                 const uint32_t *counts,
                                                 const uint32_t *pairs, uint32_t log,
                                                 uint32_t kind, uint32_t *main, uint32_t *status) {
  using namespace stwo::cuda::rv64;
  if (kind > 6 || log < 5 || log > 24 || (kind == 0 && log != 16) || (kind == 1 && log != 8) || (kind >= 2 && kind <= 5 && log != 16)) return int(cudaErrorInvalidValue);
  const uint32_t width = kind == 4 ? 16 : kind == 3 || kind == 5 ? 2 : 1;
  Custody c(ctx, lane);
  if (!c.range(counts, uint64_t(kind == 4 ? 16 : kind == 5 ? 2 : 1) << log, false) ||
      (kind == 3 && !c.range(pairs, 1u << log, false)) ||
      !c.range(main, uint64_t(width) << log, true) || !c.range(status, 1, true)) return c.status;
  multiplicities<<<((1u << log) + 127) / 128, 128, 0, c.stream>>>(counts, pairs, log, kind, main, status);
  return int(cudaPeekAtLastError());
}
