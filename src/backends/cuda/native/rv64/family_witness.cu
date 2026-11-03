#include "custody.cuh"
#include "family_witness.h"
namespace stwo::cuda::rv64 {
namespace {
constexpr uint32_t prime = 0x7fffffffu;
__device__ uint32_t multiply_base(uint32_t a, uint32_t b) {
  uint64_t x = uint64_t(a) * b;
  x = (x & prime) + (x >> 31);
  x = (x & prime) + (x >> 31);
  return uint32_t(x >= prime ? x - prime : x);
}
__device__ uint32_t reciprocal(uint32_t x) {
  if (!x) return 0;
  uint32_t result = 1;
  for (uint32_t exponent = prime - 2; exponent; exponent >>= 1) {
    if (exponent & 1) result = multiply_base(result, x);
    x = multiply_base(x, x);
  }
  return result;
}
__device__ uint64_t alu_result(uint32_t op, uint64_t a, uint64_t b) {
  switch (op) {
  case 0: return a + b;
  case 1: return a - b;
  case 2: return uint64_t(int64_t(int32_t(uint32_t(a + b))));
  case 3: return uint64_t(int64_t(int32_t(uint32_t(a - b))));
  case 4: return int64_t(a) < int64_t(b);
  case 5: return a < b;
  case 6: return a == b;
  case 7: return a != b;
  case 8: return int64_t(a) >= int64_t(b);
  default: return a >= b;
  }
}
__device__ uint64_t zbb_result(uint32_t op, uint64_t a, uint64_t b) {
  if (op == 0) return a & ~b;
  if (op == 1) return a | ~b;
  if (op == 2) return ~(a ^ b);
  if (op == 4) return uint64_t(int64_t(int8_t(a)));
  if (op == 5) return uint64_t(int64_t(int16_t(a)));
  uint64_t result = 0;
#pragma unroll
  for (uint32_t i = 0; i < 8; ++i) result |= ((a >> (8 * i)) & 255) << (8 * (7 - i));
  return result;
}
__device__ uint64_t shift_result(uint32_t op, uint64_t a, uint64_t b) {
  const uint32_t shift = uint32_t(b) & (op < 3 ? 63 : 31);
  switch (op) {
  case 0: return a << shift;
  case 1: return a >> shift;
  case 2: return uint64_t(int64_t(a) >> shift);
  case 3: return uint64_t(int64_t(int32_t(uint32_t(a) << shift)));
  case 4: return uint64_t(int64_t(int32_t(uint32_t(a) >> shift)));
  default: return uint64_t(int64_t(int32_t(a) >> shift));
  }
}
__global__ void family_witness(StwoRv64FamilyWitness j) {
  const uint32_t physical = blockIdx.x * blockDim.x + threadIdx.x;
  const uint32_t n = 1u << j.log;
  if (physical >= n) return;
  const uint32_t circle = __brev(physical) >> (32 - j.log);
  const uint32_t logical = circle < n / 2 ? 2 * circle : 2 * (n - 1 - circle) + 1;
  const bool active = logical < j.count;
  const uint32_t *f = active ? j.facts + uint64_t(logical) * 8 : nullptr;
  const uint32_t op = active ? f[0] : 0, weight = active ? f[1] : 0;
  const uint64_t a = active ? uint64_t(f[2]) | uint64_t(f[3]) << 32 : 0;
  const uint64_t b = active ? uint64_t(f[4]) | uint64_t(f[5]) << 32 : 0;
  const uint64_t c = active ? uint64_t(f[6]) | uint64_t(f[7]) << 32 : 0;
  const uint32_t limit = j.kind == 0 ? 10 : j.kind == 1 ? 3 : 6;
  const bool valid_op = j.kind == 4 ? op == 10 : op < limit;
  const uint64_t expected = !valid_op ? 0 : j.kind == 0 ? alu_result(op, a, b)
      : j.kind == 1 ? (op == 0 ? a & b : op == 1 ? a | b : a ^ b)
                    : j.kind == 2 ? shift_result(op, a, b) : j.kind == 3 ? zbb_result(op, a, b) : (a + b) & ~uint64_t(1);
  const bool canonical_b = j.kind != 3 || op < 3 || b == (op == 3 ? 0 : op == 4 ? 128 : 32768);
  if (active && (!valid_op || !canonical_b || weight >= prime || (j.kind == 4 && weight != 1) || c != expected)) {
    atomicOr(j.status, 1u);
    return;
  }
  uint32_t v[52]{};
  uint32_t width;
  if (j.kind == 0) {
    width = 47;
    v[8] = active;
    if (active) v[9 + op] = 1;
    uint32_t carry = 0, borrow = 0, sum_difference = 0;
#pragma unroll
    for (uint32_t i = 0; i < 4; ++i) {
      const uint32_t av = (a >> (16 * i)) & 65535, bv = (b >> (16 * i)) & 65535;
      const uint32_t sum = av + bv + carry, difference = av + 65536 - bv - borrow;
      carry = sum >> 16;
      borrow = difference < 65536;
      v[i] = av; v[4 + i] = bv;
      v[19 + i] = sum & 65535; v[23 + i] = difference & 65535;
      v[27 + i] = carry; v[31 + i] = borrow;
      sum_difference += difference & 65535;
      atomicAdd(j.range16_counts + v[19 + i], 1u);
      atomicAdd(j.range16_counts + v[23 + i], 1u);
    }
    v[35] = sum_difference == 0; v[36] = reciprocal(sum_difference);
    const uint32_t sign_inputs[] = {v[3], v[7], v[20], v[24]};
#pragma unroll
    for (uint32_t i = 0; i < 4; ++i) {
      v[37 + i] = sign_inputs[i] >> 15; v[41 + i] = sign_inputs[i] & 32767;
      atomicAdd(j.range16_counts + 2 * v[41 + i], 1u);
    }
    v[45] = int64_t(a) < int64_t(b); v[46] = weight;
  } else if (j.kind == 1 || j.kind == 3) {
    const uint32_t offset = j.kind == 1 ? 4 : 7;
    width = offset + 25; v[0] = active;
    if (active) v[1 + op] = 1;
#pragma unroll
    for (uint32_t i = 0; i < 8; ++i) {
      const uint32_t av = (a >> (8 * i)) & 255, bv = (b >> (8 * i)) & 255;
      v[offset + i] = av; v[offset + 8 + i] = bv; v[offset + 16 + i] = av & bv;
      atomicAdd(j.and_counts + (av << 8 | bv), 1u);
    }
    v[width - 1] = weight;
  } else if (j.kind == 4) {
    width = 17;
#pragma unroll
    for (uint32_t i = 0; i < 4; ++i) {
      v[i] = (a >> (16 * i)) & 65535;
      v[4 + i] = (b >> (16 * i)) & 65535;
      v[8 + i] = (c >> (16 * i)) & 65535;
      v[12 + i] = ((a + b) >> (16 * i)) & 65535;
    }
    v[16] = active;
  } else {
    width = 52;
#pragma unroll
    for (uint32_t i = 0; i < 4; ++i) {
      v[i] = (a >> (16 * i)) & 65535;
      v[4 + i] = (b >> (16 * i)) & 65535;
      v[8 + i] = (c >> (16 * i)) & 65535;
    }
    v[12] = active;
    if (active) v[13 + op] = 1;
    const uint32_t amount = uint32_t(b) & 15;
#pragma unroll
    for (uint32_t i = 0; i < 5; ++i) {
      const uint32_t input = i < 4 ? v[i] : 65535;
      const uint32_t left = input << amount;
      v[19 + 4 * i] = left & 65535; v[20 + 4 * i] = left >> 16;
      v[21 + 4 * i] = input >> amount;
      v[22 + 4 * i] = amount ? (input << (16 - amount)) & 65535 : 0;
      atomicAdd(j.shift_counts + input * 16 + amount, 1u);
    }
    v[39] = amount;
    if (active) {
      v[40 + ((b >> 4) & (op >= 3 ? 1 : 3))] = 1;
      v[44] = uint32_t(b & 65535) >> 6;
      v[45] = op >= 3 ? (b >> 5) & 1 : 0;
      v[46] = (a >> 31) & 1; v[47] = a >> 63; v[48] = (c >> 31) & 1;
      v[49] = op == 2 ? v[47] : 0; v[50] = op == 5 ? v[46] : 0;
    }
    v[51] = weight;
    atomicAdd(j.range16_counts + v[44], 1u);
    atomicAdd(j.range16_counts + (uint32_t(b) & 0xffc0), 1u);
    atomicAdd(j.range16_counts + 2 * (v[1] & 32767), 1u);
    atomicAdd(j.range16_counts + 2 * (v[3] & 32767), 1u);
    atomicAdd(j.range16_counts + 2 * (v[9] & 32767), 1u);
  }
#pragma unroll
  for (uint32_t column = 0; column < width; ++column)
    j.main[uint64_t(column) * n + physical] = v[column];
}
} // namespace
} // namespace stwo::cuda::rv64
extern "C" int stwo_rv64_family_witness_on(void *ctx, uint32_t lane,
                                           const StwoRv64FamilyWitness *j) {
  using namespace stwo::cuda::rv64;
  if (!j || j->reserved || j->kind > 4 || j->log < 5 || j->log > 26 ||
      j->count > (1u << j->log)) return int(cudaErrorInvalidValue);
  Custody custody(ctx, lane);
  const uint32_t width = j->kind == 0 ? 47 : j->kind == 1 ? 29 : j->kind == 2 ? 52 : j->kind == 3 ? 32 : 17;
  if ((j->count && !custody.range(j->facts, uint64_t(j->count) * 8, false)) ||
      !custody.range(j->main, uint64_t(width) << j->log, true) ||
      !custody.range(j->status, 1, true) ||
      ((j->kind == 0 || j->kind == 2) && !custody.range(j->range16_counts, 65536, true)) ||
      ((j->kind == 1 || j->kind == 3) && !custody.range(j->and_counts, 65536, true)) ||
      (j->kind == 2 && !custody.range(j->shift_counts, 1u << 20, true)))
    return custody.status;
  family_witness<<<((1u << j->log) + 127) / 128, 128, 0, custody.stream>>>(*j);
  return int(cudaPeekAtLastError());
}
