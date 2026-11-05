#include "arithmetic_witness.h"
#include "custody.cuh"
namespace stwo::cuda::rv64 {
namespace {
__device__ uint32_t mul_base(uint32_t a, uint32_t b) {
  uint64_t x = uint64_t(a) * b;
  x = (x & 0x7fffffffu) + (x >> 31);
  x = (x & 0x7fffffffu) + (x >> 31);
  return uint32_t(x >= 0x7fffffffu ? x - 0x7fffffffu : x);
}
__device__ uint32_t inverse_base(uint32_t x) {
  if (!x) return 0;
  uint32_t value = 1;
  for (uint32_t exponent = 0x7ffffffdu; exponent; exponent >>= 1) {
    if (exponent & 1) value = mul_base(value, x);
    x = mul_base(x, x);
  }
  return value;
}
__device__ void limbs(uint32_t *row, uint32_t start, uint64_t value) {
#pragma unroll
  for (uint32_t i = 0; i < 4; ++i) row[start + i] = (value >> (16 * i)) & 65535;
}
__global__ void arithmetic_witness(StwoRv64ArithmeticWitness j) {
  const uint32_t physical = blockIdx.x * blockDim.x + threadIdx.x, n = 1u << j.log;
  if (physical >= n) return;
  const uint32_t circle = __brev(physical) >> (32 - j.log);
  const uint32_t logical = circle < n / 2 ? 2 * circle : 2 * (n - 1 - circle) + 1;
  const bool active = logical < j.count;
  const uint32_t *request = active ? j.requests + uint64_t(logical) * 8 : nullptr;
  const uint32_t op = active ? request[0] : 0;
  const uint64_t a = active ? uint64_t(request[2]) | uint64_t(request[3]) << 32 : 0;
  const uint64_t b = active ? uint64_t(request[4]) | uint64_t(request[5]) << 32 : 0;
  const uint64_t result = active ? uint64_t(request[6]) | uint64_t(request[7]) << 32 : 0;
  uint32_t row[87]{};
  if (active && (request[1] || op >= (j.division ? 8 : 5))) { atomicOr(j.status, 1u); return; }
  if (j.division) {
    if (active) {
      const bool word = op >= 4, rem = op % 4 >= 2, signed_op = !(op & 1);
      const uint64_t mask = word ? 0xffffffffull : ~uint64_t(0);
      const uint64_t x = a & mask, y = b & mask;
      const bool sign_a = (x >> (word ? 31 : 63)) & 1, sign_b = (y >> (word ? 31 : 63)) & 1;
      const bool neg_a = signed_op && sign_a, neg_b = signed_op && sign_b;
      const uint64_t abs_a = (neg_a ? uint64_t(0) - x : x) & mask;
      const uint64_t abs_b = (neg_b ? uint64_t(0) - y : y) & mask;
      const bool zero = abs_b == 0, neg_out = rem ? neg_a : neg_a != neg_b;
      const uint64_t quotient = zero ? 0 : abs_a / abs_b;
      const uint64_t remainder = zero ? abs_a : abs_a % abs_b;
      const uint64_t product = quotient * abs_b;
      if (j.mul_support) {
        uint32_t *support = j.mul_support + uint64_t(logical) * 16;
#pragma unroll
        for (uint32_t k = 0; k < 2; ++k) {
          uint32_t *r = support + k * 8;
          r[0] = k ? 2 : 0; r[1] = 0;
          r[2] = uint32_t(quotient); r[3] = uint32_t(quotient >> 32);
          r[4] = uint32_t(abs_b); r[5] = uint32_t(abs_b >> 32);
          r[6] = k ? 0 : uint32_t(product); r[7] = k ? 0 : uint32_t(product >> 32);
        }
      }
      const uint64_t gap = zero ? 0 : abs_b - remainder - 1;
      const uint64_t chosen = rem ? remainder : quotient;
      const uint64_t normalized = (neg_out ? uint64_t(0) - chosen : chosen) & mask;
      const uint64_t expected = zero && !rem ? ~uint64_t(0)
          : word ? uint64_t(int64_t(int32_t(normalized))) : normalized;
      if (result != expected) atomicOr(j.status, 1u);
      const uint64_t values[] = {a, b, result, abs_a, abs_b, quotient, remainder, product, gap, normalized};
#pragma unroll
      for (uint32_t k = 0; k < 10; ++k) limbs(row, 4 * k, values[k]);
      row[60] = sign_a; row[61] = sign_b; row[62] = (normalized >> 31) & 1;
      row[63] = neg_a; row[64] = neg_b; row[65] = neg_out;
      row[66] = zero; row[67] = zero && !rem; row[69 + op] = 1;
      row[68] = inverse_base(row[16] + row[17] + row[18] + row[19]);
      uint32_t ca = 0, cb = 0, sum = 0, borrow = 0, co = 0;
#pragma unroll
      for (uint32_t i = 0; i < 4; ++i) {
        if (word && i == 2) ca = cb = co = 0;
        const uint32_t av = word && i >= 2 ? 0 : row[i];
        const uint32_t bv = word && i >= 2 ? 0 : row[4 + i];
        ca = neg_a ? (av + row[12 + i] + ca) >> 16 : 0;
        cb = neg_b ? (bv + row[16 + i] + cb) >> 16 : 0;
        row[40 + i] = ca; row[44 + i] = cb;
        sum = (row[28 + i] + row[24 + i] + sum) >> 16;
        row[48 + i] = sum;
        if (!zero) {
          const int64_t value = int64_t(row[16 + i]) - row[24 + i] - (i == 0 ? 1 : borrow);
          borrow = value < 0; row[52 + i] = borrow;
        }
        const uint32_t selected_limb = (chosen >> (16 * i)) & 65535;
        co = neg_out ? (selected_limb + row[36 + i] + co) >> 16 : 0;
        row[56 + i] = co;
      }
    }
    row[77] = logical + 1 < j.count ? logical + 1 : j.count;
    const uint32_t starts[] = {8, 12, 24, 32, 36};
#pragma unroll
    for (uint32_t k = 0; k < 5; ++k)
#pragma unroll
      for (uint32_t i = 0; i < 4; ++i) atomicAdd(j.range16 + row[starts[k] + i], 1u);
    const bool word = active && op >= 4;
    const uint32_t sign_queries[] = {2 * row[word ? 1 : 3] - 65536 * row[60], 2 * row[word ? 5 : 7] - 65536 * row[61], 2 * row[37] - 65536 * row[62]};
#pragma unroll
    for (uint32_t i = 0; i < 3; ++i) {
      if (sign_queries[i] > 65535) atomicOr(j.status, 1u);
      else atomicAdd(j.range16 + sign_queries[i], 1u);
    }
#pragma unroll
    for (uint32_t column = 0; column < 78; ++column) j.main[uint64_t(column) * n + physical] = row[column];
  } else {
    if (active) {
      const uint64_t low = a * b, high = __umul64hi(a, b);
      const bool sa = a >> 63, sb = b >> 63;
      const uint64_t expected = op == 0 ? low : op == 1 ? high - (sa ? b : 0) - (sb ? a : 0)
          : op == 2 ? high : op == 3 ? high - (sa ? b : 0) : uint64_t(int64_t(int32_t(low)));
      if (result != expected) atomicOr(j.status, 1u);
#pragma unroll
      for (uint32_t i = 0; i < 8; ++i) {
        row[i] = (a >> (8 * i)) & 255; row[8 + i] = (b >> (8 * i)) & 255;
        row[16 + i] = (result >> (8 * i)) & 255;
        row[24 + i] = (low >> (8 * i)) & 255; row[32 + i] = (high >> (8 * i)) & 255;
      }
      uint32_t carry = 0;
#pragma unroll
      for (uint32_t k = 0; k < 15; ++k) {
        uint32_t sum = carry;
#pragma unroll
        for (uint32_t i = 0; i < 8; ++i) if (k >= i && k - i < 8) sum += row[i] * row[8 + k - i];
        carry = sum >> 8; row[40 + k] = carry & 255; row[55 + k] = carry >> 8;
      }
      row[78] = sa; row[79] = sb; row[80] = (result >> 31) & 1; row[81 + op] = 1;
      if (op >= 1 && op <= 3) {
        int32_t borrow = 0;
#pragma unroll
        for (uint32_t i = 0; i < 8; ++i) {
          int32_t value = int32_t(row[32 + i]) - borrow;
          if (op != 2) value -= int32_t(sa * row[8 + i]);
          if (op == 1) value -= int32_t(sb * row[i]);
          borrow = value < 0 ? (-value + 255) / 256 : 0;
          row[70 + i] = uint32_t(borrow);
        }
      }
    }
    row[86] = logical + 1 < j.count ? logical + 1 : j.count;
    uint32_t bytes[96];
#pragma unroll
    for (uint32_t i = 0; i < 40; ++i) bytes[i] = row[i];
#pragma unroll
    for (uint32_t i = 0; i < 15; ++i) {
      bytes[40 + 3 * i] = row[40 + i]; bytes[41 + 3 * i] = row[55 + i]; bytes[42 + 3 * i] = 32 * row[55 + i];
    }
#pragma unroll
    for (uint32_t i = 0; i < 8; ++i) bytes[85 + i] = row[70 + i];
    bytes[93] = 2 * (row[7] - 128 * row[78]); bytes[94] = 2 * (row[15] - 128 * row[79]); bytes[95] = 2 * (row[19] - 128 * row[80]);
    if (j.fused_pairs) {
#pragma unroll
      for (uint32_t i = 0; i < 48; ++i) atomicAdd(j.pairs + bytes[2 * i] * 256 + bytes[2 * i + 1], 1u);
    } else {
#pragma unroll
      for (uint32_t i = 0; i < 96; ++i) atomicAdd(j.range8 + bytes[i], 1u);
    }
#pragma unroll
    for (uint32_t column = 0; column < 87; ++column) j.main[uint64_t(column) * n + physical] = row[column];
  }
}
} // namespace
} // namespace stwo::cuda::rv64
extern "C" int stwo_rv64_arithmetic_witness_on(void *ctx, uint32_t lane,
                                               const StwoRv64ArithmeticWitness *j) {
  using namespace stwo::cuda::rv64;
  if (!j || j->division > 1 || j->fused_pairs > 1 || j->log < 5 || j->log > 23 || j->count > (1u << j->log) || (j->division && j->fused_pairs)) return int(cudaErrorInvalidValue);
  if ((!j->division && j->mul_support) || (j->division && j->count && !j->mul_support)) return int(cudaErrorInvalidValue);
  Custody c(ctx, lane);
  if ((j->division && j->count && !c.range(j->mul_support, uint64_t(j->count) * 16, true)) ||
      (j->count && !c.range(j->requests, uint64_t(j->count) * 8, false)) ||
      !c.range(j->main, uint64_t(j->division ? 78 : 87) << j->log, true) || !c.range(j->status, 1, true) ||
      (j->division ? !c.range(j->range16, 65536, true) : j->fused_pairs ? !c.range(j->pairs, 65536, true) : !c.range(j->range8, 256, true))) return c.status;
  arithmetic_witness<<<((1u << j->log) + 127) / 128, 128, 0, c.stream>>>(*j);
  return int(cudaPeekAtLastError());
}
