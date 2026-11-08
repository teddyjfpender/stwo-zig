// Canonical local-GKR receipt and child-wire encoding from resident Stage1
// data. The class program contains public framing only; coefficient-vector
// lengths and every field value are read from the device proof section.
#include "rv64/custody.cuh"
#include "transcript/state.cuh"
#include <stdint.h>

struct StwoRv64GkrWireRun {
  const uint32_t *program;
  uint64_t program_words;
  const uint32_t *section;
  uint64_t section_words;
  const uint32_t *scope; // statement[8], FIXED[8], MAIN[8], ordinal
  const uint32_t *marginals;
  uint64_t marginal_words;
  uint32_t *receipt; // digest[8], zero[8]
  uint32_t *wire;    // byte length, followed by the encoded local child
  uint64_t wire_words;
  uint32_t *verdict;
  uint32_t reject_code;
  uint32_t reserved;
};
static_assert(sizeof(StwoRv64GkrWireRun) == 96, "GKR wire run ABI");

namespace {
constexpr uint32_t kMagic = 0x3157474c, kModulus = 0x7fffffffu;
struct HashStream {
  uint32_t h[8], block[16], fill;
  uint64_t count;
  __device__ void init() {
    stwo::cuda::blake2s::initialize(h);
    for (uint32_t i = 0; i < 16; ++i) block[i] = 0;
    fill = 0;
    count = 0;
  }
  __device__ void byte(uint32_t value) {
    // Keep a full final block until the next byte arrives (Blake2s framing).
    if (fill == 64) {
      count += 64;
      stwo::cuda::blake2s::compress(h, block, count, 0);
      for (uint32_t i = 0; i < 16; ++i) block[i] = 0;
      fill = 0;
    }
    block[fill >> 2] |= (value & 255u) << (8 * (fill & 3));
    ++fill;
  }
  __device__ void finish(uint32_t *out) {
    count += fill;
    stwo::cuda::blake2s::compress(h, block, count, 0xffffffffu);
    for (uint32_t i = 0; i < 8; ++i) out[i] = h[i];
  }
};

struct Sink {
  HashStream *hash;
  uint32_t *out;
  uint64_t capacity, written;
  uint32_t detail;
  __device__ void byte(uint32_t value) {
    if (written >= capacity) { detail = detail ? detail : 4; return; }
    if (hash) hash->byte(value);
    else if ((written & 3) == 0) out[written >> 2] = value & 255u;
    else out[written >> 2] |= (value & 255u) << (8 * (written & 3));
    ++written;
  }
  __device__ void word(uint32_t value) {
    for (uint32_t k = 0; k < 4; ++k) byte(value >> (8 * k));
  }
};

__device__ uint32_t interpret(const StwoRv64GkrWireRun &r, bool wire, Sink &sink) {
  const uint32_t *p = r.program;
  const uint32_t count = p[wire ? 4 : 3], at = p[wire ? 10 : 9];
  const uint32_t *pool = p + p[11];
  for (uint32_t i = 0; i < count; ++i) {
    const uint32_t *op = p + at + uint64_t(i) * 4;
    const uint32_t kind = op[0], source = op[1], off = op[2], n = op[3];
    if (kind == 0) {
      if (source != 0 || uint64_t(off) + n > p[6]) return 2;
      for (uint32_t b = 0; b < n; ++b) sink.byte(pool[(uint64_t(off) + b) >> 2] >> (8 * ((off + b) & 3)));
      if (sink.detail) return sink.detail;
      continue;
    }
    const uint32_t *data = source == 1 ? r.section : source == 2 ? r.scope : source == 3 ? r.marginals : nullptr;
    const uint64_t words = source == 1 ? r.section_words : source == 2 ? 25 : source == 3 ? r.marginal_words : 0;
    const uint64_t need = kind == 1 ? n : kind == 2 ? uint64_t(n) * 8 : (kind == 3 || kind == 4) ? 44 : kind == 5 ? 1 : UINT64_MAX;
    if (!data || need > words || uint64_t(off) > words - need) return 2;
    data += off;
    if (kind == 1 || kind == 2) {
      for (uint64_t w = 0; w < need; ++w) {
        if (kind == 2 && data[w] >= kModulus) return 3;
        sink.word(data[w]);
      }
    } else if (kind == 5) {
      sink.word(data[0]); sink.word(0);
    } else {
      const uint32_t coefficients = data[40];
      if (coefficients > 4 || data[41] != n || data[42] || data[43]) return 2;
      for (uint32_t w = 0; w < 40; ++w) if (data[w] >= kModulus) return 3;
      for (uint32_t w = 8 * coefficients; w < 32; ++w) if (data[w]) return 2;
      uint32_t last = 0;
      if (coefficients) {
        for (uint32_t w = 0; w < 8; ++w) last |= data[8 * (coefficients - 1) + w];
        if (!last) return 2;
      }
      sink.word(coefficients);
      if (kind == 4) sink.word(0);
      for (uint32_t w = 0; w < 8 * coefficients; ++w) sink.word(data[w]);
    }
    if (sink.detail) return sink.detail;
  }
  return 0;
}

__global__ void encode(StwoRv64GkrWireRun r) {
  if (blockIdx.x || threadIdx.x) return;
  r.wire[0] = 0;
  for (uint32_t i = 0; i < 16; ++i) r.receipt[i] = 0;
  const uint32_t *p = r.program;
  uint32_t detail = 0;
  if (r.program_words < 12 || p[0] != kMagic || p[1] != 1 || p[2] != r.program_words ||
      p[7] != r.section_words || p[8] != r.marginal_words || p[9] != 12 ||
      uint64_t(p[10]) != 12 + 4ull * p[3] || uint64_t(p[11]) != 12 + 4ull * (uint64_t(p[3]) + p[4]) ||
      uint64_t(p[11]) * 4 + p[6] > r.program_words * 4 || p[5] > (r.wire_words - 1) * 4) detail = 2;
  HashStream hash;
  hash.init();
  Sink receipt{&hash, nullptr, 64ull << 20, 0, 0};
  Sink wire{nullptr, r.wire + 1, (r.wire_words - 1) * 4, 0, 0};
  if (!detail) detail = interpret(r, false, receipt);
  if (!detail) detail = interpret(r, true, wire);
  if (!detail && (wire.written > p[5] || wire.written > UINT32_MAX)) detail = 4;
  if (!detail) {
    hash.finish(r.receipt);
    r.wire[0] = uint32_t(wire.written);
  }
  *r.verdict = detail ? (r.reject_code | detail) : 0;
}
} // namespace

extern "C" int stwo_rv64_gkr_receipt_encode_v1_on(void *context, uint32_t lane, const StwoRv64GkrWireRun *run) {
  if (!run || !run->program || !run->section || !run->scope || !run->marginals || !run->receipt || !run->wire || !run->verdict ||
      run->program_words < 12 || run->program_words > (1u << 20) || !run->section_words || run->section_words > (1u << 20) ||
      !run->marginal_words || run->marginal_words > 1024 || run->wire_words < 2 || run->wire_words > (16u << 20) / 4 + 1 ||
      run->reserved || (run->reject_code & 0xffffu) || run->reject_code == 0 || run->reject_code == 0xffff0000u)
    return int(cudaErrorInvalidValue);
  using stwo::cuda::rv64::RangeCustody;
  RangeCustody<7> custody(context, lane);
  if (!custody.range(run->program, run->program_words, false) || !custody.range(run->section, run->section_words, false) ||
      !custody.range(run->scope, 25, false) || !custody.range(run->marginals, run->marginal_words, false) ||
      !custody.range(run->receipt, 16, true) || !custody.range(run->wire, run->wire_words, true) || !custody.range(run->verdict, 1, true))
    return custody.status;
  encode<<<1, 1, 0, custody.stream>>>(*run);
  return int(cudaPeekAtLastError());
}
