// fused_blake2s_v1: GPU witness fill, constraint check and hint-tape gather
// for the fused Blake2s compression component (stream blake-gadget, M5).
//
// The row program is defined once in
// src/frontends/circuit/fused_blake/fused_blake2s_v1.zig (`fillRow`, `Eval`);
// this file mirrors it cell for cell. Equality is tested by dumping GPU rows
// and comparing them with the Zig fill (`fused_blake2s_selftest.cu` +
// `test "fused_blake2s_v1: GPU fill dump equals the CPU fill"`).
//
// Layout: column-major M31 words, column c of row r at cols[c * stride + r]
// (one thread per row, so every column store is coalesced across a warp).
//
// Exports (C ABI, all asynchronous on `stream` except the shadow entry):
//   stwo_fused_blake2s_v1_fill_on   tape -> trace columns + XOR multiplicities
//   stwo_fused_blake2s_v1_check_on  trace columns -> violation count
//   stwo_fused_blake2s_v1_shadow_on outer circuit values + G-gate addresses
//                                   -> hint tape -> fill (+ check), timed
#include <cstdint>
#include <cstdio>
#include <cuda_runtime.h>

namespace fused_blake2s_v1 {

constexpr uint32_t P = 0x7fffffffu;
constexpr int N_COLUMNS = 3328;
constexpr int TAPE_WORDS = 26;
constexpr int N_XOR8_LOOKUPS = 80 * 8 + 8 * 8;
constexpr int N_SPLIT_LOOKUPS = 80 * 4;
constexpr uint32_t MIN_LOG_ROWS = 4;
constexpr uint32_t MAX_INSTANCES = 3;

__device__ __constant__ uint32_t kIV[8] = {0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
                                            0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u};
__device__ __constant__ uint8_t kSigma[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};
__device__ __constant__ uint8_t kG[8][4] = {{0, 4, 8, 12}, {1, 5, 9, 13}, {2, 6, 10, 14}, {3, 7, 11, 15},
                                            {0, 5, 10, 15}, {1, 6, 11, 12}, {2, 7, 8, 13}, {3, 4, 9, 14}};

// Compile-time copies for the fully unrolled fill: after unrolling every
// call has constant arguments, so the message index folds and r.m stays in
// registers (a __constant__ table would force a dynamic local-memory index).
__host__ __device__ constexpr uint8_t sigma_c(int round, int i) {
  constexpr uint8_t S[10][16] = {
      {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
      {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}, {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
      {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}, {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
      {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}, {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
      {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}, {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};
  return S[round][i];
}
__host__ __device__ constexpr uint8_t g_c(int gi, int k) {
  constexpr uint8_t G[8][4] = {{0, 4, 8, 12}, {1, 5, 9, 13}, {2, 6, 10, 14}, {3, 7, 11, 15},
                               {0, 5, 10, 15}, {1, 6, 11, 12}, {2, 7, 8, 13}, {3, 4, 9, 14}};
  return G[gi][k];
}
__host__ __device__ constexpr uint32_t iv_c(int i) {
  constexpr uint32_t V[8] = {0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au, 0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u};
  return V[i];
}

__host__ __device__ inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

struct Record {
  uint32_t h[8];
  uint32_t m[16];
  uint32_t t0;
  uint32_t last;
};

__device__ inline void load_record(const uint32_t* tape, uint64_t index, Record& r) {
  const uint32_t* w = tape + index * TAPE_WORDS;
#pragma unroll
  for (int i = 0; i < 8; i++) r.h[i] = w[i];
#pragma unroll
  for (int i = 0; i < 16; i++) r.m[i] = w[8 + i];
  r.t0 = w[24];
  r.last = w[25] & 1u;
}

__device__ inline void zero_record(Record& r) {
#pragma unroll
  for (int i = 0; i < 8; i++) r.h[i] = 0;
#pragma unroll
  for (int i = 0; i < 16; i++) r.m[i] = 0;
  r.t0 = 0;
  r.last = 0;
}

// SplitMix64, identical to `SplitMix64` / `randomRecord` in the Zig spec.
__host__ __device__ inline uint64_t splitmix_next(uint64_t& s) {
  s += 0x9E3779B97F4A7C15ull;
  uint64_t z = s;
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}

__host__ __device__ inline void random_record(uint64_t seed, uint64_t index, uint32_t* words) {
  uint64_t s = seed ^ (index * 0xD6E8FEB86659FD93ull);
  for (int i = 0; i < 25; i++) words[i] = (uint32_t)splitmix_next(s);
  words[25] = (uint32_t)(splitmix_next(s) & 1u);
}

// ---------------------------------------------------------------------------
// Fill (mirrors `Fill` / `fillRow`).

struct Writer {
  uint32_t* base;  // already offset by the row
  uint64_t stride;
  uint32_t at;
  uint32_t* m8;
  uint32_t* m4;
  uint32_t* m7;

  __device__ inline void put(uint32_t x) {
    base[(uint64_t)at * stride] = x;
    at++;
  }
  __device__ inline void word(uint32_t x) {
    put(x & 0xff);
    put((x >> 8) & 0xff);
    put((x >> 16) & 0xff);
    put(x >> 24);
  }
  __device__ inline uint32_t add3(uint32_t a, uint32_t b, uint32_t c) {
    uint32_t r = a + b + c;
    word(r);
    return r;
  }
  __device__ inline uint32_t add2(uint32_t a, uint32_t b) {
    uint32_t r = a + b;
    word(r);
    return r;
  }
  // Table row (x << 8) | y: the circuit's bitwise_xor_8 order (`tableRow`
  // in the Zig spec; operand x in the high byte of the row index).
  __device__ inline void count(uint32_t* table, uint32_t x, uint32_t y) {
    if (table) {
#pragma unroll
      for (int j = 0; j < 4; j++) atomicAdd(&table[(((x >> (8 * j)) & 0xff) << 8) | ((y >> (8 * j)) & 0xff)], 1u);
    }
  }
  __device__ inline uint32_t xor_(uint32_t x, uint32_t y) {
    count(m8, x, y);
    word(x ^ y);
    return x ^ y;
  }
  template <int SPLIT>
  __device__ inline uint32_t xor_split(uint32_t x, uint32_t y) {
    count(SPLIT == 4 ? m4 : m7, x, y);
    uint32_t z = x ^ y;
#pragma unroll
    for (int j = 0; j < 4; j++) {
      uint32_t byte = (z >> (8 * j)) & 0xff;
      put(byte & ((1u << SPLIT) - 1));
      put(byte >> SPLIT);
    }
    return z;
  }
};

__device__ inline void fill_row(Writer& w, const Record& r, uint32_t out[8]) {
#pragma unroll
  for (int i = 0; i < 16; i++) {
    w.put(r.m[i] & 0xffff);
    w.put(r.m[i] >> 16);
  }
#pragma unroll
  for (int i = 0; i < 8; i++) w.word(r.h[i]);
  uint32_t v[16];
#pragma unroll
  for (int i = 0; i < 8; i++) v[i] = r.h[i];
#pragma unroll
  for (int i = 0; i < 8; i++) v[8 + i] = iv_c(i);
  v[12] ^= r.t0;
  if (r.last) v[14] = ~v[14];
  // Fully unrolled: every SIGMA / G index is a compile-time constant, so the
  // state and message stay in registers.
#pragma unroll
  for (int round = 0; round < 10; round++) {
#pragma unroll
    for (int gi = 0; gi < 8; gi++) {
      const int ia = g_c(gi, 0), ib = g_c(gi, 1), ic = g_c(gi, 2), id = g_c(gi, 3);
      uint32_t a = v[ia], b = v[ib], c = v[ic], d = v[id];
      const uint32_t f0 = r.m[sigma_c(round, 2 * gi)];
      const uint32_t f1 = r.m[sigma_c(round, 2 * gi + 1)];
      const uint32_t a1 = w.add3(a, b, f0);
      const uint32_t d1 = rotr(w.xor_(d, a1), 16);
      const uint32_t c1 = w.add2(c, d1);
      const uint32_t b1 = rotr(w.xor_split<4>(b, c1), 12);
      const uint32_t a2 = w.add3(a1, b1, f1);
      const uint32_t d2 = rotr(w.xor_(d1, a2), 8);
      const uint32_t c2 = w.add2(c1, d2);
      const uint32_t b2 = rotr(w.xor_split<7>(b1, c2), 7);
      v[ia] = a2;
      v[ib] = b2;
      v[ic] = c2;
      v[id] = d2;
    }
  }
#pragma unroll
  for (int i = 0; i < 8; i++) out[i] = w.xor_(w.xor_(r.h[i], v[i]), v[i + 8]);
}

// Rows [first, first + count) of an instance whose real records are
// tape[0 .. n_records); rows at or past n_records are padding (zero record).
__global__ void fill_kernel(const uint32_t* __restrict__ tape, uint64_t n_records, uint64_t first, uint64_t count,
                            uint32_t* __restrict__ cols, uint64_t stride, uint32_t* m8, uint32_t* m4, uint32_t* m7) {
  const uint64_t local = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
  if (local >= count) return;
  const uint64_t row = first + local;
  Record r;
  if (row < n_records)
    load_record(tape, row, r);
  else
    zero_record(r);
  Writer w{cols + local, stride, 0, m8, m4, m7};
  uint32_t out[8];
  fill_row(w, r, out);
}

// ---------------------------------------------------------------------------
// Check (mirrors `Eval`): M31 residuals, table membership, outputs vs the
// independent reference compression of the tape record, Gate limbs vs tape.

__device__ inline uint32_t fadd(uint32_t a, uint32_t b) {
  uint32_t s = a + b;
  return s >= P ? s - P : s;
}
__device__ inline uint32_t fsub(uint32_t a, uint32_t b) { return fadd(a, b == 0 ? 0 : P - b); }
__device__ inline uint32_t fmulc(uint32_t a, uint32_t c) { return (uint32_t)(((uint64_t)a * c) % P); }
constexpr uint32_t INV_2_16 = 1u << 15;

struct Reader {
  const uint32_t* base;
  uint64_t stride;
  uint32_t at;
  uint32_t bad;

  __device__ inline uint32_t col() {
    uint32_t x = base[(uint64_t)at * stride];
    at++;
    if (x >= P) bad++;
    return x;
  }
  __device__ inline void word(uint32_t b[4]) {
    for (int j = 0; j < 4; j++) b[j] = col();
  }
};

struct Bytes {
  uint32_t b[4];
};

__device__ inline void limbs(const Bytes& x, uint32_t& lo, uint32_t& hi) {
  lo = fadd(x.b[0], fmulc(x.b[1], 256));
  hi = fadd(x.b[2], fmulc(x.b[3], 256));
}

struct Checker {
  Reader rd;
  uint32_t violations;

  __device__ inline void carry(uint32_t e, uint32_t max) {
    if (e > max) violations++;
  }
  template <int N>
  __device__ inline Bytes add(const Bytes (&ops)[N], const uint32_t (*extra)) {
    Bytes r;
    rd.word(r.b);
    uint32_t rl, rh;
    limbs(r, rl, rh);
    uint32_t lo = 0, hi = 0;
    for (int i = 0; i < N; i++) {
      uint32_t l, h;
      limbs(ops[i], l, h);
      lo = fadd(lo, l);
      hi = fadd(hi, h);
    }
    uint32_t max = N - 1;
    if (extra) {
      lo = fadd(lo, extra[0]);
      hi = fadd(hi, extra[1]);
      max = N;
    }
    const uint32_t e_lo = fmulc(fsub(lo, rl), INV_2_16);
    carry(e_lo, max);
    const uint32_t e_hi = fmulc(fsub(fadd(hi, e_lo), rh), INV_2_16);
    carry(e_hi, max);
    return r;
  }
  __device__ inline Bytes xor_(const Bytes& x, const Bytes& y) {
    Bytes z;
    rd.word(z.b);
    for (int j = 0; j < 4; j++)
      if (x.b[j] >= 256 || y.b[j] >= 256 || z.b[j] != (x.b[j] ^ y.b[j])) violations++;
    return z;
  }
  template <int SPLIT>
  __device__ inline void xor_split(const Bytes& x, const Bytes& y, Bytes& lo, Bytes& hi) {
    for (int j = 0; j < 4; j++) {
      lo.b[j] = rd.col();
      hi.b[j] = rd.col();
      if (x.b[j] >= 256 || y.b[j] >= 256) {
        violations++;
        continue;
      }
      const uint32_t z = x.b[j] ^ y.b[j];
      if (lo.b[j] != (z & ((1u << SPLIT) - 1)) || hi.b[j] != (z >> SPLIT)) violations++;
    }
  }
};

__device__ inline Bytes const_bytes(uint32_t x) { return Bytes{{x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, x >> 24}}; }
__device__ inline uint32_t word_of(const Bytes& b) { return b.b[0] | (b.b[1] << 8) | (b.b[2] << 16) | (b.b[3] << 24); }

__device__ inline void reference_compress(const Record& r, uint32_t out[8]) {
  uint32_t v[16];
  for (int i = 0; i < 8; i++) v[i] = r.h[i];
  for (int i = 0; i < 8; i++) v[8 + i] = kIV[i];
  v[12] ^= r.t0;
  if (r.last) v[14] = ~v[14];
  for (int round = 0; round < 10; round++)
    for (int gi = 0; gi < 8; gi++) {
      uint32_t a = v[kG[gi][0]], b = v[kG[gi][1]], c = v[kG[gi][2]], d = v[kG[gi][3]];
      a = a + b + r.m[kSigma[round][2 * gi]];
      d = rotr(d ^ a, 16);
      c = c + d;
      b = rotr(b ^ c, 12);
      a = a + b + r.m[kSigma[round][2 * gi + 1]];
      d = rotr(d ^ a, 8);
      c = c + d;
      b = rotr(b ^ c, 7);
      v[kG[gi][0]] = a;
      v[kG[gi][1]] = b;
      v[kG[gi][2]] = c;
      v[kG[gi][3]] = d;
    }
  for (int i = 0; i < 8; i++) out[i] = r.h[i] ^ v[i] ^ v[i + 8];
}

__global__ void check_kernel(const uint32_t* __restrict__ cols, uint64_t stride, const uint32_t* __restrict__ tape,
                             uint64_t n_records, uint64_t first, uint64_t count, unsigned long long* violations) {
  const uint64_t local = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
  if (local >= count) return;
  const uint64_t row = first + local;
  Record rec;
  if (row < n_records)
    load_record(tape, row, rec);
  else
    zero_record(rec);
  Checker ck{Reader{cols + local, stride, 0, 0}, 0};
  uint32_t m[16][2];
  for (int k = 0; k < 16; k++) {
    m[k][0] = ck.rd.col();
    m[k][1] = ck.rd.col();
    // Gate tuple of a message word vs the tape (what the Gate relation binds).
    if (m[k][0] != (rec.m[k] & 0xffff) || m[k][1] != (rec.m[k] >> 16)) ck.violations++;
  }
  Bytes h[8];
  for (int i = 0; i < 8; i++) {
    ck.rd.word(h[i].b);
    uint32_t lo, hi;
    limbs(h[i], lo, hi);
    if (lo != (rec.h[i] & 0xffff) || hi != (rec.h[i] >> 16)) ck.violations++;
  }
  Bytes v[16];
  for (int i = 0; i < 8; i++) v[i] = h[i];
  for (int i = 0; i < 8; i++) v[8 + i] = const_bytes(kIV[i]);
  v[12] = const_bytes(kIV[4] ^ rec.t0);
  for (int j = 0; j < 4; j++) {
    const uint32_t iv = (kIV[6] >> (8 * j)) & 0xff;
    v[14].b[j] = rec.last ? fsub(fsub(255, iv), 0) : iv;
  }
  for (int round = 0; round < 10; round++)
    for (int gi = 0; gi < 8; gi++) {
      const int ia = kG[gi][0], ib = kG[gi][1], ic = kG[gi][2], id = kG[gi][3];
      const uint32_t* f0 = m[kSigma[round][2 * gi]];
      const uint32_t* f1 = m[kSigma[round][2 * gi + 1]];
      const Bytes ab[2] = {v[ia], v[ib]};
      const Bytes a1 = ck.add<2>(ab, f0);
      const Bytes z = ck.xor_(v[id], a1);
      const Bytes d1{{z.b[2], z.b[3], z.b[0], z.b[1]}};
      const Bytes cd[2] = {v[ic], d1};
      const Bytes c1 = ck.add<2>(cd, nullptr);
      Bytes xl, xh;
      ck.xor_split<4>(v[ib], c1, xl, xh);
      Bytes b1;
      for (int j = 0; j < 4; j++) b1.b[j] = fadd(xh.b[(j + 1) % 4], fmulc(xl.b[(j + 2) % 4], 16));
      const Bytes ab1[2] = {a1, b1};
      const Bytes a2 = ck.add<2>(ab1, f1);
      const Bytes z2 = ck.xor_(d1, a2);
      const Bytes d2{{z2.b[1], z2.b[2], z2.b[3], z2.b[0]}};
      const Bytes cd2[2] = {c1, d2};
      const Bytes c2 = ck.add<2>(cd2, nullptr);
      Bytes yl, yh;
      ck.xor_split<7>(b1, c2, yl, yh);
      Bytes b2;
      for (int j = 0; j < 4; j++) b2.b[j] = fadd(yh.b[j], fmulc(yl.b[(j + 1) % 4], 2));
      v[ia] = a2;
      v[ib] = b2;
      v[ic] = c2;
      v[id] = d2;
    }
  uint32_t want[8];
  reference_compress(rec, want);
  for (int i = 0; i < 8; i++) {
    const Bytes u = ck.xor_(h[i], v[i]);
    const Bytes o = ck.xor_(u, v[i + 8]);
    if (word_of(o) != want[i]) ck.violations++;
  }
  if (ck.rd.at != N_COLUMNS) ck.violations++;
  const uint32_t total = ck.violations + ck.rd.bad;
  if (total) atomicAdd(violations, (unsigned long long)total);
}

// ---------------------------------------------------------------------------
// Gather: hint tape from the outer circuit's values + blake_g_gate addresses.
// Compression c is G rows [80c, 80c + 80). A chunk is accepted only if its
// round-0 inputs have the shape blake2sU32s builds (c = IV[0..4], d = IV[4..8]
// up to t0 / the last flag), every f0/f1 of every round equals the message
// word SIGMA selects, and the reference compression reproduces the outputs of
// every one of the 80 gates.

__device__ inline bool load_word(const uint32_t* values, uint32_t value_count, uint32_t addr, uint32_t& out) {
  if (addr >= value_count) return false;
  const uint32_t* q = values + 4ull * addr;
  if (q[2] != 0 || q[3] != 0 || q[0] >= 65536u || q[1] >= 65536u) return false;
  out = q[0] | (q[1] << 16);
  return true;
}

struct GatherPp {
  const uint32_t* col[10];  // input a, b, c, d, f0, f1; output a, b, c, d
};

__global__ void gather_kernel(const uint32_t* __restrict__ values, uint32_t value_count, GatherPp pp, uint64_t n_chunks,
                              uint32_t* __restrict__ tape, unsigned long long* n_valid, unsigned long long* n_shape) {
  const uint64_t c = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
  if (c >= n_chunks) return;
  const uint64_t g0 = c * 80;
  Record r;
  bool ok = true;
  uint32_t cin[4], din[4];
  for (int gi = 0; gi < 4; gi++) {
    ok &= load_word(values, value_count, pp.col[0][g0 + gi], r.h[gi]);
    ok &= load_word(values, value_count, pp.col[1][g0 + gi], r.h[4 + gi]);
    ok &= load_word(values, value_count, pp.col[2][g0 + gi], cin[gi]);
    ok &= load_word(values, value_count, pp.col[3][g0 + gi], din[gi]);
  }
  for (int gi = 0; gi < 8; gi++) {
    ok &= load_word(values, value_count, pp.col[4][g0 + gi], r.m[2 * gi]);
    ok &= load_word(values, value_count, pp.col[5][g0 + gi], r.m[2 * gi + 1]);
  }
  if (!ok) return;
  for (int i = 0; i < 4; i++) ok &= cin[i] == kIV[i];
  ok &= din[1] == kIV[5] && din[3] == kIV[7] && (din[2] == kIV[6] || din[2] == ~kIV[6]);
  if (!ok) return;
  atomicAdd(n_shape, 1ull);
  r.t0 = din[0] ^ kIV[4];
  r.last = din[2] == ~kIV[6] ? 1u : 0u;
  uint32_t v[16];
  for (int i = 0; i < 8; i++) v[i] = r.h[i];
  for (int i = 0; i < 8; i++) v[8 + i] = kIV[i];
  v[12] ^= r.t0;
  if (r.last) v[14] = ~v[14];
  for (int round = 0; round < 10 && ok; round++)
    for (int gi = 0; gi < 8 && ok; gi++) {
      const uint64_t g = g0 + 8 * round + gi;
      uint32_t f0, f1;
      ok &= load_word(values, value_count, pp.col[4][g], f0) && f0 == r.m[kSigma[round][2 * gi]];
      ok &= load_word(values, value_count, pp.col[5][g], f1) && f1 == r.m[kSigma[round][2 * gi + 1]];
      uint32_t a = v[kG[gi][0]], b = v[kG[gi][1]], cc = v[kG[gi][2]], d = v[kG[gi][3]];
      a = a + b + f0;
      d = rotr(d ^ a, 16);
      cc = cc + d;
      b = rotr(b ^ cc, 12);
      a = a + b + f1;
      d = rotr(d ^ a, 8);
      cc = cc + d;
      b = rotr(b ^ cc, 7);
      v[kG[gi][0]] = a;
      v[kG[gi][1]] = b;
      v[kG[gi][2]] = cc;
      v[kG[gi][3]] = d;
      uint32_t o[4];
      for (int k = 0; k < 4; k++) ok &= load_word(values, value_count, pp.col[6 + k][g], o[k]);
      ok &= o[0] == a && o[1] == b && o[2] == cc && o[3] == d;
    }
  if (!ok) return;
  const unsigned long long slot = atomicAdd(n_valid, 1ull);
  uint32_t* w = tape + slot * TAPE_WORDS;
  for (int i = 0; i < 8; i++) w[i] = r.h[i];
  for (int i = 0; i < 16; i++) w[8 + i] = r.m[i];
  w[24] = r.t0;
  w[25] = r.last;
}

__global__ void random_tape_kernel(uint64_t seed, uint64_t first, uint64_t count, uint32_t* tape) {
  const uint64_t i = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= count) return;
  random_record(seed, first + i, tape + i * TAPE_WORDS);
}

// Host-side instance plan, identical to `planInstances`.
inline uint32_t plan_instances(uint64_t n, uint32_t logs[MAX_INSTANCES]) {
  uint32_t used = 0;
  uint64_t remaining = n;
  while (remaining > 0) {
    uint32_t floor_log = 63 - __builtin_clzll(remaining);
    if (used + 1 == MAX_INSTANCES || floor_log < MIN_LOG_ROWS) {
      uint64_t need = remaining < (1ull << MIN_LOG_ROWS) ? (1ull << MIN_LOG_ROWS) : remaining;
      uint32_t log = 63 - __builtin_clzll(need);
      if ((1ull << log) < need) log++;
      logs[used++] = log;
      return used;
    }
    logs[used++] = floor_log;
    remaining -= 1ull << floor_log;
  }
  return used;
}

constexpr int kThreads = 128;

}  // namespace fused_blake2s_v1

using namespace fused_blake2s_v1;

extern "C" int stwo_fused_blake2s_v1_fill_on(const uint32_t* tape, uint64_t n_records, uint64_t first, uint64_t count,
                                             uint32_t* cols, uint64_t stride, uint32_t* xor_counts, void* stream) {
  if (count == 0) return 0;
  if (!cols || stride < count) return 2;
  uint32_t* m8 = xor_counts;
  uint32_t* m4 = xor_counts ? xor_counts + (1u << 16) : nullptr;
  uint32_t* m7 = xor_counts ? xor_counts + (2u << 16) : nullptr;
  const uint64_t blocks = (count + kThreads - 1) / kThreads;
  fill_kernel<<<(unsigned)blocks, kThreads, 0, (cudaStream_t)stream>>>(tape, n_records, first, count, cols, stride, m8, m4, m7);
  return cudaGetLastError() == cudaSuccess ? 0 : 1;
}

extern "C" int stwo_fused_blake2s_v1_check_on(const uint32_t* cols, uint64_t stride, const uint32_t* tape, uint64_t n_records,
                                              uint64_t first, uint64_t count, unsigned long long* violations, void* stream) {
  if (count == 0) return 0;
  const uint64_t blocks = (count + kThreads - 1) / kThreads;
  check_kernel<<<(unsigned)blocks, kThreads, 0, (cudaStream_t)stream>>>(cols, stride, tape, n_records, first, count, violations);
  return cudaGetLastError() == cudaSuccess ? 0 : 1;
}

extern "C" int stwo_fused_blake2s_v1_random_tape_on(uint64_t seed, uint64_t first, uint64_t count, uint32_t* tape, void* stream) {
  if (count == 0) return 0;
  const uint64_t blocks = (count + kThreads - 1) / kThreads;
  random_tape_kernel<<<(unsigned)blocks, kThreads, 0, (cudaStream_t)stream>>>(seed, first, count, tape);
  return cudaGetLastError() == cudaSuccess ? 0 : 1;
}

// Shadow mode for the outer circuit (STWO_RV64_FUSED_BLAKE=shadow|check):
// derives the hint tape from the node's device values and blake_g_gate
// address columns, plans <= 3 power-of-two instances and fills every
// instance row (padding included) into a scratch buffer, with XOR
// multiplicities. Nothing it writes is read by the prover; the proof is
// unchanged. Synchronises `stream` once at the end (diagnostic path).
//
// stats (out, 16 x u64): 0 g_rows, 1 chunks, 2 shape-matched, 3 valid,
// 4 fused_rows, 5 instances, 6 gather_ns, 7 fill_ns, 8 check_ns,
// 9 check_violations, 10 xor_lookups_counted, 11 scratch_rows,
// 12 bytes_written, 13 status, 14 instance logs packed (8 bits each),
// 15 memory source (bit0: tape from cudaMallocAsync, bit1: fill scratch from workspace).
// `workspace` (optional, `workspace_words` u32 words of device memory owned by
// the caller, e.g. an arena lease) is used when cudaMallocAsync cannot supply
// the tape or the fill scratch (the static device arena may hold the device).
extern "C" int stwo_fused_blake2s_v1_shadow_on(const uint32_t* values, uint32_t value_count, const uint32_t* const* gpp,
                                               uint32_t g_rows, uint32_t flags, void* stream_raw, uint64_t* stats,
                                               uint32_t* workspace, uint64_t workspace_words) {
  cudaStream_t stream = (cudaStream_t)stream_raw;
  for (int i = 0; i < 16; i++) stats[i] = 0;
  const uint64_t chunks = g_rows / 80;
  stats[0] = g_rows;
  stats[1] = chunks;
  if (chunks == 0) return 0;
  GatherPp pp;
  for (int i = 0; i < 10; i++) pp.col[i] = gpp[i];
  uint32_t* tape = nullptr;
  unsigned long long* counters = nullptr;  // 0 valid, 1 shape, 2 violations
  uint32_t* xor_counts = nullptr;
  uint32_t* cols = nullptr;
  cudaEvent_t ev[6];
  for (auto& e : ev) cudaEventCreate(&e);
  int status = 0;
  unsigned long long host_counters[3] = {0, 0, 0};
  uint64_t rows_total = 0, scratch_rows = 0;
  uint32_t logs[MAX_INSTANCES] = {0, 0, 0};
  uint32_t n_inst = 0;
  float gather_ms = 0, fill_ms = 0, check_ms = 0;
  bool owned = true;  // tape/counters/xor_counts from cudaMallocAsync (else carved from workspace)
  uint64_t ws_used = 0;
  const uint64_t fixed_words = chunks * TAPE_WORDS + 8 + 3u * (1u << 16);
  if (cudaMallocAsync((void**)&tape, chunks * TAPE_WORDS * 4, stream) != cudaSuccess ||
      cudaMallocAsync((void**)&counters, 3 * sizeof(unsigned long long), stream) != cudaSuccess ||
      cudaMallocAsync((void**)&xor_counts, 3u * (1u << 16) * 4, stream) != cudaSuccess) {
    cudaGetLastError();
    if (tape) cudaFreeAsync(tape, stream);
    if (counters) cudaFreeAsync(counters, stream);
    if (xor_counts) cudaFreeAsync(xor_counts, stream);
    owned = false;
    if (!workspace || workspace_words < fixed_words) {
      tape = nullptr;
      counters = nullptr;
      xor_counts = nullptr;
      status = 10;
      goto done;
    }
    counters = (unsigned long long*)workspace;  // 8 words, 8-byte aligned
    xor_counts = workspace + 8;
    tape = workspace + 8 + 3u * (1u << 16);
    ws_used = fixed_words;
  }
  stats[15] = owned ? 1 : 0;
  cudaMemsetAsync(counters, 0, 3 * sizeof(unsigned long long), stream);
  cudaMemsetAsync(xor_counts, 0, 3u * (1u << 16) * 4, stream);
  cudaEventRecord(ev[0], stream);
  gather_kernel<<<(unsigned)((chunks + kThreads - 1) / kThreads), kThreads, 0, stream>>>(values, value_count, pp, chunks, tape,
                                                                                     counters, counters + 1);
  cudaEventRecord(ev[1], stream);
  if (cudaMemcpyAsync(host_counters, counters, 2 * sizeof(unsigned long long), cudaMemcpyDeviceToHost, stream) != cudaSuccess ||
      cudaStreamSynchronize(stream) != cudaSuccess) {
    status = 11;
    goto done;
  }
  n_inst = plan_instances(host_counters[0], logs);
  for (uint32_t i = 0; i < n_inst; i++) rows_total += 1ull << logs[i];
  // Scratch: the largest instance if it fits, else halve down to 2^12 rows.
  scratch_rows = n_inst ? (1ull << logs[0]) : 0;
  {
    bool cols_owned = true;
    while (scratch_rows && cudaMallocAsync((void**)&cols, scratch_rows * N_COLUMNS * 4ull, stream) != cudaSuccess) {
      cudaGetLastError();
      cols = nullptr;
      scratch_rows = scratch_rows > 4096 ? scratch_rows / 2 : 0;
    }
    if (n_inst && !cols && workspace && workspace_words > ws_used) {
      // Largest power of two of rows that fits the rest of the workspace.
      uint64_t fit = (workspace_words - ws_used) / N_COLUMNS;
      scratch_rows = 1ull << logs[0];
      while (scratch_rows > fit) scratch_rows /= 2;
      if (scratch_rows >= 256) {
        cols = workspace + ws_used;
        cols_owned = false;
      }
    }
    if (n_inst && !cols) {
      status = 12;
      goto done;
    }
    if (!cols_owned) stats[15] |= 2;
  }
  {
    cudaEventRecord(ev[2], stream);
    uint64_t base = 0;
    for (uint32_t i = 0; i < n_inst; i++) {
      const uint64_t rows = 1ull << logs[i];
      for (uint64_t at = 0; at < rows; at += scratch_rows) {
        const uint64_t count = rows - at < scratch_rows ? rows - at : scratch_rows;
        // Instance i covers tape records [base, base + rows); records past
        // the valid count are padding.
        const uint64_t n_rec = host_counters[0] > base ? host_counters[0] - base : 0;
        if (stwo_fused_blake2s_v1_fill_on(tape + base * TAPE_WORDS, n_rec, at, count, cols, scratch_rows, xor_counts, stream)) status = 13;
        if (flags & 1) {
          cudaEventRecord(ev[4], stream);
          if (stwo_fused_blake2s_v1_check_on(cols, scratch_rows, tape + base * TAPE_WORDS, n_rec, at, count, counters + 2, stream))
            status = 14;
          cudaEventRecord(ev[5], stream);
          cudaEventSynchronize(ev[5]);
          float ms = 0;
          cudaEventElapsedTime(&ms, ev[4], ev[5]);
          check_ms += ms;
        }
      }
      base += rows;
    }
    cudaEventRecord(ev[3], stream);
  }
  if (cudaMemcpyAsync(host_counters + 2, counters + 2, sizeof(unsigned long long), cudaMemcpyDeviceToHost, stream) != cudaSuccess ||
      cudaStreamSynchronize(stream) != cudaSuccess) {
    status = 15;
    goto done;
  }
  cudaEventElapsedTime(&gather_ms, ev[0], ev[1]);
  if (n_inst) cudaEventElapsedTime(&fill_ms, ev[2], ev[3]);
  {
    // Sum of XOR multiplicities (must equal rows * lookups per row).
    static thread_local uint32_t host_counts[3u << 16];
    cudaMemcpyAsync(host_counts, xor_counts, sizeof(host_counts), cudaMemcpyDeviceToHost, stream);
    cudaStreamSynchronize(stream);
    uint64_t sum = 0;
    for (uint32_t i = 0; i < (3u << 16); i++) sum += host_counts[i];
    stats[10] = sum;
  }
done:
  if (cols && !(stats[15] & 2)) cudaFreeAsync(cols, stream);
  if (owned) {
    if (xor_counts) cudaFreeAsync(xor_counts, stream);
    if (counters) cudaFreeAsync(counters, stream);
    if (tape) cudaFreeAsync(tape, stream);
  }
  cudaStreamSynchronize(stream);
  for (auto& e : ev) cudaEventDestroy(e);
  cudaGetLastError();
  stats[2] = host_counters[1];
  stats[3] = host_counters[0];
  stats[4] = rows_total;
  stats[5] = n_inst;
  stats[6] = (uint64_t)(gather_ms * 1e6);
  // With checks on, fill_ns includes the check kernels; subtract them.
  stats[7] = (uint64_t)((fill_ms - check_ms > 0 ? fill_ms - check_ms : 0) * 1e6);
  stats[8] = (uint64_t)(check_ms * 1e6);
  stats[9] = host_counters[2];
  stats[11] = scratch_rows;
  stats[12] = rows_total * N_COLUMNS * 4ull;
  stats[13] = (uint64_t)status;
  for (uint32_t i = 0; i < n_inst; i++) stats[14] |= (uint64_t)logs[i] << (8 * i);
  return status;
}
