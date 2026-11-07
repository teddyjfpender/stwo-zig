// M9 streaming commit: standalone parity + CUDA-event A/B against the
// production commit pair at the same shapes.
//   REF  (production, M8 fullstack): per chunk of K full-height columns,
//        stwo_lde_n2b_columns_on (W1 + W2, writes the LDE chunk) then
//        stwo_blake2s_mixed_seeded_eager_compact_on (eager SoA prefix banks);
//        final call -> leaves; stwo_blake2s_layer_on to the root.
//   FUSED: per chunk, stwo_m9_lde_first_pass_on (W1 only) then
//        stwo_m9_stream_commit_on (W2 + leaf absorption on chip, no LDE);
//        final call -> level-k nodes; stwo_blake2s_layer_on to the root.
// Parity compares every leaf / level-k node, the root, the opened values of
// every column at the query rows and every authentication-path word, with an
// optional lifted lower-height group absorbed first (stable ascending height
// order, as the native lifted PCS). Inputs are random M31 coefficients and
// twiddles: both arms run identical arithmetic, so bit identity is the test.
//   N=src/backends/cuda/native
//   nvcc -O3 -std=c++17 -rdc=true -arch=sm_120 -I $N \
//     $N/commitment/bench/stream_commit_bench.cu $N/commitment/stream_commit.cu \
//     $N/commitment/progressive.cu $N/commitment/merkle.cu \
//     $N/transform/lde.cu $N/transform/n2b.cu $N/transform/b2n_retained.cu -o sc_bench
//   ./sc_bench parity
//   ./sc_bench bench LOG COLUMNS CHUNK REPS K [QUERIES]
#include "commitment/stream_commit.cuh"
#include "commitment/mixed_layout.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>

namespace b = stwo::cuda::blake2s;
namespace m9 = stwo::cuda::m9;

extern "C" {
int stwo_lde_n2b_columns_on(const uint32_t *, size_t, const uint32_t *, uint32_t *, size_t, uint32_t,
                            uint32_t, const uint32_t *, uint32_t, uint32_t, void *, uint32_t *);
int stwo_blake2s_mixed_seeded_eager_compact_on(uint32_t, uint32_t, const b::MixedSegment *, uint32_t,
                                               uint32_t, const uint32_t *, uint64_t, uint32_t *,
                                               uint64_t, uint32_t *, uint64_t, void *);
int stwo_blake2s_layer_on(const b::Hash *, uint32_t, b::Hash *, void *);
int stwo_m9_lde_first_pass_split_on(const uint32_t *, size_t, const uint32_t *, uint32_t *, size_t, uint32_t,
                                    uint32_t, const uint32_t *, uint32_t, uint32_t, void *);
int stwo_m9_stream_commit_on(const m9::StreamCommitParams *, void *);
int stwo_m9_stream_commit_upper_paths_on(const uint32_t *, uint32_t, uint32_t, const uint32_t *,
                                         uint32_t, uint32_t *, void *);
uint32_t stwo_m9_stream_commit_low_bits(uint32_t);
int stwo_m9_stream_commit_occupancy(uint32_t, int *, int *);
}

#define CK(x)                                                                         \
  do {                                                                                \
    cudaError_t e_ = (x);                                                             \
    if (e_ != cudaSuccess) {                                                          \
      std::fprintf(stderr, "%s:%d %s: %s\n", __FILE__, __LINE__, #x, cudaGetErrorString(e_)); \
      std::exit(2);                                                                   \
    }                                                                                 \
  } while (0)
#define CKI(x)                                                                        \
  do {                                                                                \
    int e_ = (x);                                                                     \
    if (e_ != 0) {                                                                    \
      std::fprintf(stderr, "%s:%d %s: status %d (%s)\n", __FILE__, __LINE__, #x, e_,  \
                   cudaGetErrorString(cudaError_t(e_)));                              \
      std::exit(2);                                                                   \
    }                                                                                 \
  } while (0)

__global__ void fill(uint32_t *out, size_t n, uint32_t seed) {
  for (size_t i = blockIdx.x * size_t(blockDim.x) + threadIdx.x; i < n; i += size_t(gridDim.x) * blockDim.x) {
    uint64_t z = (uint64_t(i) + 1) * 0x9E3779B97F4A7C15ull + seed;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    z ^= z >> 31;
    out[i] = uint32_t(z % 0x7fffffffull);
  }
}
__global__ void gather_values(const uint32_t *chunk, size_t stride, uint32_t columns, const uint32_t *rows,
                              uint32_t nq, uint32_t column_base, uint32_t *values) {
  const uint32_t c = blockIdx.x * blockDim.x + threadIdx.x, q = blockIdx.y;
  if (c < columns) values[size_t(column_base + c) * nq + q] = chunk[size_t(c) * stride + rows[q]];
}
// Full-tree path extraction (rv64/trace.cu open_paths, at tree height).
__global__ void gather_paths(const uint32_t *tree, uint32_t log, const uint32_t *rows, uint32_t *paths) {
  const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x, q = blockIdx.y;
  if (i >= log * 8) return;
  const uint32_t level = i / 8, sibling = (rows[q] >> level) ^ 1u;
  const uint64_t leaves = uint64_t(1) << log, offset = 2 * leaves - ((2 * leaves) >> level);
  paths[(uint64_t(q) * log) * 8 + i] = tree[(offset + sibling) * 8 + (i & 7u)];
}

struct Shape {
  uint32_t log, columns, chunk, k, queries;
  uint32_t lifted_columns, lifted_log;  // lower-height group absorbed first
  uint32_t low = 0;                     // fused tile height override (0 = default)
  // Second arm (review): 0 = fused on every call; 1 = production non-final
  // calls + fused final call (integration step 2 as written); 2 = production
  // non-final calls + production LDE + stream_commit(lde_input) final call.
  uint32_t arm = 0;
  bool full_pool = false;  // distinct coefficients per column (chunk-invariance check)
};

struct Device {
  uint32_t *coeffs = nullptr, *logs = nullptr, *tw = nullptr, *chunk = nullptr;
  uint32_t *bank[2] = {nullptr, nullptr}, *tree = nullptr, *partial = nullptr;
  uint32_t *lifted_coeffs = nullptr, *lifted_logs = nullptr, *lifted_eval = nullptr;
  uint32_t *rows = nullptr, *ref_values = nullptr, *values = nullptr;
  uint32_t *ref_paths = nullptr, *paths = nullptr, *status = nullptr;
  size_t pool_columns = 0;
};

static size_t n_of(uint32_t log) { return size_t(1) << log; }

// Words absorbed before the full-height chunks and the seed that carries them.
struct Lifted {
  uint32_t absorbed = 0, seed_size = 0, bank = 0;
};

static void setup(const Shape &s, Device &d, cudaStream_t st, uint32_t seed) {
  const size_t n = n_of(s.log), half = n / 2;
  d.pool_columns = s.full_pool ? s.columns : std::min<size_t>(2 * size_t(s.chunk), s.columns + 1);
  CK(cudaMalloc(&d.coeffs, d.pool_columns * half * 4));
  CK(cudaMalloc(&d.logs, d.pool_columns * 4));
  CK(cudaMalloc(&d.tw, n * 4));
  CK(cudaMalloc(&d.chunk, size_t(s.chunk) * n * 4));
  for (auto &bank : d.bank) CK(cudaMalloc(&bank, 24 * n * 4));
  CK(cudaMalloc(&d.tree, (2 * n) * 32));
  CK(cudaMalloc(&d.partial, ((2 * n) >> s.k) * 32 + 64));
  fill<<<1024, 256, 0, st>>>(d.coeffs, d.pool_columns * half, seed);
  fill<<<1024, 256, 0, st>>>(d.tw, n, seed + 7);
  std::vector<uint32_t> logs(d.pool_columns);
  for (size_t c = 0; c < logs.size(); ++c) logs[c] = (c % 5 == 3) ? s.log - 3 : s.log - 1;  // some zero extension
  CK(cudaMemcpy(d.logs, logs.data(), logs.size() * 4, cudaMemcpyHostToDevice));
  if (s.lifted_columns) {
    const size_t ln = n_of(s.lifted_log);
    CK(cudaMalloc(&d.lifted_coeffs, s.lifted_columns * (ln / 2) * 4));
    CK(cudaMalloc(&d.lifted_logs, s.lifted_columns * 4));
    CK(cudaMalloc(&d.lifted_eval, s.lifted_columns * ln * 4));
    fill<<<1024, 256, 0, st>>>(d.lifted_coeffs, s.lifted_columns * (ln / 2), seed + 3);
    std::vector<uint32_t> ll(s.lifted_columns, s.lifted_log - 1);
    CK(cudaMemcpy(d.lifted_logs, ll.data(), ll.size() * 4, cudaMemcpyHostToDevice));
  }
  const uint32_t nq = std::max(1u, s.queries);
  std::mt19937 rng(seed);
  std::vector<uint32_t> rows(nq);
  for (auto &r : rows) r = rng() & uint32_t(n - 1);
  if (nq > 3) rows[3] = rows[1];  // a duplicate query
  CK(cudaMalloc(&d.rows, nq * 4));
  CK(cudaMemcpy(d.rows, rows.data(), nq * 4, cudaMemcpyHostToDevice));
  const uint32_t all_columns = s.columns + s.lifted_columns;
  CK(cudaMalloc(&d.ref_values, size_t(all_columns) * nq * 4));
  CK(cudaMalloc(&d.values, size_t(all_columns) * nq * 4));
  CK(cudaMalloc(&d.ref_paths, size_t(nq) * s.log * 32));
  CK(cudaMalloc(&d.paths, size_t(nq) * s.log * 32));
  CK(cudaMalloc(&d.status, 4));
  CK(cudaMemset(d.status, 0, 4));
  CK(cudaStreamSynchronize(st));
}

static void teardown(Device &d) {
  for (uint32_t *p : {d.coeffs, d.logs, d.tw, d.chunk, d.bank[0], d.bank[1], d.tree, d.partial,
                      d.lifted_coeffs, d.lifted_logs, d.lifted_eval, d.rows, d.ref_values, d.values,
                      d.ref_paths, d.paths, d.status})
    if (p) CK(cudaFree(p));
  d = Device{};
}

// The lifted group, identical in both arms (existing kernels at its native height).
static Lifted absorb_lifted(const Shape &s, Device &d, cudaStream_t st, bool want_values) {
  Lifted l;
  if (!s.lifted_columns) return l;
  const size_t ln = n_of(s.lifted_log);
  uint32_t launches = 0;
  CKI(stwo_lde_n2b_columns_on(d.lifted_coeffs, ln / 2, d.lifted_logs, d.lifted_eval, ln, s.lifted_log,
                              s.lifted_columns, d.tw, uint32_t(n_of(s.log)), uint32_t(ln / 2), st,
                              &launches));
  b::MixedSegment seg{d.lifted_eval, ln, s.lifted_columns * ln, uint32_t(ln), 0};
  const uint64_t cap = ln * (8 + (s.lifted_columns & 15));
  CKI(stwo_blake2s_mixed_seeded_eager_compact_on(uint32_t(ln), 1, &seg, 0, 0, nullptr, 0, d.bank[0], cap,
                                                 nullptr, 0, st));
  (void)want_values;
  l.absorbed = s.lifted_columns;
  l.seed_size = uint32_t(ln);
  l.bank = 0;
  return l;
}

// Times (ms) of one arm; parts[0] = transform, parts[1] = leaf/fused, parts[2] = layers.
struct ArmTimes { float total = 0, parts[3] = {0, 0, 0}; };

static ArmTimes run_ref(const Shape &s, Device &d, cudaStream_t st, bool extract) {
  const size_t n = n_of(s.log), half = n / 2;
  const uint32_t nq = std::max(1u, s.queries);
  cudaEvent_t ev[3];
  for (auto &e : ev) CK(cudaEventCreate(&e));
  ArmTimes times;
  cudaEvent_t start, stop;
  CK(cudaEventCreate(&start));
  CK(cudaEventCreate(&stop));
  CK(cudaEventRecord(start, st));
  Lifted l = absorb_lifted(s, d, st, extract);
  uint32_t absorbed = l.absorbed, seed_size = l.seed_size, seed_bank = l.bank;
  bool has_seed = l.absorbed != 0;
  uint32_t *leaves = d.tree;
  for (uint32_t first = 0; first < s.columns; first += s.chunk) {
    const uint32_t kc = std::min(s.chunk, s.columns - first);
    const bool final = first + kc == s.columns;
    const size_t pool = s.full_pool ? first : (first / s.chunk) % 2 ? std::min<size_t>(s.chunk, d.pool_columns - kc) : 0;
    CK(cudaEventRecord(ev[0], st));
    uint32_t launches = 0;
    CKI(stwo_lde_n2b_columns_on(d.coeffs + pool * half, half, d.logs + pool, d.chunk, n, s.log, kc, d.tw,
                                uint32_t(n), uint32_t(half), st, &launches));
    CK(cudaEventRecord(ev[1], st));
    b::MixedSegment seg{d.chunk, n, kc * n, uint32_t(n), 0};
    const uint32_t out_bank = has_seed ? 1 - seed_bank : 0;
    const uint64_t seed_cap = has_seed ? uint64_t(seed_size) * (8 + (absorbed & 15)) : 0;
    const uint32_t *seed = has_seed ? d.bank[seed_bank] : nullptr;
    if (final) {
      CKI(stwo_blake2s_mixed_seeded_eager_compact_on(uint32_t(n), 1, &seg, absorbed, has_seed ? seed_size : 0,
                                                     seed, seed_cap, nullptr, 0, leaves, n * 8, st));
    } else {
      CKI(stwo_blake2s_mixed_seeded_eager_compact_on(uint32_t(n), 1, &seg, absorbed, has_seed ? seed_size : 0,
                                                     seed, seed_cap, d.bank[out_bank],
                                                     n * (8 + ((absorbed + kc) & 15)), nullptr, 0, st));
    }
    CK(cudaEventRecord(ev[2], st));
    if (extract)
      gather_values<<<dim3{(kc + 127) / 128, nq}, 128, 0, st>>>(d.chunk, n, kc, d.rows, nq,
                                                                s.lifted_columns + first, d.ref_values);
    CK(cudaEventSynchronize(ev[2]));
    float a = 0, c = 0;
    CK(cudaEventElapsedTime(&a, ev[0], ev[1]));
    CK(cudaEventElapsedTime(&c, ev[1], ev[2]));
    times.parts[0] += a;
    times.parts[1] += c;
    absorbed += kc;
    seed_size = uint32_t(n);
    seed_bank = out_bank;
    has_seed = true;
  }
  if (extract && s.lifted_columns) {
    // Lifted values: lifted row of each query in the lower-height evaluation.
    std::vector<uint32_t> rows(nq);
    CK(cudaMemcpy(rows.data(), d.rows, nq * 4, cudaMemcpyDeviceToHost));
    const uint32_t r = s.log - s.lifted_log;
    std::vector<uint32_t> lifted(nq);
    for (uint32_t q = 0; q < nq; ++q) lifted[q] = ((rows[q] >> (r + 1)) << 1) | (rows[q] & 1u);
    uint32_t *lrows = nullptr;
    CK(cudaMalloc(&lrows, nq * 4));
    CK(cudaMemcpy(lrows, lifted.data(), nq * 4, cudaMemcpyHostToDevice));
    gather_values<<<dim3{(s.lifted_columns + 127) / 128, nq}, 128, 0, st>>>(
        d.lifted_eval, n_of(s.lifted_log), s.lifted_columns, lrows, nq, 0, d.ref_values);
    CK(cudaStreamSynchronize(st));
    CK(cudaFree(lrows));
  }
  CK(cudaEventRecord(ev[0], st));
  uint64_t offset = 0, next = n;
  for (uint64_t nodes = n; nodes > 1; nodes >>= 1) {
    CKI(stwo_blake2s_layer_on(reinterpret_cast<b::Hash *>(d.tree) + offset, uint32_t(nodes / 2),
                              reinterpret_cast<b::Hash *>(d.tree) + next, st));
    offset = next;
    next += nodes / 2;
  }
  CK(cudaEventRecord(ev[1], st));
  // Openings are timed in both arms when queries are requested (review fix:
  // the fused arm's in-kernel values used to be timed against an untimed REF).
  if (extract)
    gather_paths<<<dim3{(s.log * 8 + 127) / 128, nq}, 128, 0, st>>>(d.tree, s.log, d.rows, d.ref_paths);
  CK(cudaEventRecord(stop, st));
  CK(cudaEventSynchronize(stop));
  CK(cudaEventElapsedTime(&times.parts[2], ev[0], ev[1]));
  CK(cudaEventElapsedTime(&times.total, start, stop));
  for (auto &e : ev) CK(cudaEventDestroy(e));
  CK(cudaEventDestroy(start));
  CK(cudaEventDestroy(stop));
  return times;
}

static ArmTimes run_fused(const Shape &s, Device &d, cudaStream_t st, bool extract) {
  const size_t n = n_of(s.log), half = n / 2;
  const uint32_t nq = extract ? std::max(1u, s.queries) : 0;
  cudaEvent_t ev[3];
  for (auto &e : ev) CK(cudaEventCreate(&e));
  ArmTimes times;
  cudaEvent_t start, stop;
  CK(cudaEventCreate(&start));
  CK(cudaEventCreate(&stop));
  CK(cudaEventRecord(start, st));
  Lifted l = absorb_lifted(s, d, st, extract);
  if (extract && s.lifted_columns) {
    // The lifted group is untouched by this prototype: its values come from
    // its (small) materialised evaluation exactly as today.
    std::vector<uint32_t> rows(nq);
    CK(cudaMemcpy(rows.data(), d.rows, nq * 4, cudaMemcpyDeviceToHost));
    const uint32_t r = s.log - s.lifted_log;
    for (auto &q : rows) q = ((q >> (r + 1)) << 1) | (q & 1u);
    uint32_t *lrows = nullptr;
    CK(cudaMalloc(&lrows, nq * 4));
    CK(cudaMemcpy(lrows, rows.data(), nq * 4, cudaMemcpyHostToDevice));
    gather_values<<<dim3{(s.lifted_columns + 127) / 128, nq}, 128, 0, st>>>(
        d.lifted_eval, n_of(s.lifted_log), s.lifted_columns, lrows, nq, 0, d.values);
    CK(cudaStreamSynchronize(st));
    CK(cudaFree(lrows));
  }
  uint32_t absorbed = l.absorbed, seed_size = l.seed_size, seed_bank = l.bank;
  bool has_seed = l.absorbed != 0;
  for (uint32_t first = 0; first < s.columns; first += s.chunk) {
    const uint32_t kc = std::min(s.chunk, s.columns - first);
    const bool final = first + kc == s.columns;
    const size_t pool = s.full_pool ? first : (first / s.chunk) % 2 ? std::min<size_t>(s.chunk, d.pool_columns - kc) : 0;
    const bool production_call = s.arm != 0 && !final;
    const bool lde_final = s.arm == 2 && final;
    const uint32_t out_bank = has_seed ? 1 - seed_bank : 0;
    CK(cudaEventRecord(ev[0], st));
    if (production_call || lde_final) {
      uint32_t launches = 0;
      CKI(stwo_lde_n2b_columns_on(d.coeffs + pool * half, half, d.logs + pool, d.chunk, n, s.log, kc, d.tw,
                                  uint32_t(n), uint32_t(half), st, &launches));
    } else {
      CKI(stwo_m9_lde_first_pass_split_on(d.coeffs + pool * half, half, d.logs + pool, d.chunk, n, s.log, kc,
                                          d.tw, uint32_t(n), s.low, st));
    }
    CK(cudaEventRecord(ev[1], st));
    if (production_call) {
      b::MixedSegment seg{d.chunk, n, kc * n, uint32_t(n), 0};
      const uint64_t seed_cap = has_seed ? uint64_t(seed_size) * (8 + (absorbed & 15)) : 0;
      CKI(stwo_blake2s_mixed_seeded_eager_compact_on(uint32_t(n), 1, &seg, absorbed, has_seed ? seed_size : 0,
                                                     has_seed ? d.bank[seed_bank] : nullptr, seed_cap,
                                                     d.bank[out_bank], n * (8 + ((absorbed + kc) & 15)),
                                                     nullptr, 0, st));
      if (nq)
        gather_values<<<dim3{(kc + 127) / 128, nq}, 128, 0, st>>>(d.chunk, n, kc, d.rows, nq,
                                                                  s.lifted_columns + first, d.values);
      CK(cudaEventRecord(ev[2], st));
      CK(cudaEventSynchronize(ev[2]));
      float a = 0, c = 0;
      CK(cudaEventElapsedTime(&a, ev[0], ev[1]));
      CK(cudaEventElapsedTime(&c, ev[1], ev[2]));
      times.parts[0] += a;
      times.parts[1] += c;
      absorbed += kc;
      seed_size = uint32_t(n);
      seed_bank = out_bank;
      has_seed = true;
      continue;
    }
    m9::StreamCommitParams p{};
    p.intermediate = d.chunk;
    p.column_stride_words = n;
    p.columns = kc;
    p.log_n = s.log;
    p.twiddles = d.tw + n - half;
    // Negative control (SC_NEGATIVE=1): shift the fused twiddles by one word.
    if (std::getenv("SC_NEGATIVE")) p.twiddles += 1;
    p.absorbed_before = absorbed;
    p.seed_size = has_seed ? seed_size : 0;
    p.seed = has_seed ? d.bank[seed_bank] : nullptr;
    p.prefix = final ? nullptr : d.bank[out_bank];
    p.nodes = final ? d.partial : nullptr;
    p.subtree_levels = final ? s.k : 0;
    p.query_rows = nq ? d.rows : nullptr;
    p.query_count = nq;
    p.values = nq ? d.values : nullptr;
    p.value_column = s.lifted_columns + first;
    p.paths = (final && nq && s.k) ? d.paths : nullptr;
    p.path_log = s.log;
    p.status = d.status;
    p.low_bits = lde_final ? 0 : s.low;
    p.lde_input = lde_final ? 1 : 0;
    CKI(stwo_m9_stream_commit_on(&p, st));
    CK(cudaEventRecord(ev[2], st));
    CK(cudaEventSynchronize(ev[2]));
    float a = 0, c = 0;
    CK(cudaEventElapsedTime(&a, ev[0], ev[1]));
    CK(cudaEventElapsedTime(&c, ev[1], ev[2]));
    times.parts[0] += a;
    times.parts[1] += c;
    absorbed += kc;
    seed_size = uint32_t(n);
    seed_bank = out_bank;
    has_seed = true;
  }
  CK(cudaEventRecord(ev[0], st));
  const uint64_t base = n >> s.k;
  uint64_t offset = 0, next = base;
  for (uint64_t nodes = base; nodes > 1; nodes >>= 1) {
    CKI(stwo_blake2s_layer_on(reinterpret_cast<b::Hash *>(d.partial) + offset, uint32_t(nodes / 2),
                              reinterpret_cast<b::Hash *>(d.partial) + next, st));
    offset = next;
    next += nodes / 2;
  }
  CK(cudaEventRecord(ev[1], st));
  if (nq) CKI(stwo_m9_stream_commit_upper_paths_on(d.partial, s.log, s.k, d.rows, nq, d.paths, st));
  CK(cudaEventRecord(stop, st));
  CK(cudaEventSynchronize(stop));
  CK(cudaEventElapsedTime(&times.parts[2], ev[0], ev[1]));
  CK(cudaEventElapsedTime(&times.total, start, stop));
  for (auto &e : ev) CK(cudaEventDestroy(e));
  CK(cudaEventDestroy(start));
  CK(cudaEventDestroy(stop));
  return times;
}

static std::vector<uint32_t> down(const uint32_t *p, size_t words) {
  std::vector<uint32_t> h(words);
  CK(cudaMemcpy(h.data(), p, words * 4, cudaMemcpyDeviceToHost));
  return h;
}

// Returns mismatching words (0 = byte-identical) over nodes, root, values, paths.
static size_t parity_case(const Shape &s, cudaStream_t st, uint32_t seed, bool verbose) {
  Device d;
  setup(s, d, st, seed);
  const size_t n = n_of(s.log), nq = std::max(1u, s.queries);
  const uint32_t all = s.columns + s.lifted_columns;
  CK(cudaMemset(d.values, 0xee, all * nq * 4));
  CK(cudaMemset(d.paths, 0xee, nq * s.log * 32));
  CK(cudaMemset(d.partial, 0xee, ((2 * n) >> s.k) * 32));
  run_ref(s, d, st, true);
  run_fused(s, d, st, true);
  CK(cudaStreamSynchronize(st));
  size_t bad = 0;
  // Level-k nodes and every layer above: the partial tree is a suffix of the full one.
  const uint64_t full_offset = 2 * n - ((2 * n) >> s.k);
  const auto ref_tree = down(d.tree + full_offset * 8, ((2 * n) >> s.k) * 8 - 8);
  const auto got_tree = down(d.partial, ((2 * n) >> s.k) * 8 - 8);
  for (size_t i = 0; i < ref_tree.size(); ++i) bad += ref_tree[i] != got_tree[i];
  const auto rv = down(d.ref_values, all * nq), gv = down(d.values, all * nq);
  size_t bad_values = 0;
  for (size_t i = 0; i < rv.size(); ++i) bad_values += rv[i] != gv[i];
  const auto rp = down(d.ref_paths, nq * s.log * 8), gp = down(d.paths, nq * s.log * 8);
  size_t bad_paths = 0;
  for (size_t i = 0; i < rp.size(); ++i) bad_paths += rp[i] != gp[i];
  const auto status = down(d.status, 1);
  const auto root = down(d.partial + (((2 * n) >> s.k) - 2) * 8, 8);
  if (verbose || bad || bad_values || bad_paths || status[0])
    std::printf("parity arm=%u log=%u cols=%u chunk=%u k=%u q=%u lifted=%u@%u low=%u: tree_words=%zu bad=%zu "
                "values=%zu bad=%zu paths=%zu bad=%zu status=%u root=%08x%08x\n",
                s.arm, s.log, s.columns, s.chunk, s.k, s.queries, s.lifted_columns, s.lifted_log,
                s.low ? s.low : stwo_m9_stream_commit_low_bits(s.log), ref_tree.size(), bad, rv.size(), bad_values,
                rp.size(), bad_paths, status[0], root[0], root[1]);
  teardown(d);
  return bad + bad_values + bad_paths + status[0];
}

int main(int argc, char **argv) {
  cudaStream_t st;
  CK(cudaStreamCreateWithFlags(&st, cudaStreamNonBlocking));
  const char *mode = argc > 1 ? argv[1] : "parity";
  if (!std::strcmp(mode, "parity")) {
    size_t total = 0, cases = 0;
    // Every fused height (Low 10..13, cluster 1..8), multi-call chains with
    // every pending phase, lifted seeds, leaf / partial trees, queries.
    const Shape shapes[] = {
        {15, 3, 3, 0, 20, 0, 0},   {16, 37, 37, 0, 64, 0, 0},  {16, 37, 8, 5, 64, 5, 13},
        {17, 19, 7, 10, 108, 0, 0}, {18, 33, 16, 4, 108, 3, 16}, {19, 16, 16, 0, 108, 0, 0},
        {20, 32, 32, 5, 108, 0, 0}, {20, 21, 5, 1, 108, 17, 18}, {21, 32, 32, 10, 108, 0, 0},
        {22, 32, 32, 0, 108, 0, 0}, {22, 18, 8, 5, 108, 2, 20}, {23, 16, 16, 10, 108, 0, 0},
        {23, 17, 8, 3, 108, 6, 21}, {24, 16, 8, 0, 108, 0, 0},  {24, 45, 8, 10, 108, 0, 0},
        {24, 20, 8, 5, 216, 9, 22},
        // Taller W1 (heights 12..14) with fewer cross-CTA stages.
        {24, 18, 16, 0, 108, 0, 0, 12}, {24, 18, 16, 5, 108, 3, 22, 11}, {24, 17, 16, 10, 108, 0, 0, 10},
        {23, 17, 8, 0, 108, 0, 0, 11},  {23, 16, 16, 4, 108, 0, 0, 10},  {22, 16, 16, 0, 108, 5, 20, 10},
    };
    for (const auto &s : shapes) {
      total += parity_case(s, st, 1000 + uint32_t(cases), true);
      ++cases;
    }
    // Review additions. (a) Integration step 2 chains: production non-final
    // calls feeding a fused (arm 1) or LDE-input (arm 2) final call, incl. an
    // aligned production seed (pending 0) and every fused height. (b) Aligned
    // lifted seeds (16 / 32 lower-height words, pending 0) into the fused arm.
    Shape extra[] = {
        {24, 40, 16, 10, 108, 0, 0},    {24, 39, 16, 10, 108, 7, 22},   {24, 33, 8, 5, 216, 3, 22},
        {23, 32, 16, 0, 108, 0, 0},     {22, 37, 16, 10, 108, 5, 20},   {21, 48, 16, 10, 108, 0, 0},
        {20, 21, 5, 1, 108, 17, 18},    {18, 33, 16, 4, 108, 16, 16},   {16, 40, 16, 10, 64, 0, 0},
        {24, 40, 16, 10, 108, 16, 22},  {22, 20, 16, 3, 108, 32, 20},   {19, 17, 16, 0, 108, 16, 17},
    };
    for (uint32_t arm = 1; arm <= 2; ++arm)
      for (uint32_t i = 0; i < 9; ++i) {
        Shape s = extra[i];
        s.arm = arm;
        total += parity_case(s, st, 2000 + uint32_t(cases), true);
        ++cases;
      }
    for (uint32_t i = 9; i < 12; ++i) {
      total += parity_case(extra[i], st, 2000 + uint32_t(cases), true);
      ++cases;
    }
    // (c) Chunk invariance of the production root (the aligned-plan claim):
    // the same columns committed with different call boundaries.
    size_t inv_bad = 0;
    const Shape inv[] = {{16, 37, 37, 0, 0, 5, 13}, {20, 40, 40, 0, 0, 7, 18}, {24, 40, 40, 0, 0, 0, 0}};
    for (const auto &base : inv) {
      std::vector<uint32_t> roots;
      for (uint32_t chunk : {base.columns, 1u, 4u, 7u, 9u, 16u, 32u}) {
        if (base.log == 24 && chunk == 1) continue;
        Shape s = base;
        s.chunk = chunk;
        s.full_pool = true;
        Device d;
        setup(s, d, st, 77);
        run_ref(s, d, st, false);
        CK(cudaStreamSynchronize(st));
        const auto root = down(d.tree + (2 * n_of(s.log) - 2) * 8, 8);
        teardown(d);
        if (roots.empty()) roots = root;
        size_t diff = 0;
        for (int w = 0; w < 8; ++w) diff += root[w] != roots[w];
        inv_bad += diff;
        std::printf("chunk-invariance log=%u cols=%u lifted=%u chunk=%u root=%08x%08x diff_words=%zu\n", s.log,
                    s.columns, s.lifted_columns, chunk, root[0], root[1], diff);
      }
    }
    total += inv_bad;
    std::printf("PARITY %s cases=%zu mismatching_words=%zu (chunk-invariance diff_words=%zu)\n",
                total ? "FAIL" : "PASS", cases, total, inv_bad);
    return total ? 1 : 0;
  }
  if (!std::strcmp(mode, "occupancy")) {
    cudaDeviceProp prop{};
    CK(cudaGetDeviceProperties(&prop, 0));
    std::printf("device %s sms=%d l2=%d smem_block_optin=%zu smem_sm=%zu\n", prop.name, prop.multiProcessorCount,
                prop.l2CacheSize, prop.sharedMemPerBlockOptin, prop.sharedMemPerMultiprocessor);
    for (uint32_t log = 15; log <= 24; ++log) {
      int clusters = 0, size = 0;
      CKI(stwo_m9_stream_commit_occupancy(log, &clusters, &size));
      std::printf("OCC log=%u cluster=%d active_clusters=%d active_ctas=%d of %d SMs\n", log, size, clusters,
                  clusters * size, prop.multiProcessorCount);
    }
    return 0;
  }
  if (!std::strcmp(mode, "bench") && argc >= 7) {
    Shape s{uint32_t(std::atoi(argv[2])), uint32_t(std::atoi(argv[3])), uint32_t(std::atoi(argv[4])),
            uint32_t(std::atoi(argv[6])), argc > 7 ? uint32_t(std::atoi(argv[7])) : 0, 0, 0};
    const int reps = std::atoi(argv[5]);
    if (const char *o = std::getenv("SC_LOW")) s.low = uint32_t(std::atoi(o));
    if (const char *o = std::getenv("SC_ARM")) s.arm = uint32_t(std::atoi(o));
    if (const char *o = std::getenv("SC_OFFSET")) {  // lower-height words first: unaligned chains
      s.lifted_columns = uint32_t(std::atoi(o));
      s.lifted_log = s.log - 2;
    }
    Device d;
    setup(s, d, st, 42);
    const bool extract = s.queries != 0;
    run_ref(s, d, st, extract);  // warm
    run_fused(s, d, st, extract);
    std::vector<ArmTimes> ref, fused;
    for (int r = 0; r < reps; ++r) {
      ref.push_back(run_ref(s, d, st, extract));
      fused.push_back(run_fused(s, d, st, extract));
    }
    auto median = [](std::vector<ArmTimes> v, int part) {
      std::vector<float> x;
      for (auto &t : v) x.push_back(part < 0 ? t.total : t.parts[part]);
      std::sort(x.begin(), x.end());
      return x[x.size() / 2];
    };
    const double gb = double(s.columns) * n_of(s.log) * 4 / 1e9;
    std::printf("BENCH arm=%u low=%u offset=%u ", s.arm, s.low ? s.low : stwo_m9_stream_commit_low_bits(s.log),
                s.lifted_columns);
    std::printf("log=%u cols=%u chunk=%u k=%u q=%u reps=%d lde_gb=%.3f | ref total=%.3f lde=%.3f leaf=%.3f "
                "layers=%.3f | fused total=%.3f w1=%.3f fused=%.3f layers=%.3f | ratio=%.3f pair_ratio=%.3f\n",
                s.log, s.columns, s.chunk, s.k, s.queries, reps, gb, median(ref, -1), median(ref, 0),
                median(ref, 1), median(ref, 2), median(fused, -1), median(fused, 0), median(fused, 1),
                median(fused, 2), median(fused, -1) / median(ref, -1),
                (median(fused, 0) + median(fused, 1)) / (median(ref, 0) + median(ref, 1)));
    teardown(d);
    return 0;
  }
  std::fprintf(stderr, "usage: %s parity | bench LOG COLUMNS CHUNK REPS K [QUERIES]\n", argv[0]);
  return 2;
}
