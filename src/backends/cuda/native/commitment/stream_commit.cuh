#ifndef STWO_ZIG_CUDA_STREAM_COMMIT_CUH
#define STWO_ZIG_CUDA_STREAM_COMMIT_CUH

// M9 streaming commit prototype (STWO_RV64_M9_STREAM_COMMIT, default off).
//
// The production commit of one trace chunk is three HBM passes over the LDE:
//   W1  n2b_wide_strided*   coefficients -> intermediate   (stages 1..H)
//   W2  n2b_wide_contiguous intermediate -> LDE            (stages H+1..log_n)
//   L   mixed_leaf_kernel   LDE (+ eager prefix state) -> leaf / prefix
// This header fuses W2 and L: the last Low = log_n - H stages run on chip and
// each finished evaluation is absorbed straight into a Blake2s leaf state held
// in registers (one thread = one row). The LDE is never written, and the leaf
// pass never re-reads it.
//
// A W2 tile is 2^Low consecutive rows (Low = 13 at log 24). One CTA cannot keep
// 8192 Blake2s states, so a tile is split over a thread-block cluster of
// 2^(Low-10) CTAs x 1024 rows: the Low-10 cross-CTA stages run in registers on
// a column-sliced load and are exchanged through distributed shared memory;
// the remaining ten stages (incl. the circle stage) run per CTA with one
// padded shared-memory transpose and warp shuffles. Twiddles and stage
// indexing follow n2b_wide_stages exactly, and the Blake2s absorption follows
// mixed_leaf_kernel<true, true> (eager SoA seeds/prefixes), so values, leaves,
// nodes and roots are bit-identical to W2 + L.
//
// Decommitment outputs (delta §4 item 4): in the final call the CTA can hash
// its 1024 leaves up to `subtree_levels` (<= 10) levels on chip and write only
// level-k nodes (a leafless/partial tree), plus, for queried rows, the opened
// values of every absorbed column and the bottom k authentication siblings.

#include "blake2s_protocol.cuh"
#include "progressive_scalar.cuh"
#include "../common/circle_twiddle.cuh"
#include "../common/m31.cuh"

#include <cooperative_groups.h>
#include <cuda_runtime_api.h>
#include <stddef.h>
#include <stdint.h>

namespace stwo::cuda::m9 {

constexpr uint32_t kRows = 1024;            // rows (threads) per CTA
constexpr uint32_t kPad = kRows + kRows / 32;
constexpr uint32_t kMaxCtaQueries = 256;
constexpr uint32_t kMaxSubtreeLevels = 10;
struct StreamCommitParams {
  const uint32_t *intermediate;  // W1 output, column-major
  size_t column_stride_words;    // >= 2^log_n
  uint32_t columns;
  uint32_t log_n;
  const uint32_t *twiddles;      // domain twiddles (twiddles + words - n/2)
  uint32_t absorbed_before;      // words already absorbed into the seed
  uint32_t seed_size;            // rows of the seed (<= 2^log_n, lifted)
  const uint32_t *seed;          // eager SoA seed, plane stride seed_size
  uint32_t *prefix;              // eager SoA prefix out (non-final) or null
  uint32_t *nodes;               // final: level-k nodes (Hash AoS) or null
  uint32_t subtree_levels;       // k in [0, 10]; 0 = leaves
  const uint32_t *query_rows;    // rows at tree height (already lifted)
  uint32_t query_count;
  uint32_t *values;              // values[(value_column + c) * nq + qi]
  uint32_t value_column;
  uint32_t *paths;               // paths[(qi * path_log + level) * 8 + w]
  uint32_t path_log;             // tree log used for the path layout
  uint32_t *status;              // bit 4: CTA query overflow; bit 5: query row >= 2^log_n
  uint32_t low_bits;             // fused tile height (0 = default for log_n)
  // Review fix: 1 = `intermediate` is the finished LDE chunk (production W1 + W2
  // already ran). The kernel then only hashes (no FFT, no cluster, no
  // twiddles), so partial trees and on-chip openings are available at every
  // height without the fused tail's log 22-24 loss.
  uint32_t lde_input;
};

constexpr uint32_t kGroup = 16;             // columns per group = one Blake2s block
constexpr uint32_t kQueryWords = 2 * kMaxCtaQueries + 4;
// Shared memory (words): group buffer [16][kPad] (later the on-chip subtree),
// local twiddle cache (1023), cross twiddle cache (3 x 8), query list.
constexpr uint32_t kSmemWords = kGroup * kPad + 1024 + 32 + kQueryWords;
static_assert(kGroup * kPad >= 8u * 2u * kRows, "subtree fits the group buffer");

__device__ __forceinline__ uint32_t pad(uint32_t e) { return e + (e >> 5); }

__device__ __forceinline__ uint32_t lifted_row(uint32_t row, uint32_t log_ratio) {
  if (log_ratio == 0) return row;
  return ((row >> (log_ratio + 1u)) << 1u) | (row & 1u);
}

__device__ __forceinline__ uint32_t stage_twiddle(const M31 *twiddles, uint32_t log_n,
                                                  uint32_t bit, uint32_t left) {
  const uint32_t stage = log_n - bit;
  const uint32_t butterfly = left >> (bit + 1u);
  if (stage == log_n) return circle_twiddle(twiddles, butterfly);
  return twiddles[(1u << (log_n - 1u)) - (1u << stage) + butterfly];
}

// One radix-2 step with the partner in another lane: identical arithmetic to
// n2b_wide_stages (left' = l + t*r, right' = l - t*r), one multiply.
__device__ __forceinline__ uint32_t shuffle_butterfly(uint32_t x, uint32_t lane_bit,
                                                      bool is_left, uint32_t tw) {
  const uint32_t y = __shfl_xor_sync(0xffffffffu, x, lane_bit);
  const uint32_t product = m31_mul(tw, is_left ? y : x);
  return is_left ? m31_add(x, product) : m31_sub(y, product);
}

// Local twiddle cache: bit b holds 2^(9-b) butterflies of this CTA's rows.
__host__ __device__ constexpr uint32_t tc_off(uint32_t bit) { return 1024u - (2048u >> (bit + 1u)); }

#define STWO_M9_SET_PENDING(index, word)  \
  switch (index) {                         \
    case 0: p0 = word; break;              \
    case 1: p1 = word; break;              \
    case 2: p2 = word; break;              \
    case 3: p3 = word; break;              \
    case 4: p4 = word; break;              \
    case 5: p5 = word; break;              \
    case 6: p6 = word; break;              \
    case 7: p7 = word; break;              \
    case 8: p8 = word; break;              \
    case 9: p9 = word; break;              \
    case 10: p10 = word; break;            \
    case 11: p11 = word; break;            \
    case 12: p12 = word; break;            \
    case 13: p13 = word; break;            \
    case 14: p14 = word; break;            \
    default: p15 = word; break;            \
  }

#define STWO_M9_COMPRESS(counter, last)                                            \
  stwo::cuda::blake2s::progressive_compress(h0, h1, h2, h3, h4, h5, h6, h7, p0, p1, \
      p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13, p14, p15, counter, last)

template <uint32_t LowBits, bool LdeInput = false>
__global__ void __launch_bounds__(kRows, 1) stream_commit_kernel(StreamCommitParams p) {
  namespace cg = cooperative_groups;
  static_assert(LowBits >= 10 && LowBits <= 13, "fused tile height");
  static_assert(!LdeInput || LowBits == 10, "LDE input mode is single-CTA");
  constexpr uint32_t kCrossBits = LowBits - 10u;
  constexpr uint32_t kCluster = 1u << kCrossBits;
  constexpr uint32_t kSlice = kRows / kCluster;        // l values per CTA in the cross step
  constexpr uint32_t kPer = kSlice / 64u;              // l values per thread
  extern __shared__ uint32_t smem[];
  uint32_t *buf = smem;                                // [kGroup][kPad]
  uint32_t *tcache = buf + kGroup * kPad;              // 1023 (+1)
  uint32_t *xcache = tcache + 1024;                    // [hb][8]
  uint32_t *qlist = xcache + 32;                       // kMaxCtaQueries x 2
  uint32_t *qcount = qlist + 2 * kMaxCtaQueries;
  uint32_t *levels = buf;                              // after the last group

  const uint32_t t = threadIdx.x, lane = t & 31u;
  const uint32_t j = t >> 6, q = t & 63u;              // FFT layout: column j, thread q
  uint32_t rank = 0;
  if constexpr (kCluster > 1) rank = cg::this_cluster().block_rank();
  const uint32_t tile = blockIdx.x / kCluster;
  const uint32_t tile_base = tile << LowBits;
  const uint32_t row0 = tile_base | (rank << 10);
  const uint32_t row = row0 | t;
  const uint32_t log_n = p.log_n;
  const uint32_t size = 1u << log_n;
  const M31 *tw = p.twiddles;

  // ---- twiddle caches (column independent) ----
  if (!LdeInput && t < 1023u) {
    uint32_t bit = 0;
    while (t >= tc_off(bit + 1u)) ++bit;
    const uint32_t i = t - tc_off(bit);
    tcache[t] = stage_twiddle(tw, log_n, bit, row0 | (i << (bit + 1u)));
  }
  if (!LdeInput && t < kCrossBits * 8u) {
    const uint32_t hb = t / 8u, i = t % 8u, bit = 10u + hb;
    if (i < (1u << (kCrossBits - 1u - hb)))
      xcache[t] = stage_twiddle(tw, log_n, bit, tile_base | (i << (bit + 1u)));
  }
  // ---- queried rows of this CTA (any order, duplicates allowed) ----
  if (t == 0) *qcount = 0;
  // Every CTA of the cluster must be resident before remote DSMEM writes.
  if constexpr (kCluster > 1) cg::this_cluster().sync();
  else __syncthreads();
  for (uint32_t i = t; i < p.query_count; i += kRows) {
    const uint32_t r = p.query_rows[i];
    if (r >= size) {
      // No CTA owns it: fail closed instead of leaving values/paths unwritten.
      if (blockIdx.x == 0) atomicOr(p.status, 32u);
      continue;
    }
    if ((r >> 10) == (row0 >> 10)) {
      const uint32_t slot = atomicAdd(qcount, 1u);
      if (slot < kMaxCtaQueries) {
        qlist[2 * slot] = r & (kRows - 1u);
        qlist[2 * slot + 1] = i;
      } else {
        atomicOr(p.status, 16u);
      }
    }
  }
  __syncthreads();
  const uint32_t cta_queries = min(*qcount, kMaxCtaQueries);
  int qa = -1, qb = -1;
  for (uint32_t i = 0; i < cta_queries; ++i)
    if (qlist[2 * i] == t) {
      if (qa < 0) qa = int(qlist[2 * i + 1]);
      else if (qb < 0) qb = int(qlist[2 * i + 1]);
      else atomicOr(p.status, 16u);
    }

  // ---- seed (eager SoA, mixed_leaf_kernel<true, true> convention) ----
  uint32_t h0, h1, h2, h3, h4, h5, h6, h7;
  uint32_t p0 = 0, p1 = 0, p2 = 0, p3 = 0, p4 = 0, p5 = 0, p6 = 0, p7 = 0;
  uint32_t p8 = 0, p9 = 0, p10 = 0, p11 = 0, p12 = 0, p13 = 0, p14 = 0, p15 = 0;
  uint32_t pending = p.absorbed_before & 15u;
  if (p.seed != nullptr) {
    const uint32_t ss = p.seed_size;
    const uint32_t sr = lifted_row(row, __ffs(size / ss) - 1);
    const uint32_t *in = p.seed;
    h0 = in[0ull * ss + sr]; h1 = in[1ull * ss + sr];
    h2 = in[2ull * ss + sr]; h3 = in[3ull * ss + sr];
    h4 = in[4ull * ss + sr]; h5 = in[5ull * ss + sr];
    h6 = in[6ull * ss + sr]; h7 = in[7ull * ss + sr];
    // Pending seed words are re-read at the first group's hash step, so no
    // message register is live across any FFT phase.
  } else {
    uint32_t init[8];
    stwo::cuda::blake2s::initialize_leaf_for<true>(init);
    h0 = init[0]; h1 = init[1]; h2 = init[2]; h3 = init[3];
    h4 = init[4]; h5 = init[5]; h6 = init[6]; h7 = init[7];
  }
  uint64_t compressed_bytes = stwo::cuda::blake2s::kDomainPrefixBytes +
      uint64_t(p.absorbed_before - pending) * 4u;

  // Groups end on Blake2s block boundaries: the first one tops up the seed's
  // pending words, every later one is a whole block (the last may be short).
  const uint32_t first_group = pending ? min(16u - pending, p.columns) : min(kGroup, p.columns);
  const uint32_t groups = 1u + (p.columns - first_group + kGroup - 1u) / kGroup;
  uint32_t *col_buf = buf + j * kPad;
  // Mapping 1: element (k << 6) | q (k = element bits 9..6, coalesced rows).
  // Mapping 2: element ((q >> 2) << 6) | (k << 2) | (q & 3) (k = bits 5..2;
  // bits 1..0 are lane bits and finish with shuffles).
  auto e2 = [&](uint32_t k) { return ((q >> 2) << 6) | (k << 2) | (q & 3u); };
  for (uint32_t g = 0; g < groups; ++g) {
    const uint32_t start = g == 0 ? 0u : first_group + (g - 1u) * kGroup;
    const uint32_t count = g == 0 ? first_group : min(kGroup, p.columns - start);
    const bool active = j < count;
    const uint32_t *column = p.intermediate + size_t(start + j) * p.column_stride_words + tile_base;
    uint32_t v[16];
    if constexpr (!LdeInput) {
    if constexpr (kCluster > 1) {
      // Cross-CTA stages (bits LowBits-1..10) on a column slice, in registers.
      if (active) {
#pragma unroll
        for (uint32_t m = 0; m < kPer; ++m)
#pragma unroll
          for (uint32_t h = 0; h < kCluster; ++h)
            v[m * kCluster + h] = column[(h << 10) | (rank * kSlice + q + 64u * m)];
#pragma unroll
        for (uint32_t i = 0; i < kCrossBits; ++i) {
          const uint32_t hb = kCrossBits - 1u - i;
#pragma unroll
          for (uint32_t r = 0; r < kCluster / 2u; ++r) {
            const uint32_t kl = (r & ((1u << hb) - 1u)) | ((r >> hb) << (hb + 1u));
            const uint32_t kr = kl | (1u << hb);
            const M31 twiddle = xcache[hb * 8u + (kl >> (hb + 1u))];
#pragma unroll
            for (uint32_t m = 0; m < kPer; ++m) {
              const M31 left = v[m * kCluster + kl], product = m31_mul(twiddle, v[m * kCluster + kr]);
              v[m * kCluster + kl] = m31_add(left, product);
              v[m * kCluster + kr] = m31_sub(left, product);
            }
          }
        }
      }
      // The previous group's buffers are free in every rank (arrive after its hash).
      if (g > 0) asm volatile("barrier.cluster.wait.acquire.aligned;" ::: "memory");
      if (active) {
        cg::cluster_group cluster = cg::this_cluster();
#pragma unroll
        for (uint32_t h = 0; h < kCluster; ++h) {
          uint32_t *target = cluster.map_shared_rank(col_buf, h);
#pragma unroll
          for (uint32_t m = 0; m < kPer; ++m) target[pad(rank * kSlice + q + 64u * m)] = v[m * kCluster + h];
        }
      }
      asm volatile("barrier.cluster.arrive.release.aligned;" ::: "memory");
      asm volatile("barrier.cluster.wait.acquire.aligned;" ::: "memory");
      if (active) {
#pragma unroll
        for (uint32_t k = 0; k < 16; ++k) v[k] = col_buf[pad((k << 6) | q)];
      }
    } else {
      if (active) {
#pragma unroll
        for (uint32_t k = 0; k < 16; ++k) v[k] = column[(k << 6) | q];
      }
    }
    if (active) {
      // Bits 9..6 in registers (k bits 3..0).
#pragma unroll
      for (uint32_t i = 0; i < 4; ++i) {
        const uint32_t kb = 3u - i, bit = 6u + kb;
#pragma unroll
        for (uint32_t r = 0; r < 8; ++r) {
          const uint32_t kl = (r & ((1u << kb) - 1u)) | ((r >> kb) << (kb + 1u));
          const uint32_t kr = kl | (1u << kb);
          const M31 twiddle = tcache[tc_off(bit) + (kl >> (kb + 1u))];
          const M31 left = v[kl], product = m31_mul(twiddle, v[kr]);
          v[kl] = m31_add(left, product);
          v[kr] = m31_sub(left, product);
        }
      }
#pragma unroll
      for (uint32_t k = 0; k < 16; ++k) col_buf[pad((k << 6) | q)] = v[k];
    }
    __syncthreads();
    if (active) {
#pragma unroll
      for (uint32_t k = 0; k < 16; ++k) v[k] = col_buf[pad(e2(k))];
      // Bits 5..2 in registers (k bits 3..0).
#pragma unroll
      for (uint32_t i = 0; i < 4; ++i) {
        const uint32_t kb = 3u - i, bit = 2u + kb;
#pragma unroll
        for (uint32_t r = 0; r < 8; ++r) {
          const uint32_t kl = (r & ((1u << kb) - 1u)) | ((r >> kb) << (kb + 1u));
          const uint32_t kr = kl | (1u << kb);
          const M31 twiddle = tcache[tc_off(bit) + (e2(kl) >> (bit + 1u))];
          const M31 left = v[kl], product = m31_mul(twiddle, v[kr]);
          v[kl] = m31_add(left, product);
          v[kr] = m31_sub(left, product);
        }
      }
      // Bits 1..0 (bit 0 is the circle stage): lane bits 1..0.
#pragma unroll
      for (uint32_t i = 0; i < 2; ++i) {
        const uint32_t bit = 1u - i;
        const bool is_left = ((lane >> bit) & 1u) == 0u;
#pragma unroll
        for (uint32_t k = 0; k < 16; ++k)
          v[k] = shuffle_butterfly(v[k], 1u << bit, is_left,
                                   tcache[tc_off(bit) + ((e2(k) & ~(1u << bit)) >> (bit + 1u))]);
      }
#pragma unroll
      for (uint32_t k = 0; k < 16; ++k) col_buf[pad(e2(k))] = v[k];
    }
    __syncthreads();
    }  // !LdeInput
    // ---- hash layout: thread t = row t; one Blake2s block per full group ----
    // Every earlier block is compressed, so no message word is live here:
    // resetting them lets the compiler drop them across the FFT phases.
    p0 = p1 = p2 = p3 = p4 = p5 = p6 = p7 = 0;
    p8 = p9 = p10 = p11 = p12 = p13 = p14 = p15 = 0;
    if (g == 0 && p.seed != nullptr) {
      const uint32_t ss = p.seed_size;
      const uint32_t sr = lifted_row(row, __ffs(size / ss) - 1);
      for (uint32_t k = 0; k < pending; ++k) {
        const uint32_t word = p.seed[size_t(8 + k) * ss + sr];
        STWO_M9_SET_PENDING(k, word)
      }
    }
    for (uint32_t c = 0; c < count; ++c) {
      const uint32_t word = LdeInput ? p.intermediate[size_t(start + c) * p.column_stride_words + row]
                                     : buf[c * kPad + pad(t)];
      if (qa >= 0) {
        const size_t base = size_t(p.value_column + start + c) * p.query_count;
        p.values[base + uint32_t(qa)] = word;
        if (qb >= 0) p.values[base + uint32_t(qb)] = word;
      }
      // Eager absorption (mixed_leaf_kernel<true, true>): pending is uniform.
      if (pending == 16u) {
        compressed_bytes += 64u;
        STWO_M9_COMPRESS(compressed_bytes, 0u);
        pending = 0;
      }
      STWO_M9_SET_PENDING(pending, word)
      ++pending;
    }
    // A full block followed by more words is never final: compress it now
    // (the same compression the next word would trigger, same counter).
    if (pending == 16u && g + 1u < groups) {
      compressed_bytes += 64u;
      STWO_M9_COMPRESS(compressed_bytes, 0u);
      pending = 0;
    }
    if constexpr (kCluster > 1) asm volatile("barrier.cluster.arrive.release.aligned;" ::: "memory");
    else __syncthreads();
  }
  if constexpr (kCluster > 1) asm volatile("barrier.cluster.wait.acquire.aligned;" ::: "memory");
  const uint64_t words = uint64_t(p.absorbed_before) + p.columns;

  if (p.prefix != nullptr) {
    if (pending == 16u) {
      compressed_bytes += 64u;
      STWO_M9_COMPRESS(compressed_bytes, 0u);
      pending = 0;
    }
    uint32_t *out = p.prefix;
#define STWO_M9_OUT(k, value) out[size_t(k) * size + row] = value
    STWO_M9_OUT(0, h0); STWO_M9_OUT(1, h1); STWO_M9_OUT(2, h2); STWO_M9_OUT(3, h3);
    STWO_M9_OUT(4, h4); STWO_M9_OUT(5, h5); STWO_M9_OUT(6, h6); STWO_M9_OUT(7, h7);
#define STWO_M9_PENDING_OUT(k) if (pending > k) STWO_M9_OUT(8 + k, p##k)
    STWO_M9_PENDING_OUT(0); STWO_M9_PENDING_OUT(1); STWO_M9_PENDING_OUT(2);
    STWO_M9_PENDING_OUT(3); STWO_M9_PENDING_OUT(4); STWO_M9_PENDING_OUT(5);
    STWO_M9_PENDING_OUT(6); STWO_M9_PENDING_OUT(7); STWO_M9_PENDING_OUT(8);
    STWO_M9_PENDING_OUT(9); STWO_M9_PENDING_OUT(10); STWO_M9_PENDING_OUT(11);
    STWO_M9_PENDING_OUT(12); STWO_M9_PENDING_OUT(13); STWO_M9_PENDING_OUT(14);
#undef STWO_M9_PENDING_OUT
#undef STWO_M9_OUT
    return;
  }
  if (pending < 1) p0 = 0;
  if (pending < 2) p1 = 0;
  if (pending < 3) p2 = 0;
  if (pending < 4) p3 = 0;
  if (pending < 5) p4 = 0;
  if (pending < 6) p5 = 0;
  if (pending < 7) p6 = 0;
  if (pending < 8) p7 = 0;
  if (pending < 9) p8 = 0;
  if (pending < 10) p9 = 0;
  if (pending < 11) p10 = 0;
  if (pending < 12) p11 = 0;
  if (pending < 13) p12 = 0;
  if (pending < 14) p13 = 0;
  if (pending < 15) p14 = 0;
  if (pending < 16) p15 = 0;
  STWO_M9_COMPRESS(stwo::cuda::blake2s::kDomainPrefixBytes + words * 4u, 0xffffffffu);

  using stwo::cuda::blake2s::Hash;
  const uint32_t k = p.subtree_levels;
  if (k == 0) {
    uint4 *dst = reinterpret_cast<uint4 *>(p.nodes + size_t(row) * 8u);
    dst[0] = make_uint4(h0, h1, h2, h3);
    dst[1] = make_uint4(h4, h5, h6, h7);
    return;  // a full leaf layer: every path level comes from the tree
  }
  // On-chip subtree: level l holds kRows >> l nodes, word-major (conflict-free).
  // It reuses the group buffer, which every thread is done with.
  __syncthreads();
  uint32_t *level = levels;
  level[0 * kRows + t] = h0; level[1 * kRows + t] = h1;
  level[2 * kRows + t] = h2; level[3 * kRows + t] = h3;
  level[4 * kRows + t] = h4; level[5 * kRows + t] = h5;
  level[6 * kRows + t] = h6; level[7 * kRows + t] = h7;
  uint32_t nodes = kRows;
  for (uint32_t l = 0; l < k; ++l) {
    __syncthreads();
    uint32_t *next = level + 8u * nodes;
    const uint32_t half = nodes >> 1;
    if (t < half) {
      Hash left, right;
#pragma unroll
      for (uint32_t w = 0; w < 8; ++w) {
        left.words[w] = level[w * nodes + 2u * t];
        right.words[w] = level[w * nodes + 2u * t + 1u];
      }
      const Hash parent = stwo::cuda::blake2s::hash_children_for<true>(left, right);
#pragma unroll
      for (uint32_t w = 0; w < 8; ++w) next[w * half + t] = parent.words[w];
    }
    level = next;
    nodes = half;
  }
  __syncthreads();
  if (k > 0 && t < nodes) {
    uint32_t *dst = p.nodes + (size_t(row0 >> k) + t) * 8u;
#pragma unroll
    for (uint32_t w = 0; w < 8; ++w) dst[w] = level[w * nodes + t];
  }
  // Bottom k siblings of every queried row of this CTA.
  if (p.paths != nullptr) {
    for (uint32_t e = t; e < cta_queries * k * 8u; e += kRows) {
      const uint32_t qi = e / (k * 8u), rem = e % (k * 8u), l = rem / 8u, w = rem % 8u;
      const uint32_t local = qlist[2 * qi], query = qlist[2 * qi + 1];
      uint32_t offset = 0, n = kRows;
      for (uint32_t i = 0; i < l; ++i) { offset += 8u * n; n >>= 1; }
      const uint32_t sibling = (local >> l) ^ 1u;
      p.paths[(size_t(query) * p.path_log + l) * 8u + w] = levels[offset + w * n + sibling];
    }
  }
}

#undef STWO_M9_COMPRESS
#undef STWO_M9_SET_PENDING

// Upper authentication path from a partial tree that starts at level k:
// nodes[level k .. root] laid out like the full tree's layers (k = 0 is the
// production layout). Writes levels k..log-1 of the open_paths layout.
template <uint32_t Unused = 0>
__global__ void stream_commit_upper_paths(const uint32_t *tree, uint32_t tree_log,
                                          uint32_t k, const uint32_t *query_rows,
                                          uint32_t query_count, uint32_t *paths) {
  const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x, qi = blockIdx.y;
  if (qi >= query_count || i >= (tree_log - k) * 8u) return;
  const uint32_t level = k + i / 8u, row = query_rows[qi];
  const uint32_t sibling = (row >> level) ^ 1u;
  const uint64_t base = uint64_t(1) << (tree_log - k);  // nodes at level k
  const uint64_t offset = 2 * base - ((2 * base) >> (level - k));
  paths[(uint64_t(qi) * tree_log + level) * 8u + (i & 7u)] = tree[(offset + sibling) * 8u + (i & 7u)];
}

}  // namespace stwo::cuda::m9

#endif
