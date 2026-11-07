// Device ProofEncoder of a native segment proof (M8 GPU-native, design
// rv64-m8-gpu-native.md §3.4/§3.5, inventory H11/H13; stream native, piece
// n-stage2). Host reference (the bytes it must reproduce exactly):
//
//   WP.encodePhysical(.{ .commitment_scheme_proof =
//       hybrid_pcs.decodeWords(shape, pcs_words).proof })
//
// i.e. pcs_assembly.assemble (trace.zig / fri.zig: query sorting, duplicate
// consistency, Merkle witness selection) followed by the proof_wire binary
// writer (magic "STWOPRW8", config, commitments, sampled values,
// decommitments, queried values, PoW, FRI layers, last layer). Every field of
// the wire stream is a whole u32 word, so the encoder writes a word stream.
//
// One block (kThreads threads), enqueue only, no sync, no readback. Inputs:
//   program  per-class encode program (native_encode.zig Program: geometry,
//            PCS word offsets, the static prefix as const/copy runs)
//   pcs      the enqueue-only PCS Result.words of this proof (job arena)
//   scratch  Program.scratch_words (job arena)
//   region   the proof's request-slab encoded region: [len bytes][bytes...]
// Outputs: region, and two gpu_native.Verdict words:
//   pcs_verdict     Check.pcs_status (0x0207): header / numerical status /
//                   channel state / geometry exactly as decodeWords checks them
//   encode_verdict  Check.encode_bounds (0x0104): capacity, canonical values,
//                   query range, duplicate consistency (assemble's errors)
// On any reject the length word is 0 (publication refuses the request).
#include "rv64/custody.cuh"
#include <stdint.h>

namespace stwo::cuda::rv64::encode {
namespace {
constexpr uint32_t kThreads = 1024;
constexpr uint32_t kPrime = 0x7fffffffu;
constexpr uint32_t kMagic = 0x314e454eu;  // "NEN1"
constexpr uint32_t kMaxQueries = 1024;
constexpr uint32_t kPcsStatus = 0x0207u, kEncodeBounds = 0x0104u;
enum PcsDetail : uint32_t { kHeader = 1, kNumerical = 2, kChannel = 3, kLength = 4, kProgram = 5 };
enum EncodeDetail : uint32_t {
  kOverrun = 1,
  kInconsistentTrace = 2,
  kInconsistentFri = 3,
  kNoncanonical = 4,
  kQueryRange = 5,
};
// Program header words (native_encode.zig Program.Header, same order).
enum Header : uint32_t {
  hMagic = 0, hTrees, hQueries, hLayers, hBeta, hInitialLog, hDegreeLog, hSampleCount,
  hPcsWords, hConfig0, hConfig5 = hConfig0 + 5, hCapacityWords, hTreeTable, hLayerTable,
  hOffRoots, hOffSamples, hOffNonce, hOffTerminal, hOffQueries, hScratchWords,
  hPrefixWords, hConstTable, hConstCount, hRunTable, hRunCount, hInverseTable, hHeaderWords
};
constexpr uint32_t kTreeRecord = 8;   // cols, tree_log, logs_off, inverse_off, pcs_values, pcs_paths, 0, 0
constexpr uint32_t kLayerRecord = 8;  // fold, leaf, shift, height, pcs_root, pcs_values, pcs_paths, 0

struct Shared {
  uint64_t keys[kMaxQueries];       // sort keys (value << 32 | index)
  uint32_t dist_rep[kMaxQueries];   // distinct raw queries (ascending): first index
  uint32_t dist_val[kMaxQueries];
  uint32_t order[kMaxQueries];      // a sorted query order (per tree / per layer)
  uint32_t part[kThreads];
  uint32_t cursor, pcs, enc, total, placeholder;
};

__device__ __forceinline__ void fail(uint32_t *word, uint32_t detail) {
  atomicCAS(word, 0u, detail);
}
__device__ __forceinline__ uint32_t position(uint32_t row, uint32_t from, uint32_t to) {
  return from >= to ? (((row >> (from - to + 1)) << 1) | (row & 1)) : (((row >> 1) << (to - from + 1)) | (row & 1));
}
__device__ __forceinline__ bool same8(const uint32_t *a, const uint32_t *b) {
  bool ok = true;
  for (uint32_t i = 0; i < 8; ++i) ok = ok && a[i] == b[i];
  return ok;
}

// Block-wide exclusive scan of data[0, n) in place; returns the total. All
// threads must call it.
__device__ uint32_t scan(Shared &s, uint32_t *data, uint32_t n) {
  const uint32_t per = (n + blockDim.x - 1) / blockDim.x;
  const uint32_t b = min(n, threadIdx.x * per), e = min(n, b + per);
  uint32_t sum = 0;
  for (uint32_t i = b; i < e; ++i) sum += data[i];
  __syncthreads();
  s.part[threadIdx.x] = sum;
  __syncthreads();
  for (uint32_t off = 1; off < blockDim.x; off <<= 1) {
    const uint32_t v = threadIdx.x >= off ? s.part[threadIdx.x - off] : 0u;
    __syncthreads();
    s.part[threadIdx.x] += v;
    __syncthreads();
  }
  uint32_t run = threadIdx.x ? s.part[threadIdx.x - 1] : 0u;
  for (uint32_t i = b; i < e; ++i) {
    const uint32_t f = data[i];
    data[i] = run;
    run += f;
  }
  const uint32_t total = s.part[blockDim.x - 1];
  __syncthreads();
  return total;
}

// Bitonic sort of s.keys[0, n) ascending (n <= kMaxQueries), padded to 2^k.
__device__ void sort_keys(Shared &s, uint32_t n) {
  uint32_t n2 = 1;
  while (n2 < n) n2 <<= 1;
  for (uint32_t i = n + threadIdx.x; i < n2; i += blockDim.x) s.keys[i] = UINT64_MAX;
  __syncthreads();
  for (uint32_t k = 2; k <= n2; k <<= 1)
    for (uint32_t j = k >> 1; j > 0; j >>= 1) {
      for (uint32_t i = threadIdx.x; i < n2; i += blockDim.x) {
        const uint32_t l = i ^ j;
        if (l > i) {
          const uint64_t a = s.keys[i], b = s.keys[l];
          const bool up = (i & k) == 0;
          if ((a > b) == up) {
            s.keys[i] = b;
            s.keys[l] = a;
          }
        }
      }
      __syncthreads();
    }
}

struct Writer {
  uint32_t *out;
  uint32_t capacity;
  __device__ void put(Shared &s, uint32_t at, uint32_t value) const {
    if (at < capacity) out[at] = value;
    else fail(&s.enc, kOverrun);
  }
};

// One Merkle opening walk (trace tree or FRI layer): level 0 nodes (sorted
// unique) with a representative path-slot each; per level the unpaired
// nodes' sibling hashes go to the witness (ascending), parents form the next
// level. `path(rep, level)` -> 8 words. Writes at s.cursor; returns count.
template <typename Path>
__device__ uint32_t merkle_walk(Shared &s, const Writer &w, uint32_t *node, uint32_t *rep, uint32_t *node2,
                                uint32_t *rep2, uint32_t *flag, uint32_t n, uint32_t height, Path path) {
  uint32_t total = 0;
  for (uint32_t level = 0; level < height; ++level) {
    // first: not the second element of an adjacent pair; unpaired: first
    // without its sibling after it.
    for (uint32_t i = threadIdx.x; i < n; i += blockDim.x) {
      const uint32_t x = node[i];
      const bool second = i > 0 && (x & 1u) && node[i - 1] == (x ^ 1u);
      const bool paired = !second && i + 1 < n && node[i + 1] == (x ^ 1u);
      flag[i] = (!second && !paired) ? 1u : 0u;
      flag[n + i] = second ? 0u : 1u;
    }
    __syncthreads();
    const uint32_t unpaired = scan(s, flag, n);
    const uint32_t firsts = scan(s, flag + n, n);
    const uint32_t base = s.cursor;
    for (uint32_t i = threadIdx.x; i < n; i += blockDim.x) {
      const uint32_t x = node[i];
      const bool second = i > 0 && (x & 1u) && node[i - 1] == (x ^ 1u);
      const bool paired = !second && i + 1 < n && node[i + 1] == (x ^ 1u);
      if (!second && !paired) {
        const uint32_t *h = path(rep[i], level);
        const uint32_t at = base + 8 * flag[i];
        for (uint32_t c = 0; c < 8; ++c) w.put(s, at + c, h[c]);
      }
      if (!second) {
        node2[flag[n + i]] = x >> 1;
        rep2[flag[n + i]] = rep[i];
      }
    }
    __syncthreads();
    if (threadIdx.x == 0) s.cursor = base + 8 * unpaired;
    for (uint32_t i = threadIdx.x; i < firsts; i += blockDim.x) {
      node[i] = node2[i];
      rep[i] = rep2[i];
    }
    __syncthreads();
    n = firsts;
    total += unpaired;
  }
  return total;
}

__global__ void __launch_bounds__(kThreads) encode_kernel(const uint32_t *P, const uint32_t *W, uint32_t *scratch,
                                                         uint32_t *region, uint64_t region_words,
                                                         uint32_t *pcs_verdict, uint32_t *encode_verdict) {
  __shared__ Shared s;
  const uint32_t T = P[hTrees], Q = P[hQueries], L = P[hLayers], beta = P[hBeta], lifting = P[hInitialLog];
  if (threadIdx.x == 0) {
    s.pcs = 0;
    s.enc = 0;
    s.cursor = 0;
    // decodeWords: header, numerical status, channel state, sample count.
    const uint32_t *h = W;
    if (h[0] != 0x52564d4fu || h[1] != 2 || h[7] != T || h[9] != L || h[10] != lifting || h[11] != Q ||
        h[12] != P[hDegreeLog] || h[8] != P[hSampleCount])
      fail(&s.pcs, kHeader);
    else if (W[14] != 0)
      fail(&s.pcs, kNumerical);
    else {
      const uint32_t *st = W + 15;
      if (st[9] != h[13] || st[10] != 0 || st[11] != 0 || st[12] != 17 + h[13] || st[13] | st[14] | st[15])
        fail(&s.pcs, kChannel);
    }
  }
  __syncthreads();
  const uint64_t room = region_words - 1;
  const Writer w{region + 1, uint32_t(room < P[hCapacityWords] ? room : P[hCapacityWords])};
  if (s.pcs == 0) {
    const uint32_t *queries = W + P[hOffQueries];
    // ---- canonical values and query range (whole sections, as decoded)
    for (uint32_t i = threadIdx.x; i < Q; i += blockDim.x)
      if (queries[i] >= (1u << lifting)) fail(&s.enc, kQueryRange);
    for (uint32_t i = threadIdx.x; i < 8 * P[hSampleCount]; i += blockDim.x)
      if (W[P[hOffSamples] + i] >= kPrime) fail(&s.enc, kNoncanonical);
    if (threadIdx.x < 8 && W[P[hOffTerminal] + threadIdx.x] >= kPrime) fail(&s.enc, kNoncanonical);
    for (uint32_t t = 0; t < T; ++t) {
      const uint32_t *r = P + P[hTreeTable] + kTreeRecord * t;
      for (uint32_t i = threadIdx.x; i < r[0] * Q; i += blockDim.x)
        if (W[r[4] + i] >= kPrime) fail(&s.enc, kNoncanonical);
    }
    for (uint32_t l = 0; l < L; ++l) {
      const uint32_t *r = P + P[hLayerTable] + kLayerRecord * l;
      for (uint32_t i = threadIdx.x; i < ((Q << r[0]) * 8); i += blockDim.x)
        if (W[r[5] + i] >= kPrime) fail(&s.enc, kNoncanonical);
    }
    __syncthreads();
  }
  if (s.pcs == 0 && s.enc == 0) {
    const uint32_t *queries = W + P[hOffQueries];
    uint32_t *node = scratch, *rep = scratch + 4 * kMaxQueries, *node2 = scratch + 8 * kMaxQueries,
             *rep2 = scratch + 12 * kMaxQueries, *flag = scratch + 16 * kMaxQueries;
    // ---- static prefix: consts and copy runs (magic, config, commitments,
    //      sampled values, decommitment tree count)
    for (uint32_t i = threadIdx.x; i < P[hConstCount]; i += blockDim.x) {
      const uint32_t *c = P + P[hConstTable] + 2 * i;
      w.put(s, c[0], c[1]);
    }
    for (uint32_t r = 0; r < P[hRunCount]; ++r) {
      const uint32_t *run = P + P[hRunTable] + 3 * r;
      for (uint32_t i = threadIdx.x; i < run[2]; i += blockDim.x) w.put(s, run[0] + i, W[run[1] + i]);
    }
    if (threadIdx.x == 0) s.cursor = P[hPrefixWords];
    // ---- distinct raw queries ascending, first index each (trace
    //      representatives; FRI positions)
    for (uint32_t i = threadIdx.x; i < Q; i += blockDim.x) s.keys[i] = (uint64_t(queries[i]) << 32) | i;
    __syncthreads();
    sort_keys(s, Q);
    for (uint32_t i = threadIdx.x; i < Q; i += blockDim.x) flag[i] = (i == 0 || (s.keys[i] >> 32) != (s.keys[i - 1] >> 32)) ? 1u : 0u;
    __syncthreads();
    for (uint32_t i = threadIdx.x; i < Q; i += blockDim.x) s.order[i] = uint32_t(s.keys[i]);  // raw sorted order (dups kept)
    __syncthreads();
    const uint32_t R = scan(s, flag, Q);
    for (uint32_t i = threadIdx.x; i < Q; i += blockDim.x)
      if (i == 0 || (s.keys[i] >> 32) != (s.keys[i - 1] >> 32)) {
        s.dist_rep[flag[i]] = uint32_t(s.keys[i]);
        s.dist_val[flag[i]] = uint32_t(s.keys[i] >> 32);
      }
    __syncthreads();
    // ---- decommitments, per tree (trace.zig assemble)
    for (uint32_t t = 0; t < T; ++t) {
      const uint32_t *tr = P + P[hTreeTable] + kTreeRecord * t;
      const uint32_t cols = tr[0], tl = tr[1];
      const uint32_t *logs = P + tr[2];
      const uint32_t *values = W + tr[4], *paths = W + tr[5];
      // value consistency: sort by r = (p >> 1) | (p & 1) << (tl - 1); every
      // column's position classes are contiguous runs of r >> (s - 1).
      for (uint32_t i = threadIdx.x; i < Q; i += blockDim.x) {
        const uint32_t p = position(queries[i], lifting, tl);
        const uint32_t r = (p >> 1) | ((p & 1u) << (tl - 1));
        s.keys[i] = (uint64_t(r) << 32) | i;
      }
      __syncthreads();
      sort_keys(s, Q);
      for (uint32_t k = threadIdx.x; k < cols * Q; k += blockDim.x) {
        const uint32_t ci = k / Q, i = k % Q;
        if (i == 0) continue;
        const uint32_t sh = tl - logs[ci];  // (s - 1)
        const uint32_t a = uint32_t(s.keys[i]), b = uint32_t(s.keys[i - 1]);
        if (((s.keys[i] >> 32) >> sh) == ((s.keys[i - 1] >> 32) >> sh) && values[ci * Q + a] != values[ci * Q + b])
          fail(&s.enc, kInconsistentTrace);
      }
      __syncthreads();
      // path consistency + level-0 nodes: sort by tree position p.
      for (uint32_t i = threadIdx.x; i < Q; i += blockDim.x)
        s.keys[i] = (uint64_t(position(queries[i], lifting, tl)) << 32) | i;
      __syncthreads();
      sort_keys(s, Q);
      for (uint32_t k = threadIdx.x; k < tl * Q; k += blockDim.x) {
        const uint32_t level = k / Q, i = k % Q;
        if (i == 0) continue;
        const uint32_t a = uint32_t(s.keys[i]), b = uint32_t(s.keys[i - 1]);
        if (((s.keys[i] >> 32) >> level) == ((s.keys[i - 1] >> 32) >> level) &&
            !same8(paths + (uint64_t(a) * tl + level) * 8, paths + (uint64_t(b) * tl + level) * 8))
          fail(&s.enc, kInconsistentTrace);
      }
      for (uint32_t i = threadIdx.x; i < Q; i += blockDim.x) flag[i] = (i == 0 || (s.keys[i] >> 32) != (s.keys[i - 1] >> 32)) ? 1u : 0u;
      __syncthreads();
      const uint32_t n0 = scan(s, flag, Q);
      for (uint32_t i = threadIdx.x; i < Q; i += blockDim.x)
        if (i == 0 || (s.keys[i] >> 32) != (s.keys[i - 1] >> 32)) {
          node[flag[i]] = uint32_t(s.keys[i] >> 32);
          rep[flag[i]] = uint32_t(s.keys[i]);
        }
      if (threadIdx.x == 0) {
        s.placeholder = s.cursor;
        s.cursor += 1;
      }
      __syncthreads();
      const uint32_t count = merkle_walk(s, w, node, rep, node2, rep2, flag, n0, tl,
                                         [&](uint32_t q, uint32_t level) { return paths + (uint64_t(q) * tl + level) * 8; });
      if (threadIdx.x == 0) w.put(s, s.placeholder, count);
      __syncthreads();
    }
    // ---- queried values: [T] per tree [cols] per original column [R][R values]
    if (threadIdx.x == 0) {
      s.placeholder = s.cursor;
      w.put(s, s.cursor, T);
      s.cursor += 1;
    }
    __syncthreads();
    for (uint32_t t = 0; t < T; ++t) {
      const uint32_t *tr = P + P[hTreeTable] + kTreeRecord * t;
      const uint32_t cols = tr[0];
      const uint32_t *inverse = P + tr[3];
      const uint32_t *values = W + tr[4];
      const uint32_t base = s.cursor;
      if (threadIdx.x == 0) w.put(s, base, cols);
      for (uint32_t k = threadIdx.x; k < cols * (R + 1); k += blockDim.x) {
        const uint32_t o = k / (R + 1), j = k % (R + 1);
        const uint32_t at = base + 1 + o * (R + 1) + j;
        w.put(s, at, j == 0 ? R : values[inverse[o] * Q + s.dist_rep[j - 1]]);
      }
      __syncthreads();
      if (threadIdx.x == 0) s.cursor = base + 1 + cols * (R + 1);
      __syncthreads();
    }
    // ---- proof of work (u64 LE = nonce[0], nonce[1])
    if (threadIdx.x == 0) {
      w.put(s, s.cursor, W[P[hOffNonce]]);
      w.put(s, s.cursor + 1, W[P[hOffNonce] + 1]);
      s.cursor += 2;
    }
    __syncthreads();
    // ---- FRI layers (fri.zig layerProof), in raw-sorted order s.order
    for (uint32_t l = 0; l < L; ++l) {
      const uint32_t *lr = P + P[hLayerTable] + kLayerRecord * l;
      const uint32_t fold = lr[0], leaf = lr[1], shift = lr[2], height = lr[3];
      const uint32_t subset = 1u << fold, slots = 1u << (fold - leaf);
      const uint32_t *values = W + lr[5], *paths = W + lr[6];
      // groups of the raw-sorted queries (starts are non-decreasing)
      auto start_of = [&](uint32_t q) { return ((queries[q] >> shift) >> fold) << fold; };
      // same-group duplicates: whole value and path blocks must agree
      for (uint32_t k = threadIdx.x; k < Q; k += blockDim.x) {
        if (k == 0) continue;
        const uint32_t a = s.order[k], b = s.order[k - 1];
        if (start_of(a) != start_of(b)) continue;
        for (uint32_t v = 0; v < subset * 8; ++v)
          if (values[uint64_t(a) * subset * 8 + v] != values[uint64_t(b) * subset * 8 + v]) fail(&s.enc, kInconsistentFri);
        for (uint32_t v = 0; v < slots * height * 8; ++v)
          if (paths[uint64_t(a) * slots * height * 8 + v] != paths[uint64_t(b) * slots * height * 8 + v]) fail(&s.enc, kInconsistentFri);
      }
      for (uint32_t k = threadIdx.x; k < Q; k += blockDim.x) flag[k] = (k == 0 || start_of(s.order[k]) != start_of(s.order[k - 1])) ? 1u : 0u;
      __syncthreads();
      const uint32_t G = scan(s, flag, Q);
      // group g -> representative query (node2 = start, rep2 = query)
      for (uint32_t k = threadIdx.x; k < Q; k += blockDim.x)
        if (k == 0 || start_of(s.order[k]) != start_of(s.order[k - 1])) {
          node2[flag[k]] = start_of(s.order[k]);
          rep2[flag[k]] = s.order[k];
        }
      __syncthreads();
      // layer positions (sorted unique raw >> shift) -> s.keys as u64 for
      // binary search; s.order stays intact.
      uint32_t *lpos = flag + 4 * kMaxQueries;  // Q words
      for (uint32_t k = threadIdx.x; k < Q; k += blockDim.x) flag[k] = (k == 0 || (queries[s.order[k]] >> shift) != (queries[s.order[k - 1]] >> shift)) ? 1u : 0u;
      __syncthreads();
      const uint32_t NP = scan(s, flag, Q);
      for (uint32_t k = threadIdx.x; k < Q; k += blockDim.x)
        if (k == 0 || (queries[s.order[k]] >> shift) != (queries[s.order[k - 1]] >> shift)) lpos[flag[k]] = queries[s.order[k]] >> shift;
      __syncthreads();
      // FRI witness values: positions of each group not queried, ascending.
      uint32_t *wflag = flag + 5 * kMaxQueries;  // G * subset <= 16 * Q words
      for (uint32_t k = threadIdx.x; k < G * subset; k += blockDim.x) {
        const uint32_t pos = node2[k / subset] + (k % subset);
        uint32_t lo = 0, hi = NP;
        while (lo < hi) {
          const uint32_t mid = (lo + hi) >> 1;
          if (lpos[mid] < pos) lo = mid + 1; else hi = mid;
        }
        wflag[k] = (lo < NP && lpos[lo] == pos) ? 0u : 1u;
      }
      __syncthreads();
      const uint32_t nw = scan(s, wflag, G * subset);
      const uint32_t vbase = s.cursor;
      if (threadIdx.x == 0) w.put(s, vbase, nw);
      for (uint32_t k = threadIdx.x; k < G * subset; k += blockDim.x) {
        const uint32_t pos = node2[k / subset] + (k % subset);
        uint32_t lo = 0, hi = NP;
        while (lo < hi) {
          const uint32_t mid = (lo + hi) >> 1;
          if (lpos[mid] < pos) lo = mid + 1; else hi = mid;
        }
        if (!(lo < NP && lpos[lo] == pos)) {
          const uint32_t *v = values + (uint64_t(rep2[k / subset]) * subset + (k % subset)) * 8;
          for (uint32_t c = 0; c < 8; ++c) w.put(s, vbase + 1 + 8 * wflag[k] + c, v[c]);
        }
      }
      __syncthreads();
      // leaves: (start >> leaf) + slot per group, rep = query * slots + slot.
      // Cross-group path consistency: the (group, slot) sequence is
      // monotone in its node at every level, so adjacent entries suffice.
      for (uint32_t k = threadIdx.x; k < G * slots; k += blockDim.x) {
        node[k] = (node2[k / slots] >> leaf) + (k % slots);
        rep[k] = rep2[k / slots] * slots + (k % slots);
      }
      __syncthreads();
      for (uint32_t k = threadIdx.x; k < height * G * slots; k += blockDim.x) {
        const uint32_t level = k / (G * slots), e = k % (G * slots);
        if (e == 0) continue;
        if ((node[e] >> level) == (node[e - 1] >> level) &&
            !same8(paths + (uint64_t(rep[e]) * height + level) * 8, paths + (uint64_t(rep[e - 1]) * height + level) * 8))
          fail(&s.enc, kInconsistentFri);
      }
      if (threadIdx.x == 0) {
        s.cursor = vbase + 1 + 8 * nw;
        s.placeholder = s.cursor;
        s.cursor += 1;
      }
      __syncthreads();
      const uint32_t nh = merkle_walk(s, w, node, rep, node2, rep2, wflag, G * slots, height,
                                      [&](uint32_t r, uint32_t level) { return paths + (uint64_t(r) * height + level) * 8; });
      if (threadIdx.x == 0) {
        w.put(s, s.placeholder, nh);
        for (uint32_t c = 0; c < 8; ++c) w.put(s, s.cursor + c, W[lr[4] + c]);
        s.cursor += 8;
        if (l == 0) {
          w.put(s, s.cursor, L - 1);
          s.cursor += 1;
        }
      }
      __syncthreads();
    }
    // ---- last layer polynomial: one coefficient
    if (threadIdx.x == 0) {
      w.put(s, s.cursor, 1);
      for (uint32_t c = 0; c < 8; ++c) w.put(s, s.cursor + 1 + c, W[P[hOffTerminal] + c]);
      s.cursor += 9;
    }
    __syncthreads();
    (void)beta;
  }
  if (threadIdx.x == 0) {
    const bool ok = s.pcs == 0 && s.enc == 0;
    region[0] = ok ? s.cursor * 4u : 0u;
    *pcs_verdict = s.pcs ? ((kPcsStatus << 16) | s.pcs) : 0u;
    *encode_verdict = s.pcs ? ((kEncodeBounds << 16) | 0xffu) : (s.enc ? ((kEncodeBounds << 16) | s.enc) : 0u);
  }
}
}  // namespace
}  // namespace stwo::cuda::rv64::encode

// region: [1 length word][capacity words]; verdicts: 1 word each (request
// slab status words). program/pcs/scratch: job arena or class-cache memory of
// `context`. Shape limits are validated on the host (native_encode.zig) and
// re-checked here before launch.
extern "C" int stwo_rv64_native_encode_proof_v1_on(void *context, uint32_t lane, const uint32_t *program,
                                                  uint64_t program_words, const uint32_t *pcs, uint64_t pcs_words,
                                                  uint32_t *scratch, uint64_t scratch_words, uint32_t *region,
                                                  uint64_t region_words, uint32_t *pcs_verdict,
                                                  uint32_t *encode_verdict, const uint32_t *program_host) {
  using namespace stwo::cuda::rv64;
  namespace e = stwo::cuda::rv64::encode;
  // program_host: the same program in host memory (validated here, never
  // read by the kernel): the launch refuses a program it cannot run.
  if (!program_host || program_words < e::hHeaderWords || program_host[e::hMagic] != e::kMagic ||
      program_host[e::hPcsWords] != pcs_words || program_host[e::hScratchWords] > scratch_words ||
      program_host[e::hQueries] == 0 || program_host[e::hQueries] > e::kMaxQueries || region_words < 2)
    return int(cudaErrorInvalidValue);
  RangeCustody<6> custody(context, lane);
  if (!custody.range(program, program_words, false) || !custody.range(pcs, pcs_words, false) ||
      !custody.range(scratch, scratch_words, true) || !custody.range(region, region_words, true) ||
      !custody.range(pcs_verdict, 1, true) || !custody.range(encode_verdict, 1, true))
    return custody.status;
  e::encode_kernel<<<1, e::kThreads, 0, custody.stream>>>(program, pcs, scratch, region, region_words, pcs_verdict,
                                                          encode_verdict);
  return int(cudaPeekAtLastError());
}

extern "C" uint32_t stwo_rv64_native_encode_version(void) {
  return 1;
}
