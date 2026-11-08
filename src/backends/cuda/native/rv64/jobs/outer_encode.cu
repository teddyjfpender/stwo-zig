// Device proof encoding of an enqueue-only PCS readback image (M8 GPU-native,
// design rv64-m8-gpu-native.md §3.3-§3.5; host side and the host mirror of
// this kernel: integrations/riscv_cuda/rv64/jobs/outer_encode.zig).
//
// Input: the PCS Result.words image (hybrid_pcs.decodeWords layout), a
// per-class descriptor (outer_encode.zig buildDescriptor: shape constants,
// FRI plan, column tables, wire constants), the node's expected roots, claims,
// section status latches and expected outputs. Output: the exact bytes of
//   [om31 wire.encode envelope] + stwo_proof_wire encodeProofBytesBinary(
//       pcs_assembly.assemble(decodeWords(image)))
// into region[1..] with region[0] = byte length, plus two Verdict words:
// node_pcs_status (0x0304) and encode_bounds (0x0104). No arithmetic, no
// hashing: a re-layout with the host assembler's query dedup, lifted-Merkle /
// FRI decommitment witness walks and its refusals (canonical values,
// duplicate-query consistency, header / latch / root checks).
//
// One block of kThreads threads, one launch, enqueue only:
//   validate (thread 0)      descriptor, image header, latches, roots
//   validate (all)           canonical values, query range
//   sort (all)               rank sort of the raw queries (value, index)
//   per trace tree / FRI layer
//     plan (thread 0)        sorted-merge witness walk -> copy ops + level lists
//     check (all)            bsearch consistency of every duplicated query
//   layout (thread 0)        section offsets, capacity, small words, op dsts
//   copy (all)               copy ops, queried values, outputs, claims
// Several threads may refuse at once: the lowest rank in the host mirror's
// check order wins (atomicMin), so device and host name the same detail.
#include "rv64/custody.cuh"
#include <stdint.h>

struct StwoRv64OuterEncodeIo {
  const uint32_t *desc;
  uint64_t desc_words;       // == desc[2]
  const uint32_t *image;
  uint64_t image_words;
  const uint32_t *roots[4];  // expected root per tree (8 words) or null
  const uint32_t *claims;    // claims_words (= 8 x desc claims; envelope only)
  const uint32_t *latches;   // latches_words words that must be 0 (envelope only)
  const uint32_t *outputs;   // outputs_words (= 4 x desc outputs; envelope only)
  uint32_t claims_words, latches_words, outputs_words, reserved;
  uint32_t *region;          // [0] byte length, [1..] payload
  uint64_t region_words;     // including the length word
  uint32_t *pcs_status;
  uint32_t *encode_status;
  uint32_t *scratch;
  uint64_t scratch_words;
};
static_assert(sizeof(StwoRv64OuterEncodeIo) == 152, "outer encode Io ABI");

namespace stwo::cuda::rv64 {
namespace {
constexpr uint32_t kThreads = 512;
constexpr uint32_t kMaxQ = 1024, kMaxTrees = 4, kMaxLayers = 28;
constexpr uint32_t kModulus = 0x7fffffffu;
constexpr uint32_t kPcsStatus = 0x0304u, kEncodeBounds = 0x0104u;
// Descriptor words (outer_encode.zig D).
enum : uint32_t {
  dMagic = 0, dVersion = 1, dWords = 2, dFlags = 3, dTrees = 4, dQueries = 5, dDegreeLog = 6,
  dLayers = 7, dInitialLog = 8, dBlowup = 9, dSamples = 10, dOutputs = 11, dClaims = 12,
  dLatches = 13, dImageWords = 14, dMaxPayload = 15, dScratch = 16, dMaxOps = 17,
  dConfig = 24, dPhysMagic = 30, dEnvelope = 32, dFixedRoot = 50, dFri = 64,
  dTreeTable = 64 + 4 * 28, dTables = 64 + 4 * 28 + 4 * 4,
};
constexpr uint32_t kFlagFixedRoot = 2u;  // outer_encode.zig D.flag_fixed_root
constexpr uint32_t kDescMagic = 0x434e454fu, kDescVersion = 1, kImageMagic = 0x52564d4fu;
// Detail codes and their rank in the host check order (outer_encode.zig detail_order).
enum : uint32_t {
  kDescriptor = 1, kImageLength = 2, kHeader = 3, kNumerical = 4, kChannel = 5, kRoot = 6,
  kQueryRange = 7, kNoncanonical = 8, kTraceInconsistent = 9, kFriInconsistent = 10,
  kSectionLatch = 11, kNoncanonicalPublic = 12,
};
__device__ __constant__ uint32_t kRankOf[13] = {0xff, 0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 6, 7};
__device__ __constant__ uint32_t kDetailOfRank[12] = {1, 2, 3, 4, 5, 6, 11, 12, 7, 8, 9, 10};

struct Layer {
  uint32_t count, fold_step, leaf_log, shift;
};
struct Tree {
  uint32_t columns, tree_log, table, samples;
};
struct Op {
  uint32_t dst, src, n;
};
struct Levels {
  uint32_t nodes[kMaxLayers], reps[kMaxLayers], len[kMaxLayers];
};

struct Shared {
  uint32_t fail;  // lowest failing rank + 1 (0 = none)
  uint32_t q, trees, layers, initial_log, envelope;
  uint64_t roots_at, samples_at, nonce_at, terminal_at, queries_at;
  uint64_t layer_root[kMaxLayers], layer_values[kMaxLayers], layer_paths[kMaxLayers];
  uint64_t tree_values[kMaxTrees], tree_paths[kMaxTrees];
  uint32_t sorted[kMaxQ];  // raw query indices in (value, index) order
  uint32_t reps[kMaxQ];    // first index of every distinct raw value
  uint32_t n_reps;
  uint32_t p[kMaxQ];       // tree positions of the current tree
  uint32_t order[kMaxQ];   // indices in (p, index) order
  uint32_t fpos[kMaxQ], frep[kMaxQ], fn;  // FRI layer positions + representative raw index
  // scratch bump allocator (words) and op list
  uint64_t bump;
  uint32_t n_ops;
  uint32_t ops_at;  // scratch offset of the op list
  uint32_t trace_ops_first[kMaxTrees], trace_ops_n[kMaxTrees];
  uint32_t fri_values_first[kMaxLayers], fri_values_n[kMaxLayers];
  uint32_t fri_hash_first[kMaxLayers], fri_hash_n[kMaxLayers];
  uint32_t sample_ops_first, sample_ops_n;
  Levels lv;          // level lists of the current tree / layer
  uint32_t canon_at;  // scratch offset of canon[log][q] of the current tree
  uint32_t group_at;  // scratch offset of group_rep[q] of the current layer
  uint64_t words;     // payload words
  uint64_t qv_at[kMaxTrees];  // payload offset of each tree's queried-values block
  uint64_t out_at, claims_at;
};

__device__ __forceinline__ void refuse(Shared &s, uint32_t detail) {
  atomicMin(&s.fail, kRankOf[detail] + 1);
}
__device__ __forceinline__ Layer layer_of(const uint32_t *d, uint32_t l) {
  const uint32_t *b = d + dFri + 4 * l;
  return {b[0], b[1], b[2], b[3]};
}
__device__ __forceinline__ Tree tree_of(const uint32_t *d, uint32_t t) {
  const uint32_t *b = d + dTreeTable + 4 * t;
  return {b[0], b[1], b[2], b[3]};
}
__device__ __forceinline__ uint32_t log2u(uint32_t x) {
  return 31u - __clz(x);
}
__device__ __forceinline__ uint32_t height(Layer l) {
  return log2u(l.count) - l.leaf_log;
}
// trace.zig position
__device__ __forceinline__ uint32_t position(uint32_t row, uint32_t from, uint32_t to) {
  return from >= to ? (((row >> (from - to + 1)) << 1) | (row & 1u))
                    : (((row >> 1) << (to - from + 1)) | (row & 1u));
}
__device__ __forceinline__ bool eq8(const uint32_t *a, const uint32_t *b) {
  bool ok = true;
  for (uint32_t k = 0; k < 8; ++k) ok = ok && a[k] == b[k];
  return ok;
}
__device__ uint32_t find(const uint32_t *nodes, uint32_t n, uint32_t node) {
  uint32_t lo = 0, hi = n;
  while (lo < hi) {
    const uint32_t mid = (lo + hi) >> 1;
    if (nodes[mid] < node) lo = mid + 1;
    else hi = mid;
  }
  return (lo < n && nodes[lo] == node) ? lo : 0xffffffffu;
}
__device__ __forceinline__ uint32_t take(Shared &s, uint64_t words) {
  const uint64_t at = s.bump;
  s.bump += words;
  return uint32_t(at);
}

// Image offsets (outer_encode.zig Image.of). Thread 0.
__device__ void image_layout(Shared &s, const uint32_t *d) {
  const uint64_t q = s.q;
  s.roots_at = 31;
  s.samples_at = s.roots_at + uint64_t(s.trees) * 8;
  s.nonce_at = s.samples_at + uint64_t(d[dSamples]) * 8;
  s.terminal_at = s.nonce_at + 2;
  s.queries_at = s.terminal_at + 8;
  uint64_t at = s.queries_at + q;
  for (uint32_t l = 0; l < s.layers; ++l) {
    const Layer f = layer_of(d, l);
    s.layer_root[l] = at;
    s.layer_values[l] = at + 8;
    s.layer_paths[l] = at + 8 + ((q << f.fold_step) * 8);
    at = s.layer_paths[l] + (q << (f.fold_step - f.leaf_log)) * height(f) * 8;
  }
  for (uint32_t t = 0; t < s.trees; ++t) {
    const Tree tr = tree_of(d, t);
    s.tree_values[t] = at;
    s.tree_paths[t] = at + uint64_t(tr.columns) * q;
    at = s.tree_paths[t] + q * tr.tree_log * 8;
  }
  s.out_at = at;  // total image words (reused below)
}

// Thread 0: descriptor sanity (mirror validate head). Returns false on refusal.
__device__ bool validate_head(Shared &s, const StwoRv64OuterEncodeIo &io) {
  const uint32_t *d = io.desc;
  if (d[dMagic] != kDescMagic || d[dVersion] != kDescVersion || d[dWords] < dTables || d[dWords] != io.desc_words ||
      !d[dTrees] || d[dTrees] > kMaxTrees || !d[dQueries] || d[dQueries] > kMaxQ ||
      !d[dLayers] || d[dLayers] > kMaxLayers) {
    refuse(s, kDescriptor);
    return false;
  }
  s.q = d[dQueries];
  s.trees = d[dTrees];
  s.layers = d[dLayers];
  s.initial_log = d[dInitialLog];
  s.envelope = d[dFlags] & 1u;
  for (uint32_t l = 0; l < s.layers; ++l) {
    const Layer f = layer_of(d, l);
    if (!f.fold_step || f.fold_step > 4 || f.leaf_log > f.fold_step || f.count < (1u << f.fold_step) ||
        (f.count & (f.count - 1)) || f.count > (1u << 28)) {
      refuse(s, kDescriptor);
      return false;
    }
  }
  for (uint32_t t = 0; t < s.trees; ++t) {
    const Tree tr = tree_of(d, t);
    if (!tr.columns || tr.columns > 65536 || tr.tree_log < 1 || tr.tree_log > 28 ||
        uint64_t(tr.table) + 4ull * tr.columns > d[dWords]) {
      refuse(s, kDescriptor);
      return false;
    }
  }
  if (s.initial_log < 1 || s.initial_log > 28 ||
      io.claims_words != (s.envelope ? 8 * d[dClaims] : 0) || io.outputs_words != (s.envelope ? 4 * d[dOutputs] : 0) ||
      io.latches_words != (s.envelope ? d[dLatches] : 0) ||
      (s.envelope && (d[dOutputs] > 65536 || !d[dClaims] || d[dClaims] > 64 || d[dLatches] > 16 ||
                      !io.claims || (d[dOutputs] && !io.outputs) || (d[dLatches] && !io.latches)))) {
    refuse(s, kDescriptor);
    return false;
  }
  if (uint64_t(d[dScratch]) > io.scratch_words) {
    refuse(s, kDescriptor);
    return false;
  }
  image_layout(s, d);
  if (io.image_words != s.out_at || s.out_at != d[dImageWords]) {
    refuse(s, kImageLength);
    return false;
  }
  const uint32_t *h = io.image;
  if (h[0] != kImageMagic || h[1] != 2 || h[7] != s.trees || h[8] != d[dSamples] || h[9] != s.layers ||
      h[10] != s.initial_log || h[11] != s.q || h[12] != d[dDegreeLog]) {
    refuse(s, kHeader);
    return false;
  }
  if (h[14]) {
    refuse(s, kNumerical);
    return false;
  }
  const uint32_t *st = h + 15;
  bool ok = st[9] == h[13] && !st[10] && !st[11] && st[12] == 17u + h[13];
  for (uint32_t k = 13; k < 16; ++k) ok = ok && !st[k];
  if (!ok) {
    refuse(s, kChannel);
    return false;
  }
  for (uint32_t t = 0; t < s.trees; ++t)
    if (io.roots[t] && !eq8(io.roots[t], h + s.roots_at + 8 * t)) {
      refuse(s, kRoot);
      return false;
    }
  // flag_fixed_root: the expected tree-0 root (the root the node mixed into
  // its transcript) must also equal the class's FIXED root (host
  // InvalidOm31DeviceFixedRoot).
  if ((d[dFlags] & kFlagFixedRoot) && io.roots[0] && !eq8(io.roots[0], d + dFixedRoot)) {
    refuse(s, kRoot);
    return false;
  }
  if (s.envelope)
    for (uint32_t i = 0; i < d[dLatches]; ++i)
      if (io.latches[i]) {
        refuse(s, kSectionLatch);
        return false;
      }
  return true;
}

// All threads: canonical public words, query range, canonical image values.
__device__ void validate_values(Shared &s, const StwoRv64OuterEncodeIo &io) {
  const uint32_t *d = io.desc;
  const uint32_t tid = threadIdx.x;
  if (s.envelope) {
    for (uint32_t i = tid; i < 8 * d[dClaims]; i += kThreads)
      if (io.claims[i] >= kModulus) refuse(s, kNoncanonicalPublic);
    for (uint32_t i = tid; i < 4 * d[dOutputs]; i += kThreads)
      if (io.outputs[i] >= kModulus) refuse(s, kNoncanonicalPublic);
  }
  const uint32_t *raw = io.image + s.queries_at;
  for (uint32_t i = tid; i < s.q; i += kThreads)
    if (uint64_t(raw[i]) >= (1ull << s.initial_log)) refuse(s, kQueryRange);
  auto range = [&](uint64_t at, uint64_t n) {
    for (uint64_t i = tid; i < n; i += kThreads)
      if (io.image[at + i] >= kModulus) refuse(s, kNoncanonical);
  };
  range(s.samples_at, uint64_t(d[dSamples]) * 8);
  range(s.terminal_at, 8);
  for (uint32_t l = 0; l < s.layers; ++l) range(s.layer_values[l], (uint64_t(s.q) << layer_of(d, l).fold_step) * 8);
  for (uint32_t t = 0; t < s.trees; ++t) range(s.tree_values[t], uint64_t(tree_of(d, t).columns) * s.q);
}

__device__ __forceinline__ void push_op(Shared &s, uint32_t *scratch, uint32_t src, uint32_t n) {
  uint32_t *o = scratch + s.ops_at + 3 * s.n_ops;
  o[0] = 0;
  o[1] = src;
  o[2] = n;
  s.n_ops += 1;
}

// Thread 0: the lifted-Merkle witness walk (mirror Mirror.walk). Level 0 is
// already in scratch at s.lv.nodes[0]/reps[0] with s.lv.len[0] entries.
// hash(rep, level) = paths + (rep * stride + level) * 8.
__device__ void walk(Shared &s, uint32_t *scratch, uint32_t levels, uint64_t paths, uint32_t stride) {
  for (uint32_t lv = 0; lv < levels; ++lv) {
    const uint32_t *nodes = scratch + s.lv.nodes[lv];
    const uint32_t *reps = scratch + s.lv.reps[lv];
    const uint32_t n = s.lv.len[lv];
    uint32_t *next_nodes = nullptr, *next_reps = nullptr;
    if (lv + 1 < levels) {
      s.lv.nodes[lv + 1] = take(s, n);
      s.lv.reps[lv + 1] = take(s, n);
      next_nodes = scratch + s.lv.nodes[lv + 1];
      next_reps = scratch + s.lv.reps[lv + 1];
    }
    uint32_t m = 0;
    for (uint32_t i = 0; i < n;) {
      const uint32_t first = nodes[i];
      const bool paired = i + 1 < n && nodes[i + 1] == (first ^ 1u);
      if (!paired) push_op(s, scratch, uint32_t(paths + (uint64_t(reps[i]) * stride + lv) * 8), 8);
      if (next_nodes) {
        next_nodes[m] = first >> 1;
        next_reps[m] = reps[i];
      }
      ++m;
      i += paired ? 2 : 1;
    }
    if (lv + 1 < levels) s.lv.len[lv + 1] = m;
  }
}

// Thread 0: canonical query per column position for a column of height
// `log` in a tree of `tl` (mirror canonicalFor).
__device__ void canonical_for(Shared &s, uint32_t *canon, uint32_t tl, uint32_t log) {
  uint32_t run_key = 0xffffffffu;
  uint32_t first[2] = {0xffffffffu, 0xffffffffu};
  for (uint32_t k = 0; k < s.q; ++k) {
    const uint32_t i = s.order[k];
    const uint32_t cp = position(s.p[i], tl, log);
    if ((cp >> 1) != run_key) {
      run_key = cp >> 1;
      first[0] = first[1] = 0xffffffffu;
    }
    if (first[cp & 1u] == 0xffffffffu) first[cp & 1u] = i;
    canon[i] = first[cp & 1u];
  }
}

__device__ void trace_tree(Shared &s, const StwoRv64OuterEncodeIo &io, uint32_t t) {
  const uint32_t *d = io.desc;
  const uint32_t tid = threadIdx.x;
  const Tree tr = tree_of(d, t);
  const uint32_t tl = tr.tree_log, q = s.q;
  const uint32_t *raw = io.image + s.queries_at;
  uint32_t *scratch = io.scratch;
  for (uint32_t i = tid; i < q; i += kThreads) s.p[i] = position(raw[i], s.initial_log, tl);
  __syncthreads();
  for (uint32_t i = tid; i < q; i += kThreads) {
    uint32_t rank = 0;
    for (uint32_t j = 0; j < q; ++j) rank += (s.p[j] < s.p[i] || (s.p[j] == s.p[i] && j < i));
    s.order[rank] = i;
  }
  __syncthreads();
  if (tid == 0) {
    s.lv.nodes[0] = take(s, q);
    s.lv.reps[0] = take(s, q);
    uint32_t *nodes = scratch + s.lv.nodes[0], *reps = scratch + s.lv.reps[0];
    uint32_t n = 0;
    for (uint32_t k = 0; k < q; ++k) {
      const uint32_t i = s.order[k];
      if (!n || nodes[n - 1] != s.p[i]) {
        nodes[n] = s.p[i];
        reps[n] = i;
        ++n;
      }
    }
    s.lv.len[0] = n;
    s.trace_ops_first[t] = s.n_ops;
    walk(s, scratch, tl, s.tree_paths[t], tl);
    s.trace_ops_n[t] = s.n_ops - s.trace_ops_first[t];
    // canon[log * q + i] for every distinct column height of the tree.
    s.canon_at = take(s, uint64_t(tl + 1) * q);
    const uint32_t *logs = d + tr.table;
    for (uint32_t c = 0; c < tr.columns; ++c)
      if (c == 0 || logs[c] != logs[c - 1]) canonical_for(s, scratch + s.canon_at + uint64_t(logs[c]) * q, tl, logs[c]);
  }
  __syncthreads();
  // Hash consistency: every query's sibling at every level equals its node's representative's.
  const uint32_t *img = io.image;
  for (uint32_t task = tid; task < q * tl; task += kThreads) {
    const uint32_t qi = task / tl, lv = task % tl;
    const uint32_t k = find(scratch + s.lv.nodes[lv], s.lv.len[lv], s.p[qi] >> lv);
    if (k == 0xffffffffu) {
      refuse(s, kTraceInconsistent);
      continue;
    }
    const uint32_t rep = scratch[s.lv.reps[lv] + k];
    if (!eq8(img + s.tree_paths[t] + (uint64_t(qi) * tl + lv) * 8, img + s.tree_paths[t] + (uint64_t(rep) * tl + lv) * 8))
      refuse(s, kTraceInconsistent);
  }
  // Value consistency: queries sharing a column position share its value.
  const uint32_t *logs = d + tr.table;
  const uint32_t *values = img + s.tree_values[t];
  for (uint64_t task = tid; task < uint64_t(tr.columns) * q; task += kThreads) {
    const uint32_t c = uint32_t(task / q), qi = uint32_t(task % q);
    const uint32_t canon = scratch[s.canon_at + uint64_t(logs[c]) * q + qi];
    if (canon != qi && values[uint64_t(c) * q + qi] != values[uint64_t(c) * q + canon]) refuse(s, kTraceInconsistent);
  }
  __syncthreads();
}

__device__ void fri_layer(Shared &s, const StwoRv64OuterEncodeIo &io, uint32_t l) {
  const uint32_t *d = io.desc;
  const uint32_t tid = threadIdx.x;
  const Layer f = layer_of(d, l);
  const uint32_t h = height(f), q = s.q;
  const uint32_t subset = 1u << f.fold_step, slots = 1u << (f.fold_step - f.leaf_log);
  const uint32_t *raw = io.image + s.queries_at;
  const uint32_t *img = io.image;
  uint32_t *scratch = io.scratch;
  if (tid == 0) s.group_at = take(s, q);
  __syncthreads();
  // Group representative of every raw query (the first position of its group).
  for (uint32_t qi = tid; qi < q; qi += kThreads) {
    const uint32_t pos = raw[qi] >> f.shift;
    uint32_t g = find(s.fpos, s.fn, pos);
    if (g == 0xffffffffu) {  // impossible by construction
      refuse(s, kFriInconsistent);
      g = 0;
    }
    while (g > 0 && (s.fpos[g - 1] >> f.fold_step) == (pos >> f.fold_step)) --g;
    scratch[s.group_at + qi] = s.frep[g];
  }
  __syncthreads();
  for (uint64_t task = tid; task < uint64_t(q) * subset; task += kThreads) {
    const uint32_t qi = uint32_t(task / subset), off = uint32_t(task % subset);
    const uint32_t rep = scratch[s.group_at + qi];
    if (rep != qi && !eq8(img + s.layer_values[l] + (uint64_t(qi) * subset + off) * 8,
                          img + s.layer_values[l] + (uint64_t(rep) * subset + off) * 8))
      refuse(s, kFriInconsistent);
  }
  if (tid == 0) {
    // Witness values and leaves (fri.zig layerProof walk).
    s.fri_values_first[l] = s.n_ops;
    s.lv.nodes[0] = take(s, uint64_t(s.fn) * slots);
    s.lv.reps[0] = take(s, uint64_t(s.fn) * slots);
    uint32_t *leaves = scratch + s.lv.nodes[0], *lreps = scratch + s.lv.reps[0];
    uint32_t n = 0;
    for (uint32_t cursor = 0; cursor < s.fn;) {
      const uint32_t start = (s.fpos[cursor] >> f.fold_step) << f.fold_step;
      const uint32_t rep = s.frep[cursor];
      for (uint32_t off = 0; off < subset; ++off) {
        if (cursor < s.fn && s.fpos[cursor] == start + off) ++cursor;
        else push_op(s, scratch, uint32_t(s.layer_values[l] + (uint64_t(rep) * subset + off) * 8), 8);
      }
      for (uint32_t slot = 0; slot < slots; ++slot) {
        leaves[n] = (start >> f.leaf_log) + slot;
        lreps[n] = rep * slots + slot;
        ++n;
      }
    }
    s.lv.len[0] = n;
    s.fri_values_n[l] = s.n_ops - s.fri_values_first[l];
    s.fri_hash_first[l] = s.n_ops;
    walk(s, scratch, h, s.layer_paths[l], h);
    s.fri_hash_n[l] = s.n_ops - s.fri_hash_first[l];
  }
  __syncthreads();
  for (uint64_t task = tid; task < uint64_t(q) * slots * h; task += kThreads) {
    const uint32_t lv = uint32_t(task % h);
    const uint32_t path = uint32_t(task / h);  // qi * slots + slot
    const uint32_t qi = path / slots, slot = path % slots;
    const uint32_t start = ((raw[qi] >> f.shift) >> f.fold_step) << f.fold_step;
    const uint32_t leaf = (start >> f.leaf_log) + slot;
    const uint32_t k = find(scratch + s.lv.nodes[lv], s.lv.len[lv], leaf >> lv);
    if (k == 0xffffffffu) {
      refuse(s, kFriInconsistent);
      continue;
    }
    const uint32_t rep = scratch[s.lv.reps[lv] + k];
    if (!eq8(img + s.layer_paths[l] + (uint64_t(path) * h + lv) * 8, img + s.layer_paths[l] + (uint64_t(rep) * h + lv) * 8))
      refuse(s, kFriInconsistent);
  }
  __syncthreads();
  if (tid == 0) {  // Queries.fold, keeping the first rep
    uint32_t w = 0;
    for (uint32_t i = 0; i < s.fn; ++i) {
      const uint32_t folded = s.fpos[i] >> f.fold_step;
      if (!w || s.fpos[w - 1] != folded) {
        s.fpos[w] = folded;
        s.frep[w] = s.frep[i];
        ++w;
      }
    }
    s.fn = w;
  }
  __syncthreads();
}

// Thread 0: payload layout, small words, op destinations (mirror emit order).
__device__ void layout_and_head(Shared &s, const StwoRv64OuterEncodeIo &io) {
  const uint32_t *d = io.desc;
  const uint32_t *img = io.image;
  uint32_t *out = io.region + 1;
  uint32_t *ops = io.scratch + s.ops_at;
  uint64_t at = 0;
  uint64_t phys_len_at = 0;
  auto put = [&](uint32_t w) { out[at++] = w; };
  auto copy = [&](uint64_t src, uint32_t n) {
    for (uint32_t k = 0; k < n; ++k) out[at + k] = img[src + k];
    at += n;
  };
  auto place = [&](uint32_t first, uint32_t n) {  // count + ops of a section
    put(n);
    for (uint32_t i = 0; i < n; ++i) {
      ops[3 * (first + i)] = uint32_t(at);
      at += ops[3 * (first + i) + 2];
    }
  };
  if (s.envelope) {
    for (uint32_t i = 0; i < 18; ++i) put(d[dEnvelope + i]);
    put(d[dOutputs]);
    s.out_at = at;
    at += 4ull * d[dOutputs];
    s.claims_at = at;
    at += 8ull * d[dClaims];
    phys_len_at = at;
    put(0);
  }
  const uint64_t phys = at;
  put(d[dPhysMagic]);
  put(d[dPhysMagic + 1]);
  for (uint32_t i = 0; i < 6; ++i) put(d[dConfig + i]);
  put(s.trees);
  copy(s.roots_at, 8 * s.trees);
  put(s.trees);
  uint32_t op = s.sample_ops_first;
  for (uint32_t t = 0; t < s.trees; ++t) {
    const Tree tr = tree_of(d, t);
    put(tr.columns);
    const uint32_t *counts = d + tr.table + 3 * tr.columns;
    for (uint32_t c = 0; c < tr.columns; ++c) {
      put(counts[c]);
      if (counts[c]) {
        ops[3 * op] = uint32_t(at);
        at += 8ull * counts[c];
        ++op;
      }
    }
  }
  put(s.trees);
  for (uint32_t t = 0; t < s.trees; ++t) place(s.trace_ops_first[t], s.trace_ops_n[t]);
  put(s.trees);
  for (uint32_t t = 0; t < s.trees; ++t) {
    const Tree tr = tree_of(d, t);
    put(tr.columns);
    s.qv_at[t] = at;  // columns x (1 + n_reps), written by the copy phase
    at += uint64_t(tr.columns) * (1 + s.n_reps);
  }
  copy(s.nonce_at, 2);
  for (uint32_t l = 0; l < s.layers; ++l) {
    if (l == 1) put(s.layers - 1);
    place(s.fri_values_first[l], s.fri_values_n[l]);
    place(s.fri_hash_first[l], s.fri_hash_n[l]);
    copy(s.layer_root[l], 8);
  }
  if (s.layers == 1) put(0);
  put(1);
  copy(s.terminal_at, 8);
  if (s.envelope) out[phys_len_at] = uint32_t((at - phys) * 4);
  s.words = at;
}

// Payload size only (mirror layoutWords), before anything is written.
__device__ uint64_t payload_words(const Shared &s, const uint32_t *d) {
  uint64_t n = 0;
  if (s.envelope) n += 18 + 1 + 4ull * d[dOutputs] + 8ull * d[dClaims] + 1;
  n += 2 + 6 + 1 + 8ull * s.trees + 1;
  for (uint32_t t = 0; t < s.trees; ++t) {
    const Tree tr = tree_of(d, t);
    n += 1 + tr.columns + 8ull * tr.samples;
  }
  n += 1;
  for (uint32_t t = 0; t < s.trees; ++t) n += 1 + 8ull * s.trace_ops_n[t];
  n += 1;
  for (uint32_t t = 0; t < s.trees; ++t) n += 1 + uint64_t(tree_of(d, t).columns) * (1 + s.n_reps);
  n += 2;
  for (uint32_t l = 0; l < s.layers; ++l) n += 1 + 8ull * s.fri_values_n[l] + 1 + 8ull * s.fri_hash_n[l] + 8;
  n += 1 + 1 + 8;
  return n;
}

__global__ void __launch_bounds__(kThreads) outer_encode(StwoRv64OuterEncodeIo io) {
  __shared__ Shared s;
  const uint32_t tid = threadIdx.x;
  const uint32_t *d = io.desc;
  if (tid == 0) {
    s.fail = 0xffffffffu;  // atomicMin target: rank + 1, 0xffffffff = none
    s.bump = 0;
    s.n_ops = 0;
    io.region[0] = 0;
    validate_head(s, io);
  }
  __syncthreads();
  if (s.fail == 0xffffffffu) validate_values(s, io);
  __syncthreads();
  if (s.fail == 0xffffffffu) {
    const uint32_t q = s.q;
    const uint32_t *raw = io.image + s.queries_at;
    for (uint32_t i = tid; i < q; i += kThreads) {
      uint32_t rank = 0;
      for (uint32_t j = 0; j < q; ++j) rank += (raw[j] < raw[i] || (raw[j] == raw[i] && j < i));
      s.sorted[rank] = i;
    }
    __syncthreads();
    if (tid == 0) {
      uint32_t n = 0;
      for (uint32_t k = 0; k < q; ++k) {
        const uint32_t i = s.sorted[k];
        if (!n || raw[s.reps[n - 1]] != raw[i]) s.reps[n++] = i;
      }
      s.n_reps = n;
      // FRI layer-0 positions: distinct raw values, ascending, first index.
      for (uint32_t k = 0; k < n; ++k) {
        s.fpos[k] = raw[s.reps[k]];
        s.frep[k] = s.reps[k];
      }
      s.fn = n;
      s.ops_at = take(s, 3ull * d[dMaxOps]);
      // Sampled-value ops first (one per sampled column, tree / original column order).
      s.sample_ops_first = 0;
      uint64_t cursor = s.samples_at;
      for (uint32_t t = 0; t < s.trees; ++t) {
        const Tree tr = tree_of(d, t);
        const uint32_t *counts = d + tr.table + 3 * tr.columns;
        for (uint32_t c = 0; c < tr.columns; ++c)
          if (counts[c]) {
            push_op(s, io.scratch, uint32_t(cursor), 8 * counts[c]);
            cursor += 8ull * counts[c];
          }
      }
      s.sample_ops_n = s.n_ops;
    }
    __syncthreads();
    for (uint32_t t = 0; t < s.trees; ++t) trace_tree(s, io, t);
    for (uint32_t l = 0; l < s.layers; ++l) fri_layer(s, io, l);
    if (tid == 0 && (s.n_ops > d[dMaxOps] || s.bump > d[dScratch])) refuse(s, kDescriptor);  // bound drift: fail closed
  }
  __syncthreads();
  const bool rejected = s.fail != 0xffffffffu;
  __shared__ uint32_t fits;
  if (tid == 0) {
    fits = 0;
    if (!rejected) {
      const uint64_t words = payload_words(s, d);
      if (words + 1 <= io.region_words) {
        fits = 1;
        layout_and_head(s, io);
      }
    }
  }
  __syncthreads();
  if (!rejected && fits) {
    const uint32_t *img = io.image;
    uint32_t *out = io.region + 1;
    const uint32_t *ops = io.scratch + s.ops_at;
    // Copy ops (8-word hashes / FRI values, sampled columns).
    for (uint32_t i = tid; i < s.n_ops; i += kThreads) {
      const uint32_t dst = ops[3 * i], src = ops[3 * i + 1], n = ops[3 * i + 2];
      for (uint32_t k = 0; k < n; ++k) out[uint64_t(dst) + k] = img[uint64_t(src) + k];
    }
    // Queried values: tree, original column, distinct raw query.
    for (uint32_t t = 0; t < s.trees; ++t) {
      const Tree tr = tree_of(d, t);
      const uint32_t *o2s = d + tr.table + 2 * tr.columns;
      const uint32_t stride = 1 + s.n_reps;
      const uint32_t *values = img + s.tree_values[t];
      for (uint64_t task = tid; task < uint64_t(tr.columns) * stride; task += kThreads) {
        const uint32_t c = uint32_t(task / stride), k = uint32_t(task % stride);
        out[s.qv_at[t] + task] = k == 0 ? s.n_reps : values[uint64_t(o2s[c]) * s.q + s.reps[k - 1]];
      }
    }
    if (s.envelope) {
      for (uint32_t i = tid; i < 4 * d[dOutputs]; i += kThreads) out[s.out_at + i] = io.outputs[i];
      for (uint32_t i = tid; i < 8 * d[dClaims]; i += kThreads) out[s.claims_at + i] = io.claims[i];
    }
  }
  __syncthreads();
  if (tid == 0) {
    if (rejected) {
      const uint32_t rank = s.fail - 1;
      io.pcs_status[0] = (kPcsStatus << 16) | (rank < 12 ? kDetailOfRank[rank] : kDescriptor);
      io.encode_status[0] = (kEncodeBounds << 16) | 2u;
      io.region[0] = 0;
    } else if (!fits) {
      io.pcs_status[0] = 0;
      io.encode_status[0] = (kEncodeBounds << 16) | 1u;
      io.region[0] = 0;
    } else {
      io.pcs_status[0] = 0;
      io.encode_status[0] = 0;
      __threadfence_block();
      io.region[0] = uint32_t(s.words * 4);
    }
  }
}
}  // namespace

}  // namespace stwo::cuda::rv64

// One launch on the lane's exec stream. Every pointer is custody-checked
// against the execution context (job arena, slab, class region); the kernel
// re-validates the descriptor and image itself and fails closed through the
// two Verdict words (never a host error for a bad image).
extern "C" int stwo_rv64_outer_encode_v1_on(void *context, uint32_t lane, const StwoRv64OuterEncodeIo *io) {
  using namespace stwo::cuda::rv64;
  if (!io || !io->desc || io->desc_words < dTables || !io->image || !io->image_words || io->region_words < 1 ||
      !io->scratch_words || io->reserved)
    return int(cudaErrorInvalidValue);
  RangeCustody<13> custody(context, lane);
  bool ok = custody.range(io->desc, io->desc_words, false) && custody.range(io->image, io->image_words, false);
  for (int t = 0; t < 4 && ok; ++t)
    if (io->roots[t]) ok = custody.range(io->roots[t], 8, false);
  if (ok && io->claims_words) ok = custody.range(io->claims, io->claims_words, false);
  if (ok && io->latches_words) ok = custody.range(io->latches, io->latches_words, false);
  if (ok && io->outputs_words) ok = custody.range(io->outputs, io->outputs_words, false);
  ok = ok && custody.range(io->region, io->region_words, true) && custody.range(io->pcs_status, 1, true) &&
       custody.range(io->encode_status, 1, true) && custody.range(io->scratch, io->scratch_words, true);
  if (!ok) return custody.status ? custody.status : int(cudaErrorInvalidValue);
  outer_encode<<<1, kThreads, 0, custody.stream>>>(*io);
  return int(cudaPeekAtLastError());
}

extern "C" uint32_t stwo_rv64_outer_encode_version(void) {
  return 1;
}
