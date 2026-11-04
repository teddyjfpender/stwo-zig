#include "../commitment/blake2s_core.cuh"
#include "custody.cuh"
#include "trace.h"
#include "prefix_banks.h"
namespace b = stwo::cuda::blake2s;
extern "C" int stwo_blake2s_mixed_leaf_on(uint32_t, uint32_t,
                                          const b::MixedSegment *, b::Hash *,
                                          void *);
extern "C" int stwo_blake2s_mixed_seeded_on(
    uint32_t, uint32_t, const b::MixedSegment *, uint32_t, uint32_t,
    const b::ProgressiveState *, b::ProgressiveState *, b::Hash *, void *);
// Eager prefix states (kernels stream): native_height_leaves below is a
// self-contained chain (each seed is its own previous call's prefix), so it
// may skip the deferred full block and halve its prefix-state HBM traffic.
extern "C" int stwo_blake2s_mixed_seeded_eager_on(
    uint32_t, uint32_t, const b::MixedSegment *, uint32_t, uint32_t,
    const b::ProgressiveState *, b::ProgressiveState *, b::Hash *, void *);
extern "C" int stwo_blake2s_layer_on(const b::Hash *, uint32_t, b::Hash *,
                                     void *);
namespace stwo::cuda::rv64 {
struct TraceInputs {
  b::MixedSegment segments[b::kMaxMixedSegments];
  uint32_t count, columns;
};
using TraceCustody = RangeCustody<b::kMaxMixedSegments + 8>;
static bool validate(TraceCustody &c, const b::MixedSegment *segments,
                     uint32_t count, uint32_t log, TraceInputs *out) {
  if (!segments || !count || count > b::kMaxMixedSegments || log < 1 ||
      log > 28) {
    c.status = int(cudaErrorInvalidValue);
    return false;
  }
  out->count = count;
  out->columns = 0;
  uint32_t previous = 0;
  for (uint32_t i = 0; i < count; ++i) {
    const auto s = segments[i];
    if (s.reserved || !power2(s.source_size) || s.source_size < 2 ||
        s.source_size > (1u << log) || s.source_size < previous ||
        s.stride_words < s.source_size || !s.capacity_words ||
        s.capacity_words % s.stride_words ||
        s.capacity_words / s.stride_words > 65536 - out->columns) {
      c.status = int(cudaErrorInvalidValue);
      return false;
    }
    if (!c.range(s.columns, s.capacity_words, false))
      return false;
    out->segments[i] = s;
    out->columns += s.capacity_words / s.stride_words;
    previous = s.source_size;
  }
  return true;
}
__device__ uint32_t lift_row(uint32_t row, uint32_t from_log, uint32_t to_log) {
  return from_log >= to_log
             ? ((row >> (from_log - to_log + 1)) << 1) | (row & 1u)
             : ((row >> 1) << (to_log - from_log + 1)) | (row & 1u);
}
__device__ bool query_row(StwoRv64TraceOpen j, uint32_t qi, uint32_t *row) {
  const auto q = j.queries[qi];
  if (q >= (1u << j.lifting_log)) {
    atomicOr(j.status, 1u);
    *row = 0;
    return false;
  }
  *row = lift_row(q, j.lifting_log, j.tree_log);
  return true;
}
__global__ void open_values(TraceInputs input, StwoRv64TraceOpen j) {
  const uint32_t col = blockIdx.x * blockDim.x + threadIdx.x, qi = blockIdx.y;
  if (col >= input.columns)
    return;
  uint32_t row = 0, value = 0, remaining = col;
  if (query_row(j, qi, &row))
    for (uint32_t i = 0; i < input.count; ++i) {
      const auto s = input.segments[i];
      const uint32_t columns = s.capacity_words / s.stride_words;
      if (remaining >= columns) {
        remaining -= columns;
        continue;
      }
      const uint32_t source_log = __ffs(s.source_size) - 1;
      value = s.columns[uint64_t(remaining) * s.stride_words +
                        lift_row(row, j.tree_log, source_log)];
      if (value >= 0x7fffffffu) {
        atomicOr(j.status, 2u);
        value = 0;
      }
      break;
    }
  j.values[uint64_t(col) * j.query_count + qi] = value;
}
__global__ void open_paths(StwoRv64TraceOpen j) {
  const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x, qi = blockIdx.y;
  if (i >= j.tree_log * 8)
    return;
  uint32_t row = 0, value = 0;
  if (query_row(j, qi, &row)) {
    const uint32_t level = i / 8, sibling = (row >> level) ^ 1u;
    const uint64_t leaves = uint64_t(1) << j.tree_log;
    const uint64_t offset = 2 * leaves - ((2 * leaves) >> level);
    value = j.tree[(offset + sibling) * 8 + (i & 7u)];
  }
  j.paths[(uint64_t(qi) * j.tree_log) * 8 + i] = value;
}
} // namespace stwo::cuda::rv64
// Absorb sorted column groups once at their native height. A seed contains
// the unfinalized Blake state, including its pending block. Lifting that seed
// is exactly equivalent to repeating the low-height words in every final leaf.
// Scratch is stream-owned and never aliases caller allocations.
static int native_height_leaves(const b::MixedSegment *segments, uint32_t count,
                                uint32_t leaves, b::Hash *hashes,
                                cudaStream_t stream, b::ProgressiveState *scratch = nullptr,
                                const stwo::cuda::rv64::PrefixBanks &banks = {}) {
  b::ProgressiveState *seed = nullptr;
  uint32_t seed_size = 0, absorbed = 0, bank = 0;
  for (uint32_t first = 0; first < count;) {
    uint32_t end = first + 1;
    while (end < count && segments[end].source_size == segments[first].source_size)
      ++end;
    const bool final = end == count;
    const uint32_t size = final ? leaves : segments[first].source_size;
    b::ProgressiveState *next = nullptr;
    int status = 0;
    if (!final && scratch) {
      if (size > banks.rows[bank]) return int(cudaErrorInvalidValue);
      next = scratch + banks.offset(bank);
      bank ^= 1u;
    } else if (!final)
      status = int(cudaMallocAsync(reinterpret_cast<void **>(&next),
                                   uint64_t(size) * sizeof(*next), stream));
    if (!status)
      status = stwo_blake2s_mixed_seeded_eager_on(
          size, end - first, segments + first, absorbed, seed_size, seed,
          next, final ? hashes : nullptr, stream);
    if (seed && !scratch) {
      const int freed = int(cudaFreeAsync(seed, stream));
      if (!status) status = freed;
    }
    if (status) {
      if (next && !scratch) cudaFreeAsync(next, stream);
      return status;
    }
    for (uint32_t i = first; i < end; ++i)
      absorbed += segments[i].capacity_words / segments[i].stride_words;
    seed = next;
    seed_size = final ? 0 : size;
    first = end;
  }
  return 0;
}
static int prefix_bank_layout(const b::MixedSegment *segments, uint32_t count,
                              stwo::cuda::rv64::PrefixBanks *banks) {
  if (!segments || !count || count > b::kMaxMixedSegments || !banks)
    return int(cudaErrorInvalidValue);
  uint32_t previous = 0;
  for (uint32_t i = 0; i < count; ++i) {
    const uint32_t size = segments[i].source_size;
    if (!size || (size & (size - 1)) || size > (1u << 28) || size < previous)
      return int(cudaErrorInvalidValue);
    if (i + 1 < count && size != segments[i + 1].source_size && !banks->addHeight(size))
      return int(cudaErrorInvalidValue);
    previous = size;
  }
  return 0;
}
extern "C" int stwo_rv64_trace_prefix_workspace_words(
    const b::MixedSegment *segments, uint32_t count, uint64_t *words) {
  if (!words) return int(cudaErrorInvalidValue);
  stwo::cuda::rv64::PrefixBanks banks;
  const int status = prefix_bank_layout(segments, count, &banks);
  if (!status) *words = banks.words();
  return status;
}
extern "C" int stwo_rv64_trace_tree_on(void *ctx, uint32_t lane,
                                       const b::MixedSegment *segments,
                                       uint32_t count, uint32_t log,
                                       uint32_t *tree, uint64_t tree_words) {
  using namespace stwo::cuda::rv64;
  TraceCustody c(ctx, lane);
  TraceInputs input{};
  if (!validate(c, segments, count, log, &input))
    return c.status;
  const uint64_t leaves = uint64_t(1) << log, need = (2 * leaves - 1) * 8;
  if (tree_words < need || reinterpret_cast<uintptr_t>(tree) % 32)
    return int(cudaErrorInvalidValue);
  // An optional tail is caller-owned, admitted scratch from the same context
  // pool as the tree and evaluations. Two banks preserve the previous prefix
  // until the next height has consumed it, without cross-pool allocations.
  static_assert(sizeof(b::ProgressiveState) == PrefixBanks::state_words * 4,
                "prefix bank state representation");
  PrefixBanks banks;
  const int layout_status = prefix_bank_layout(segments, count, &banks);
  if (layout_status) return layout_status;
  const uint64_t scratch_words = banks.words();
  const bool owned_scratch = tree_words >= need + scratch_words;
  if (!c.range(tree, need + (owned_scratch ? scratch_words : 0), true))
    return c.status;
  auto *scratch = owned_scratch && scratch_words
                      ? reinterpret_cast<b::ProgressiveState *>(tree + need)
                      : nullptr;
  auto *hashes = reinterpret_cast<b::Hash *>(tree);
  int status = native_height_leaves(input.segments, count, uint32_t(leaves),
                                    hashes, c.stream, scratch, banks);
  uint64_t offset = 0, next_offset = leaves;
  for (uint32_t nodes = leaves; !status && nodes > 1; nodes >>= 1) {
    status = stwo_blake2s_layer_on(hashes + offset, nodes / 2,
                                   hashes + next_offset, c.stream);
    offset = next_offset;
    next_offset += nodes / 2;
  }
  return status;
}
extern "C" int stwo_rv64_trace_open_on(void *ctx, uint32_t lane,
                                       const b::MixedSegment *segments,
                                       uint32_t count,
                                       const StwoRv64TraceOpen *job) {
  using namespace stwo::cuda::rv64;
  if (!job || job->reserved || job->lifting_log < 1 || job->lifting_log > 28 ||
      !job->query_count || job->query_count > 1024)
    return int(cudaErrorInvalidValue);
  TraceCustody c(ctx, lane);
  TraceInputs input{};
  const auto j = *job;
  if (!validate(c, segments, count, j.tree_log, &input))
    return c.status;
  const uint64_t tree_need = ((uint64_t(2) << j.tree_log) - 1) * 8;
  const uint64_t value_need = uint64_t(input.columns) * j.query_count,
                 path_need = uint64_t(j.query_count) * j.tree_log * 8;
  if (j.tree_words < tree_need || j.value_words < value_need ||
      j.path_words < path_need || reinterpret_cast<uintptr_t>(j.tree) % 32)
    return int(cudaErrorInvalidValue);
  if (!c.range(j.tree, tree_need, false) ||
      !c.range(j.queries, j.query_count, false) ||
      !c.range(j.values, value_need, true) ||
      !c.range(j.paths, path_need, true) || !c.range(j.status, 1, true))
    return c.status;
  open_values<<<dim3((input.columns + 127) / 128, j.query_count), 128, 0,
                c.stream>>>(input, j);
  open_paths<<<dim3((j.tree_log * 8 + 127) / 128, j.query_count), 128, 0,
               c.stream>>>(j);
  return int(cudaPeekAtLastError());
}
// Streaming opening halves: values are read from each evaluation chunk while
// it is live; paths are read from the finished tree. Together they are exactly
// stwo_rv64_trace_open_on over the complete (never materialised) LDE.
extern "C" int stwo_rv64_trace_open_values_on(void *ctx, uint32_t lane,
                                              const b::MixedSegment *segments,
                                              uint32_t count,
                                              const StwoRv64TraceOpen *job) {
  using namespace stwo::cuda::rv64;
  if (!job || job->reserved || job->lifting_log < 1 || job->lifting_log > 28 ||
      !job->query_count || job->query_count > 1024)
    return int(cudaErrorInvalidValue);
  TraceCustody c(ctx, lane);
  TraceInputs input{};
  const auto j = *job;
  if (!validate(c, segments, count, j.tree_log, &input))
    return c.status;
  const uint64_t value_need = uint64_t(input.columns) * j.query_count;
  if (j.value_words < value_need)
    return int(cudaErrorInvalidValue);
  if (!c.range(j.queries, j.query_count, false) ||
      !c.range(j.values, value_need, true) || !c.range(j.status, 1, true))
    return c.status;
  open_values<<<dim3((input.columns + 127) / 128, j.query_count), 128, 0,
                c.stream>>>(input, j);
  return int(cudaPeekAtLastError());
}
extern "C" int stwo_rv64_trace_open_paths_on(void *ctx, uint32_t lane,
                                             const StwoRv64TraceOpen *job) {
  using namespace stwo::cuda::rv64;
  if (!job || job->reserved || job->lifting_log < 1 || job->lifting_log > 28 ||
      !job->query_count || job->query_count > 1024 || job->tree_log < 1 ||
      job->tree_log > 28)
    return int(cudaErrorInvalidValue);
  TraceCustody c(ctx, lane);
  const auto j = *job;
  const uint64_t tree_need = ((uint64_t(2) << j.tree_log) - 1) * 8;
  const uint64_t path_need = uint64_t(j.query_count) * j.tree_log * 8;
  if (j.tree_words < tree_need || j.path_words < path_need ||
      reinterpret_cast<uintptr_t>(j.tree) % 32)
    return int(cudaErrorInvalidValue);
  if (!c.range(j.tree, tree_need, false) ||
      !c.range(j.queries, j.query_count, false) ||
      !c.range(j.paths, path_need, true) || !c.range(j.status, 1, true))
    return c.status;
  open_paths<<<dim3((j.tree_log * 8 + 127) / 128, j.query_count), 128, 0,
               c.stream>>>(j);
  return int(cudaPeekAtLastError());
}
