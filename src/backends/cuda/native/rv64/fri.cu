#include "commitment/blake2s_core.cuh"
#include "custody.cuh"
#include "fri.h"
#include "om31.cuh"
using StwoFriHash = stwo::cuda::blake2s::Hash;
extern "C" int stwo_blake2s_layer_on(const StwoFriHash *, uint32_t,
                                     StwoFriHash *, void *);
// T6 contiguous-tree layers (commitment/merkle.cu): STWO_RV64_M8_MERKLE_FUSED
// unset/0 runs exactly the per-layer loop; =1 the fused schedule (bit-identical).
// Weak: an image without the entry keeps the loop.
extern "C" int stwo_blake2s_merkle_layers_on(StwoFriHash *, uint32_t, uint64_t, void *)
    __attribute__((weak));
namespace stwo::cuda::rv64 {
__global__ void fri_terminal(StwoRv64Plane input, uint32_t count,
                             uint32_t *output, uint32_t *status) {
  __shared__ uint32_t flags;
  if (!threadIdx.x)
    flags = atomicOr(status, 0u);
  __syncthreads();
  const OM31 first = load(input.words, input.stride, 0);
  for (uint32_t i = threadIdx.x; i < count; i += blockDim.x) {
    const OM31 value = load(input.words, input.stride, i);
    if (!canonical(value))
      atomicOr(&flags, 2u);
    if (!is_zero(sub(value, first)))
      atomicOr(&flags, 8u);
  }
  __syncthreads();
  if (!threadIdx.x) {
    atomicOr(status, flags);
    for (uint32_t c = 0; c < 8; ++c)
      output[c] = flags ? 0 : coordinate(first, c);
  }
}
__device__ bool fri_query(StwoRv64FriOpen j, uint32_t q, uint32_t *start) {
  const uint32_t raw = j.queries[q];
  const uint64_t initial_count = uint64_t(j.count) << j.shift;
  if (raw >= initial_count) {
    atomicOr(j.status, 1u);
    return false;
  }
  *start = ((raw >> j.shift) >> j.fold_step) << j.fold_step;
  return true;
}
__global__ void fri_open_values(StwoRv64FriOpen j) {
  const uint32_t q = blockIdx.y, i = blockIdx.x * blockDim.x + threadIdx.x;
  const uint32_t words = 8u << j.fold_step;
  if (i >= words)
    return;
  uint32_t value = 0, start = 0;
  if (fri_query(j, q, &start)) {
    value = j.input.words[uint64_t(i & 7u) * j.input.stride + start + i / 8];
    if (value >= q::kPrime) {
      atomicOr(j.status, 2u);
      value = 0;
    }
  }
  j.values[uint64_t(q) * words + i] = value;
}
__global__ void fri_open_paths(StwoRv64FriOpen j, uint32_t height) {
  const uint32_t q = blockIdx.y, i = blockIdx.x * blockDim.x + threadIdx.x;
  const uint32_t per_query = (1u << (j.fold_step - j.leaf_log)) * height * 8;
  if (i >= per_query)
    return;
  uint32_t value = 0, start = 0;
  if (fri_query(j, q, &start)) {
    const uint32_t slot = i / (height * 8), level = (i / 8) % height;
    const uint32_t leaf = (start >> j.leaf_log) + slot;
    const uint64_t leaves = j.count >> j.leaf_log;
    const uint64_t offset = 2 * leaves - ((2 * leaves) >> level);
    const uint32_t sibling = (leaf >> level) ^ 1u;
    value = j.tree[(offset + sibling) * 8 + (i & 7u)];
  }
  j.paths[uint64_t(q) * per_query + i] = value;
}
} // namespace stwo::cuda::rv64
extern "C" int stwo_rv64_fri_tree_on(void *ctx, uint32_t lane,
                                     StwoRv64Plane input, uint32_t count,
                                     uint32_t leaf_log, uint32_t *tree,
                                     uint64_t words) {
  using namespace stwo::cuda::rv64;
  if (!power2(count) || count > max_count || (leaf_log != 0 && leaf_log != 2) ||
      count < (1u << leaf_log))
    return int(cudaErrorInvalidValue);
  if (reinterpret_cast<uintptr_t>(tree) % alignof(StwoFriHash))
    return int(cudaErrorInvalidValue);
  const uint32_t leaves = count >> leaf_log;
  const uint64_t need = (uint64_t(leaves) * 2 - 1) * 8;
  if (words < need)
    return int(cudaErrorInvalidValue);
  Custody c(ctx, lane);
  if (!c.plane(input, count, 8, false) || !c.range(tree, need, true))
    return c.status;
  int status = stwo_rv64_fri_leaves_on(ctx, lane, input, count, leaf_log, 1,
                                       tree, leaves);
  if (status)
    return status;
  if (&stwo_blake2s_merkle_layers_on && leaves >= 2 && c.stream) {
    status = stwo_blake2s_merkle_layers_on(reinterpret_cast<StwoFriHash *>(tree), leaves,
                                           uint64_t(2) * leaves - 1, c.stream);
    return status ? status : int(cudaPeekAtLastError());
  }
  uint64_t offset = 0;
  for (uint32_t n = leaves; n > 1; n >>= 1) {
    status = stwo_blake2s_layer_on(
        reinterpret_cast<const StwoFriHash *>(tree + offset * 8), n / 2,
        reinterpret_cast<StwoFriHash *>(tree + (offset + n) * 8), c.stream);
    if (status)
      return status;
    offset += n;
  }
  return int(cudaPeekAtLastError());
}
extern "C" int stwo_rv64_fri_terminal_on(void *ctx, uint32_t lane,
                                         StwoRv64Plane input, uint32_t count,
                                         uint32_t *output, uint32_t *status) {
  using namespace stwo::cuda::rv64;
  if (!power2(count) || count < 2 || count > 65536)
    return int(cudaErrorInvalidValue);
  Custody c(ctx, lane);
  if (!c.plane(input, count, 8, false) || !c.range(output, 8, true) ||
      !c.range(status, 1, true))
    return c.status;
  fri_terminal<<<1, 128, 0, c.stream>>>(input, count, output, status);
  return int(cudaPeekAtLastError());
}
extern "C" int stwo_rv64_fri_open_on(void *ctx, uint32_t lane,
                                     const StwoRv64FriOpen *input) {
  using namespace stwo::cuda::rv64;
  if (!input || input->reserved || !power2(input->count) ||
      input->count > max_count || !input->query_count ||
      input->query_count > 1024 || !input->fold_step || input->fold_step > 4 ||
      input->shift > 28 ||
      uint64_t(input->count) > (uint64_t(1) << (28 - input->shift)) ||
      input->count < (1u << input->fold_step) ||
      input->leaf_log != (input->fold_step > 1 ? 2u : 0u))
    return int(cudaErrorInvalidValue);
  const auto j = *input;
  const uint32_t leaves = j.count >> j.leaf_log,
                 height = 31u - uint32_t(__builtin_clz(leaves));
  const uint64_t tree_words = (uint64_t(leaves) * 2 - 1) * 8;
  const uint64_t value_words = uint64_t(j.query_count) * (8u << j.fold_step);
  const uint64_t path_words =
      uint64_t(j.query_count) * (1u << (j.fold_step - j.leaf_log)) * height * 8;
  if (j.tree_words < tree_words || j.value_words < value_words ||
      j.path_words < path_words)
    return int(cudaErrorInvalidValue);
  Custody c(ctx, lane);
  if (!c.plane(j.input, j.count, 8, false) ||
      !c.range(j.tree, tree_words, false) ||
      !c.range(j.queries, j.query_count, false) ||
      !c.range(j.values, value_words, true) ||
      (path_words && !c.range(j.paths, path_words, true)) ||
      !c.range(j.status, 1, true))
    return c.status;
  fri_open_values<<<dim3(((8u << j.fold_step) + 127) / 128, j.query_count), 128,
                    0, c.stream>>>(j);
  if (path_words)
    fri_open_paths<<<
        dim3((((1u << (j.fold_step - j.leaf_log)) * height * 8) + 127) / 128,
             j.query_count),
        128, 0, c.stream>>>(j, height);
  return int(cudaPeekAtLastError());
}
