// Isolated six-input Blake-G relation body.
//
// One active thread owns one padded row, loads the six raw words exactly once,
// and instantiates the same phase-local evaluator as the fused witness writer.
// It emits nine fractions into the proven 512-leaf shared inverse/scan slab.
// Keeping this in a separate translation unit prevents its arithmetic register
// footprint from reducing occupancy for the generic relation kernel.

#include <cstddef>
#include <cstdint>
#include <cuda_runtime.h>

#include "relation_fused.cuh"
#include "blake_g_row_evaluator.cuh"

namespace {

constexpr uint32_t BLAKE_G_INPUTS = 6;
constexpr uint32_t BLAKE_G_COLUMNS = 9;
constexpr uint32_t BLAKE_G_COORDINATES = 4 * BLAKE_G_COLUMNS;
constexpr uint32_t BLAKE_G_TILE_ROWS =
    RELATION_FUSED_ONE_READ_FRACTIONS / BLAKE_G_COLUMNS;

struct blake_shared_qm31 {
  m31 *words;
  uint32_t stride;
};

__device__ __forceinline__ qm31 shared_load(blake_shared_qm31 slab,
                                            uint32_t index) {
  return {{slab.words[index], slab.words[slab.stride + index]},
          {slab.words[2u * slab.stride + index],
           slab.words[3u * slab.stride + index]}};
}

__device__ __forceinline__ void shared_store(blake_shared_qm31 slab,
                                              uint32_t index, qm31 value) {
  slab.words[index] = value.a.a;
  slab.words[slab.stride + index] = value.a.b;
  slab.words[2u * slab.stride + index] = value.b.a;
  slab.words[3u * slab.stride + index] = value.b.b;
}

__device__ __forceinline__ bool is_zero(qm31 value) {
  return value.a.a == 0u && value.a.b == 0u && value.b.a == 0u &&
         value.b.b == 0u;
}

__device__ __forceinline__ void reject_zero(qm31 value) {
  if (is_zero(value)) {
    asm volatile("trap;");
  }
}

__device__ __forceinline__ void batch_inverse(blake_shared_qm31 leaves,
                                               blake_shared_qm31 tree) {
  uint32_t child_count = RELATION_FUSED_ONE_READ_FRACTIONS;
  blake_shared_qm31 children = leaves;
  uint32_t tree_offset = 0u;
  while (child_count > 1u) {
    uint32_t parent_count = child_count >> 1u;
    blake_shared_qm31 parents = {tree.words + tree_offset, tree.stride};
    for (uint32_t parent = threadIdx.x; parent < parent_count;
         parent += blockDim.x) {
      shared_store(parents, parent,
                   mul(shared_load(children, parent << 1u),
                       shared_load(children, (parent << 1u) + 1u)));
    }
    __syncthreads();
    children = parents;
    tree_offset += parent_count;
    child_count = parent_count;
  }
  if (threadIdx.x == 0u) {
    qm31 root = shared_load(children, 0u);
    reject_zero(root);
    shared_store(children, 0u, inv(root));
  }
  __syncthreads();

  uint32_t parent_count = 1u;
  while (parent_count < RELATION_FUSED_ONE_READ_FRACTIONS) {
    uint32_t parent_offset =
        RELATION_FUSED_ONE_READ_FRACTIONS - (parent_count << 1u);
    blake_shared_qm31 parents = {tree.words + parent_offset, tree.stride};
    uint32_t next_count = parent_count << 1u;
    blake_shared_qm31 next =
        next_count == RELATION_FUSED_ONE_READ_FRACTIONS
            ? leaves
            : blake_shared_qm31{
                  tree.words + RELATION_FUSED_ONE_READ_FRACTIONS -
                      (next_count << 1u),
                  tree.stride};
    for (uint32_t parent = threadIdx.x; parent < parent_count;
         parent += blockDim.x) {
      qm31 inverse = shared_load(parents, parent);
      qm31 left = shared_load(next, parent << 1u);
      qm31 right = shared_load(next, (parent << 1u) + 1u);
      shared_store(next, parent << 1u, mul(inverse, right));
      shared_store(next, (parent << 1u) + 1u, mul(inverse, left));
    }
    __syncthreads();
    parent_count = next_count;
  }
}

__device__ __forceinline__ qm31 combine_xor(uint32_t relation, uint32_t a,
                                             uint32_t b, uint32_t x,
                                             const qm31 *alphas, qm31 z) {
  qm31 zero = {{0, 0}, {0, 0}};
  qm31 value = sub(zero, z);
  value = add(value, mul(relation, alphas[0]));
  value = add(value, mul(a, alphas[1]));
  value = add(value, mul(b, alphas[2]));
  return add(value, mul(x, alphas[3]));
}

struct BlakeGRelationSink {
  blake_shared_qm31 numerators;
  blake_shared_qm31 denominators;
  uint32_t row_index;
  const qm31 *alphas;
  qm31 z;
  qm31 pending;
  qm31 final_denominator;

  template <uint32_t Column>
  __device__ __forceinline__ void trace(uint32_t) {}

  template <uint32_t Column>
  __device__ __forceinline__ void auxiliary(uint32_t) {}

  template <uint32_t Tuple, uint32_t Relation>
  __device__ __forceinline__ void tuple(uint32_t a, uint32_t b, uint32_t x) {
    qm31 denominator = combine_xor(Relation, a, b, x, alphas, z);
    if constexpr ((Tuple & 1u) == 0u) {
      pending = denominator;
    } else {
      uint32_t index = row_index + (Tuple >> 1u);
      shared_store(numerators, index, add(pending, denominator));
      shared_store(denominators, index, mul(pending, denominator));
    }
  }

  template <uint32_t Lut, uint32_t Destination, uint32_t Bits,
            uint32_t Relation>
  __device__ __forceinline__ void count_lut(uint32_t, uint32_t) {}

  __device__ __forceinline__ void count_xor12(uint32_t, uint32_t) {}

  template <uint32_t Word>
  __device__ __forceinline__ void lookup(uint32_t value) {
    if constexpr (Word == 64u) {
      qm31 zero = {{0, 0}, {0, 0}};
      final_denominator = add(sub(zero, z), mul(value, alphas[0]));
    } else if constexpr (Word >= 65u && Word <= 84u) {
      final_denominator =
          add(final_denominator, mul(value, alphas[Word - 64u]));
    } else if constexpr (Word == 86u) {
      m31 negative_enabler = value == 0u ? 0u : P - value;
      shared_store(numerators, row_index + 8u,
                   qm31{{negative_enabler, 0}, {0, 0}});
      shared_store(denominators, row_index + 8u, final_denominator);
    }
  }
};

__device__ __forceinline__ void store_coordinates(m31 *const *outputs,
                                                    uint32_t column,
                                                    uint32_t row, qm31 value) {
  uint32_t base = 4u * column;
  outputs[base][row] = value.a.a;
  outputs[base + 1u][row] = value.a.b;
  outputs[base + 2u][row] = value.b.a;
  outputs[base + 3u][row] = value.b.b;
}

__global__ void relation_blake_g_inputs_kernel(
    const uint32_t *const *sources, uint32_t rows, uint32_t n_real,
    const qm31 *alphas, const qm31 *z_ptr, m31 *const *outputs) {
  extern __shared__ m31 shared_words[];
  blake_shared_qm31 numerators = {shared_words,
                                  RELATION_FUSED_ONE_READ_FRACTIONS};
  blake_shared_qm31 denominators = {
      shared_words + 4u * RELATION_FUSED_ONE_READ_FRACTIONS,
      RELATION_FUSED_ONE_READ_FRACTIONS};
  blake_shared_qm31 tree = {
      shared_words + 8u * RELATION_FUSED_ONE_READ_FRACTIONS,
      RELATION_FUSED_ONE_READ_TREE_NODES};
  const qm31 one = {{1, 0}, {0, 0}};
  uint32_t block_first_row = blockIdx.x * RELATION_LAUNCH_BLOCK;
  uint32_t block_last_row = block_first_row + RELATION_LAUNCH_BLOCK;
  block_last_row = block_last_row < rows ? block_last_row : rows;

  for (uint32_t tile_first_row = block_first_row;
       tile_first_row < block_last_row; tile_first_row += BLAKE_G_TILE_ROWS) {
    uint32_t active_rows = block_last_row - tile_first_row;
    active_rows = active_rows < BLAKE_G_TILE_ROWS ? active_rows
                                                  : BLAKE_G_TILE_ROWS;
    uint32_t active_fractions = active_rows * BLAKE_G_COLUMNS;
    shared_store(denominators, threadIdx.x, one);
    shared_store(denominators, threadIdx.x + blockDim.x, one);
    __syncthreads();

    if (threadIdx.x < active_rows) {
      uint32_t row = tile_first_row + threadIdx.x;
      BlakeGRelationSink sink = {numerators,
                                 denominators,
                                 threadIdx.x * BLAKE_G_COLUMNS,
                                 alphas,
                                 z_ptr[0],
                                 one,
                                 one};
      // These are the only row-sized source reads in the direct body.
      blake_g_evaluate_row(sources[0][row], sources[1][row], sources[2][row],
                           sources[3][row], sources[4][row], sources[5][row],
                           row, n_real, sink);
    }
    __syncthreads();

    batch_inverse(denominators, tree);
    for (uint32_t index = threadIdx.x; index < active_fractions;
         index += blockDim.x) {
      shared_store(numerators, index,
                   mul(shared_load(numerators, index),
                       shared_load(denominators, index)));
    }
    __syncthreads();

    blake_shared_qm31 scan_source = numerators;
    blake_shared_qm31 scan_destination = denominators;
    for (uint32_t offset = 1u; offset < BLAKE_G_COLUMNS; offset <<= 1u) {
      for (uint32_t index = threadIdx.x; index < active_fractions;
           index += blockDim.x) {
        uint32_t column = index % BLAKE_G_COLUMNS;
        qm31 value = shared_load(scan_source, index);
        if (column >= offset) {
          value = add(value, shared_load(scan_source, index - offset));
        }
        shared_store(scan_destination, index, value);
      }
      __syncthreads();
      blake_shared_qm31 swap = scan_source;
      scan_source = scan_destination;
      scan_destination = swap;
    }
    for (uint32_t index = threadIdx.x; index < active_fractions;
         index += blockDim.x) {
      uint32_t tile_row = index / BLAKE_G_COLUMNS;
      uint32_t column = index - tile_row * BLAKE_G_COLUMNS;
      store_coordinates(outputs, column, tile_first_row + tile_row,
                        shared_load(scan_source, index));
    }
    __syncthreads();
  }
}

}  // namespace

extern "C" int stwo_relation_blake_g_inputs_on(
    const uint32_t *const *sources, uint32_t n_sources, uint32_t rows,
    uint32_t n_real, const uint32_t *alpha_powers, uint32_t n_alpha_powers,
    const uint32_t *z, uint32_t *const *outputs, uint32_t n_outputs,
    void *stream_raw) {
  if (sources == nullptr || n_sources != BLAKE_G_INPUTS || rows == 0u ||
      n_real == 0u || n_real > rows || alpha_powers == nullptr ||
      n_alpha_powers < 21u || z == nullptr || outputs == nullptr ||
      n_outputs != BLAKE_G_COORDINATES || stream_raw == nullptr) {
    return static_cast<int>(cudaErrorInvalidValue);
  }
  cudaStream_t stream = reinterpret_cast<cudaStream_t>(stream_raw);
  uint32_t blocks = (rows + RELATION_LAUNCH_BLOCK - 1u) /
                    RELATION_LAUNCH_BLOCK;
  relation_blake_g_inputs_kernel<<<blocks, RELATION_LAUNCH_BLOCK,
                                   RELATION_FUSED_ONE_READ_SHARED_BYTES,
                                   stream>>>(
      sources, rows, n_real, reinterpret_cast<const qm31 *>(alpha_powers),
      reinterpret_cast<const qm31 *>(z),
      reinterpret_cast<m31 *const *>(outputs));
  return static_cast<int>(cudaGetLastError());
}
