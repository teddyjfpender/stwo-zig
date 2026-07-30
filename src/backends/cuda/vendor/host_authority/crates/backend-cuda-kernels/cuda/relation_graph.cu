// Allocation-free generated CommonLookupElements execution. Every pointer is
// caller-owned arena storage and every launch uses the explicit proof stream.

#include <cstddef>
#include <cstdint>
#include <cuda_runtime.h>

#include "batch_inverse.cuh"
#include "fields.cuh"
#include "prefix_sum.cuh"
// Tuple/combine/multiplicity semantics and the geometry binary search are
// shared with the fused lane (relation_fused.cu) through this header so the
// two lanes cannot drift.
#include "relation_fused.cuh"
// The coset scan-order bijection is shared with the decoupled-lookback tail
// (relation_scan.cu) through this header for the same reason.
#include "relation_scan.cuh"

namespace {

constexpr uint32_t BLOCK = RELATION_LAUNCH_BLOCK;
constexpr uint32_t DESC_WORDS = RELATION_DESC_WORDS;

// Expand the channel's exact LookupElements draw order `[z, alpha]` into the
// persistent relation slots consumed by every generated relation instance.
// One thread is intentional: at most 128 QM31 powers are produced and this
// launch sits on a serial Fiat-Shamir boundary.
__global__ void relation_expand_challenges_kernel(const qm31 *drawn,
                                                   qm31 *alpha_powers,
                                                   uint32_t n_alpha_powers,
                                                   qm31 *z) {
  if (blockIdx.x != 0u || threadIdx.x != 0u) {
    return;
  }
  z[0] = drawn[0];
  qm31 alpha = drawn[1];
  qm31 power = {{1, 0}, {0, 0}};
  for (uint32_t i = 0; i < n_alpha_powers; ++i) {
    alpha_powers[i] = power;
    power = mul(power, alpha);
  }
}

__device__ __forceinline__ void relation_pair_at(
    const uint32_t *const *sources, uint32_t n_rows, uint32_t row,
    uint32_t n_real, uint32_t source_offset_rows,
    const uint32_t *descriptors, uint32_t column, const qm31 *alphas, qm31 z,
    m31 *const *outputs, qm31 *denominators) {
  qm31 numerator;
  qm31 denominator;
  relation_column_fraction(sources, n_rows, row, n_real, source_offset_rows,
                           descriptors + column * DESC_WORDS, alphas, z,
                           &numerator, &denominator);
  uint32_t output_base = column * 4u;
  outputs[output_base][row] = numerator.a.a;
  outputs[output_base + 1u][row] = numerator.a.b;
  outputs[output_base + 2u][row] = numerator.b.a;
  outputs[output_base + 3u][row] = numerator.b.b;
  denominators[column * n_rows + row] = denominator;
}

__global__ void relation_pairs_kernel(const uint32_t *const *sources,
                                      uint32_t n_rows, uint32_t n_real,
                                      uint32_t source_offset_rows,
                                      const uint32_t *descriptors,
                                      const qm31 *alphas, const qm31 *z_ptr,
                                      m31 *const *outputs, qm31 *denominators) {
  uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
  uint32_t column = blockIdx.y;
  if (row >= n_rows) {
    return;
  }
  relation_pair_at(sources, n_rows, row, n_real, source_offset_rows,
                   descriptors, column, alphas, z_ptr[0], outputs,
                   denominators);
}

__global__ void relation_pairs_global_kernel(
    const uint32_t *const *const *source_tables,
    const uint32_t *const *descriptors, m31 *const *const *output_tables,
    qm31 *const *denominator_slabs, const uint32_t *geometry,
    uint32_t n_instances, const qm31 *alphas, const qm31 *z_ptr) {
  uint32_t local_block = 0u;
  uint32_t instance = relation_instance_for_block(
      geometry, n_instances, blockIdx.x, RELATION_PAIR_FIRST,
      RELATION_PAIR_BLOCKS, &local_block);
  if (instance == n_instances) {
    return;
  }
  const uint32_t *g = geometry + instance * RELATION_GEOMETRY_WORDS;
  uint32_t row_blocks = g[RELATION_ROW_BLOCKS];
  uint32_t column = local_block / row_blocks;
  uint32_t row_block = local_block - column * row_blocks;
  uint32_t row = row_block * BLOCK + threadIdx.x;
  if (row >= g[RELATION_ROWS]) {
    return;
  }
  relation_pair_at(
      source_tables[instance], g[RELATION_ROWS], row, g[RELATION_REAL_ROWS],
      g[RELATION_SOURCE_OFFSET], descriptors[instance], column, alphas, z_ptr[0],
      output_tables[instance], denominator_slabs[instance]);
}

__global__ void fraction_chain_batched_kernel(m31 *const *outputs,
                                              const qm31 *inverses,
                                              uint32_t n_rows,
                                              uint32_t n_columns) {
  uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
  if (row >= n_rows) {
    return;
  }
  qm31 accumulated = {{0, 0}, {0, 0}};
  for (uint32_t column = 0; column < n_columns; ++column) {
    uint32_t base = column * 4u;
    qm31 numerator = {{outputs[base][row], outputs[base + 1u][row]},
                      {outputs[base + 2u][row], outputs[base + 3u][row]}};
    accumulated = add(
        accumulated,
        mul(numerator, inverses[column * n_rows + row]));
    outputs[base][row] = accumulated.a.a;
    outputs[base + 1u][row] = accumulated.a.b;
    outputs[base + 2u][row] = accumulated.b.a;
    outputs[base + 3u][row] = accumulated.b.b;
  }
}

__global__ void fraction_chain_global_kernel(
    m31 *const *const *output_tables, const qm31 *const *inverses,
    const uint32_t *geometry, uint32_t n_instances) {
  uint32_t global_block = blockIdx.x;
  uint32_t lo = 0u;
  uint32_t hi = n_instances;
  while (lo < hi) {
    uint32_t mid = lo + (hi - lo) / 2u;
    if (geometry[mid * RELATION_GEOMETRY_WORDS + RELATION_ROW_FIRST] <=
        global_block) {
      lo = mid + 1u;
    } else {
      hi = mid;
    }
  }
  if (lo == 0u) {
    return;
  }
  uint32_t instance = lo - 1u;
  const uint32_t *g = geometry + instance * RELATION_GEOMETRY_WORDS;
  uint32_t local_block = global_block - g[RELATION_ROW_FIRST];
  if (local_block >= g[RELATION_ROW_BLOCKS]) {
    return;
  }
  uint32_t rows = g[RELATION_ROWS];
  uint32_t columns = g[RELATION_COLUMNS];
  uint32_t row = local_block * BLOCK + threadIdx.x;
  if (row >= rows) {
    return;
  }
  m31 *const *outputs = output_tables[instance];
  const qm31 *inverse = inverses[instance];
  qm31 accumulated = {{0, 0}, {0, 0}};
  for (uint32_t column = 0; column < columns; ++column) {
    uint32_t base = column * 4u;
    qm31 numerator = {{outputs[base][row], outputs[base + 1u][row]},
                      {outputs[base + 2u][row], outputs[base + 3u][row]}};
    accumulated =
        add(accumulated, mul(numerator, inverse[column * rows + row]));
    outputs[base][row] = accumulated.a.a;
    outputs[base + 1u][row] = accumulated.a.b;
    outputs[base + 2u][row] = accumulated.b.a;
    outputs[base + 3u][row] = accumulated.b.b;
  }
}

__global__ void reduce_coordinates_kernel(const m31 *c0, const m31 *c1,
                                          const m31 *c2, const m31 *c3,
                                          uint32_t n_rows, qm31 *partials) {
  extern __shared__ qm31 shared[];
  uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
  shared[threadIdx.x] = row < n_rows
                            ? qm31{{c0[row], c1[row]}, {c2[row], c3[row]}}
                            : qm31{{0, 0}, {0, 0}};
  __syncthreads();
  for (uint32_t stride = blockDim.x / 2u; stride != 0u; stride >>= 1u) {
    if (threadIdx.x < stride) {
      shared[threadIdx.x] =
          add(shared[threadIdx.x], shared[threadIdx.x + stride]);
    }
    __syncthreads();
  }
  if (threadIdx.x == 0u) {
    partials[blockIdx.x] = shared[0];
  }
}

__global__ void reduce_qm31_kernel(const qm31 *input, uint32_t size,
                                   qm31 *partials) {
  extern __shared__ qm31 shared[];
  uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
  shared[threadIdx.x] = index < size ? input[index] : qm31{{0, 0}, {0, 0}};
  __syncthreads();
  for (uint32_t stride = blockDim.x / 2u; stride != 0u; stride >>= 1u) {
    if (threadIdx.x < stride) {
      shared[threadIdx.x] =
          add(shared[threadIdx.x], shared[threadIdx.x + stride]);
    }
    __syncthreads();
  }
  if (threadIdx.x == 0u) {
    partials[blockIdx.x] = shared[0];
  }
}

__global__ void shift_last_column_kernel(m31 *c0, m31 *c1, m31 *c2, m31 *c3,
                                         uint32_t n_rows, const qm31 *sum,
                                         qm31 *claimed_sum, m31 inverse_rows) {
  uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
  if (row == 0u) {
    claimed_sum[0] = sum[0];
  }
  if (row >= n_rows) {
    return;
  }
  qm31 shift = mul(inverse_rows, sum[0]);
  c0[row] = sub(c0[row], shift.a.a);
  c1[row] = sub(c1[row], shift.a.b);
  c2[row] = sub(c2[row], shift.b.a);
  c3[row] = sub(c3[row], shift.b.b);
}

__global__ void reduce_coordinates_ragged_kernel(
    m31 *const *const *output_tables, const uint32_t *geometry,
    uint32_t n_instances, qm31 *partials) {
  uint32_t local_block = 0u;
  uint32_t instance = relation_instance_for_block(
      geometry, n_instances, blockIdx.x, RELATION_ROW_FIRST,
      RELATION_ROW_BLOCKS, &local_block);
  if (instance == n_instances) {
    return;
  }
  const uint32_t *g = geometry + instance * RELATION_GEOMETRY_WORDS;
  m31 *const *outputs = output_tables[instance];
  uint32_t last = (g[RELATION_COLUMNS] - 1u) * 4u;
  uint32_t row = local_block * BLOCK + threadIdx.x;
  extern __shared__ qm31 shared_qm31[];
  shared_qm31[threadIdx.x] =
      row < g[RELATION_ROWS]
          ? qm31{{outputs[last][row], outputs[last + 1u][row]},
                 {outputs[last + 2u][row], outputs[last + 3u][row]}}
          : qm31{{0, 0}, {0, 0}};
  __syncthreads();
  for (uint32_t stride = BLOCK / 2u; stride != 0u; stride >>= 1u) {
    if (threadIdx.x < stride) {
      shared_qm31[threadIdx.x] =
          add(shared_qm31[threadIdx.x], shared_qm31[threadIdx.x + stride]);
    }
    __syncthreads();
  }
  if (threadIdx.x == 0u) {
    partials[g[RELATION_ROW_FIRST] + local_block] = shared_qm31[0];
  }
}

__global__ void finalize_claimed_sums_ragged_kernel(
    qm31 *const *claimed_sums, const uint32_t *geometry,
    uint32_t n_instances, const qm31 *partials) {
  uint32_t instance = blockIdx.x;
  if (instance >= n_instances) {
    return;
  }
  const uint32_t *g = geometry + instance * RELATION_GEOMETRY_WORDS;
  uint32_t first = g[RELATION_ROW_FIRST];
  uint32_t count = g[RELATION_ROW_BLOCKS];
  qm31 accumulated = {{0, 0}, {0, 0}};
  for (uint32_t index = threadIdx.x; index < count; index += BLOCK) {
    accumulated = add(accumulated, partials[first + index]);
  }
  extern __shared__ qm31 shared_qm31[];
  shared_qm31[threadIdx.x] = accumulated;
  __syncthreads();
  for (uint32_t stride = BLOCK / 2u; stride != 0u; stride >>= 1u) {
    if (threadIdx.x < stride) {
      shared_qm31[threadIdx.x] =
          add(shared_qm31[threadIdx.x], shared_qm31[threadIdx.x + stride]);
    }
    __syncthreads();
  }
  if (threadIdx.x == 0u) {
    claimed_sums[instance][0] = shared_qm31[0];
  }
}

__device__ __forceinline__ uint32_t relation_scan_instance_for_block(
    const uint32_t *geometry, uint32_t n_instances, uint32_t global_block,
    uint32_t *local_block) {
  uint32_t lo = 0u;
  uint32_t hi = n_instances;
  while (lo < hi) {
    uint32_t mid = lo + (hi - lo) / 2u;
    const uint32_t *g = geometry + mid * RELATION_GEOMETRY_WORDS;
    if (g[RELATION_ROW_FIRST] * 4u <= global_block) {
      lo = mid + 1u;
    } else {
      hi = mid;
    }
  }
  if (lo == 0u) {
    return n_instances;
  }
  uint32_t instance = lo - 1u;
  const uint32_t *g = geometry + instance * RELATION_GEOMETRY_WORDS;
  *local_block = global_block - g[RELATION_ROW_FIRST] * 4u;
  return *local_block < g[RELATION_ROW_BLOCKS] * 4u ? instance : n_instances;
}

// The scan-order bijection `relation_coset_scan_row` lives in
// relation_scan.cuh, shared with the decoupled-lookback tail.

__global__ void shift_scan_tiles_ragged_kernel(
    m31 *const *const *output_tables, qm31 *const *claimed_sums,
    const uint32_t *geometry, uint32_t n_instances, m31 *block_sums) {
  uint32_t local_block = 0u;
  uint32_t instance = relation_scan_instance_for_block(
      geometry, n_instances, blockIdx.x, &local_block);
  if (instance == n_instances) {
    return;
  }
  const uint32_t *g = geometry + instance * RELATION_GEOMETRY_WORDS;
  uint32_t row_blocks = g[RELATION_ROW_BLOCKS];
  uint32_t coordinate = local_block / row_blocks;
  uint32_t row_block = local_block - coordinate * row_blocks;
  uint32_t scan_index = row_block * BLOCK + threadIdx.x;
  m31 *output =
      output_tables[instance][(g[RELATION_COLUMNS] - 1u) * 4u + coordinate];
  qm31 sum = claimed_sums[instance][0];
  m31 sum_coordinate = coordinate == 0u   ? sum.a.a
                       : coordinate == 1u ? sum.a.b
                       : coordinate == 2u ? sum.b.a
                                          : sum.b.b;
  m31 shift = mul(g[RELATION_INVERSE_ROWS], sum_coordinate);
  extern __shared__ m31 shared_m31[];
  shared_m31[threadIdx.x] =
      scan_index < g[RELATION_ROWS]
          ? sub(output[relation_coset_scan_row(scan_index, g[RELATION_ROWS])],
                shift)
          : 0u;
  __syncthreads();
  for (uint32_t offset = 1u; offset < BLOCK; offset <<= 1u) {
    m31 value = shared_m31[threadIdx.x];
    if (threadIdx.x >= offset) {
      value = add(value, shared_m31[threadIdx.x - offset]);
    }
    __syncthreads();
    shared_m31[threadIdx.x] = value;
    __syncthreads();
  }
  if (scan_index < g[RELATION_ROWS]) {
    output[relation_coset_scan_row(scan_index, g[RELATION_ROWS])] =
        shared_m31[threadIdx.x];
  }
  uint32_t valid = g[RELATION_ROWS] - row_block * BLOCK;
  valid = valid < BLOCK ? valid : BLOCK;
  if (threadIdx.x + 1u == valid) {
    block_sums[blockIdx.x] = shared_m31[threadIdx.x];
  }
}

__global__ void scan_block_totals_ragged_kernel(
    m31 *block_sums, const uint32_t *geometry, uint32_t n_instances) {
  uint32_t segment = blockIdx.x;
  uint32_t instance = segment / 4u;
  uint32_t coordinate = segment % 4u;
  if (instance >= n_instances) {
    return;
  }
  const uint32_t *g = geometry + instance * RELATION_GEOMETRY_WORDS;
  uint32_t count = g[RELATION_ROW_BLOCKS];
  uint32_t first = g[RELATION_ROW_FIRST] * 4u + coordinate * count;
  __shared__ m31 shared_m31[BLOCK];
  __shared__ m31 carry;
  if (threadIdx.x == 0u) {
    carry = 0u;
  }
  __syncthreads();
  for (uint32_t chunk = 0u; chunk < count; chunk += BLOCK) {
    uint32_t remaining = count - chunk;
    uint32_t valid = remaining < BLOCK ? remaining : BLOCK;
    shared_m31[threadIdx.x] = threadIdx.x < valid
                                   ? block_sums[first + chunk + threadIdx.x]
                                   : 0u;
    __syncthreads();
    for (uint32_t offset = 1u; offset < BLOCK; offset <<= 1u) {
      m31 value = shared_m31[threadIdx.x];
      if (threadIdx.x >= offset) {
        value = add(value, shared_m31[threadIdx.x - offset]);
      }
      __syncthreads();
      shared_m31[threadIdx.x] = value;
      __syncthreads();
    }
    m31 base = carry;
    // Every warp snapshots the segment carry before the last valid thread may
    // publish the next chunk's carry.
    __syncthreads();
    if (threadIdx.x < valid) {
      m31 total = add(shared_m31[threadIdx.x], base);
      block_sums[first + chunk + threadIdx.x] = total;
      if (threadIdx.x + 1u == valid) {
        carry = total;
      }
    }
    __syncthreads();
  }
}

__global__ void add_scan_offsets_ragged_kernel(
    m31 *const *const *output_tables, const uint32_t *geometry,
    uint32_t n_instances, const m31 *block_sums) {
  uint32_t local_block = 0u;
  uint32_t instance = relation_scan_instance_for_block(
      geometry, n_instances, blockIdx.x, &local_block);
  if (instance == n_instances) {
    return;
  }
  const uint32_t *g = geometry + instance * RELATION_GEOMETRY_WORDS;
  uint32_t row_blocks = g[RELATION_ROW_BLOCKS];
  uint32_t coordinate = local_block / row_blocks;
  uint32_t row_block = local_block - coordinate * row_blocks;
  if (row_block == 0u) {
    return;
  }
  uint32_t scan_index = row_block * BLOCK + threadIdx.x;
  if (scan_index >= g[RELATION_ROWS]) {
    return;
  }
  uint32_t row = relation_coset_scan_row(scan_index, g[RELATION_ROWS]);
  m31 *output =
      output_tables[instance][(g[RELATION_COLUMNS] - 1u) * 4u + coordinate];
  output[row] = add(output[row], block_sums[blockIdx.x - 1u]);
}

} // namespace

extern "C" int stwo_relation_expand_challenges_on(
    const uint32_t *drawn_z_alpha, uint32_t *alpha_powers,
    uint32_t n_alpha_powers, uint32_t *z, void *stream_raw) {
  if (drawn_z_alpha == nullptr || alpha_powers == nullptr || z == nullptr ||
      n_alpha_powers == 0u) {
    return (int)cudaErrorInvalidValue;
  }
  cudaStream_t stream = reinterpret_cast<cudaStream_t>(stream_raw);
  relation_expand_challenges_kernel<<<1, 1, 0, stream>>>(
      reinterpret_cast<const qm31 *>(drawn_z_alpha),
      reinterpret_cast<qm31 *>(alpha_powers), n_alpha_powers,
      reinterpret_cast<qm31 *>(z));
  return (int)cudaGetLastError();
}

extern "C" int stwo_relation_pairs_on(
    const uint32_t *const *sources, uint32_t n_sources, uint32_t n_rows,
    uint32_t n_real, uint32_t source_offset_rows, const uint32_t *descriptors,
    uint32_t n_columns, const uint32_t *alpha_powers, uint32_t n_alpha_powers,
    const uint32_t *z, uint32_t *const *outputs, uint32_t *denominators,
    void *stream_raw) {
  if (n_sources == 0u || n_rows == 0u || n_real > n_rows || n_columns == 0u ||
      n_alpha_powers == 0u) {
    return (int)cudaErrorInvalidValue;
  }
  cudaStream_t stream = reinterpret_cast<cudaStream_t>(stream_raw);
  dim3 grid((n_rows + BLOCK - 1u) / BLOCK, n_columns);
  relation_pairs_kernel<<<grid, BLOCK, 0, stream>>>(
      sources, n_rows, n_real, source_offset_rows, descriptors,
      reinterpret_cast<const qm31 *>(alpha_powers),
      reinterpret_cast<const qm31 *>(z),
      reinterpret_cast<m31 *const *>(outputs),
      reinterpret_cast<qm31 *>(denominators));
  return (int)cudaGetLastError();
}

extern "C" int stwo_relation_pairs_global_on(
    const uint32_t *const *const *source_tables,
    const uint32_t *const *descriptors, uint32_t *const *const *output_tables,
    uint32_t *const *denominator_slabs, const uint32_t *geometry,
    uint32_t n_instances, uint32_t total_pair_blocks,
    const uint32_t *alpha_powers, uint32_t n_alpha_powers, const uint32_t *z,
    void *stream_raw) {
  if (source_tables == nullptr || descriptors == nullptr ||
      output_tables == nullptr || denominator_slabs == nullptr ||
      geometry == nullptr || n_instances == 0u || total_pair_blocks == 0u ||
      alpha_powers == nullptr || n_alpha_powers == 0u || z == nullptr ||
      stream_raw == nullptr) {
    return (int)cudaErrorInvalidValue;
  }
  cudaStream_t stream = reinterpret_cast<cudaStream_t>(stream_raw);
  relation_pairs_global_kernel<<<total_pair_blocks, BLOCK, 0, stream>>>(
      source_tables, descriptors,
      reinterpret_cast<m31 *const *const *>(output_tables),
      reinterpret_cast<qm31 *const *>(denominator_slabs), geometry, n_instances,
      reinterpret_cast<const qm31 *>(alpha_powers),
      reinterpret_cast<const qm31 *>(z));
  return (int)cudaGetLastError();
}

extern "C" int stwo_relation_fraction_chain_on(uint32_t *const *outputs,
                                               uint32_t *denominators,
                                               uint32_t *inverse_scratch,
                                               uint32_t n_rows,
                                               uint32_t n_columns,
                                               void *stream_raw) {
  if (outputs == nullptr || denominators == nullptr ||
      inverse_scratch == nullptr || n_rows == 0u || n_columns == 0u ||
      static_cast<uint64_t>(n_rows) * n_columns > 0x7fffffffu) {
    return (int)cudaErrorInvalidValue;
  }
  cudaStream_t stream = reinterpret_cast<cudaStream_t>(stream_raw);
  // The arena ABI still carries the old one-column scratch slot. Keep validating
  // it until that public plan is revised, but invert the private denominator slab
  // in place so every column can be submitted in one capture-safe launch.
  (void)inverse_scratch;
  qm31 *inverse = reinterpret_cast<qm31 *>(denominators);
  cudaError_t error = batch_inverse_secure_field_columns_on(
      stream, inverse, inverse, (int)n_rows, (int)n_columns);
  if (error != cudaSuccess) {
    return (int)error;
  }
  uint32_t blocks = (n_rows + BLOCK - 1u) / BLOCK;
  fraction_chain_batched_kernel<<<blocks, BLOCK, 0, stream>>>(
      reinterpret_cast<m31 *const *>(outputs), inverse, n_rows, n_columns);
  return (int)cudaGetLastError();
}

extern "C" int stwo_relation_fraction_chain_global_on(
    uint32_t *const *const *output_tables, uint32_t *const *denominator_slabs,
    const uint32_t *geometry, uint32_t n_instances,
    uint32_t total_inverse_blocks, uint32_t total_chain_blocks,
    void *stream_raw) {
  if (output_tables == nullptr || denominator_slabs == nullptr ||
      geometry == nullptr || n_instances == 0u || total_inverse_blocks == 0u ||
      total_chain_blocks == 0u || total_inverse_blocks > 0x7fffffffu ||
      total_chain_blocks > 0x7fffffffu) {
    return (int)cudaErrorInvalidValue;
  }
  cudaStream_t stream = reinterpret_cast<cudaStream_t>(stream_raw);
  cudaError_t error = batch_inverse_secure_field_ragged_on(
      stream, reinterpret_cast<qm31 *const *>(denominator_slabs), geometry,
      static_cast<int>(n_instances), static_cast<int>(total_inverse_blocks));
  if (error != cudaSuccess) {
    return (int)error;
  }
  fraction_chain_global_kernel<<<total_chain_blocks, BLOCK, 0, stream>>>(
      reinterpret_cast<m31 *const *const *>(output_tables),
      reinterpret_cast<const qm31 *const *>(denominator_slabs), geometry,
      n_instances);
  return (int)cudaGetLastError();
}

extern "C" int stwo_relation_reduce_shift_on(
    uint32_t *output_0, uint32_t *output_1, uint32_t *output_2,
    uint32_t *output_3, uint32_t n_rows, uint32_t *reduction_a,
    uint32_t *reduction_b, uint32_t reduction_capacity, uint32_t *claimed_sum,
    uint32_t inverse_rows, void *stream_raw) {
  if (n_rows == 0u || reduction_capacity == 0u) {
    return (int)cudaErrorInvalidValue;
  }
  cudaStream_t stream = reinterpret_cast<cudaStream_t>(stream_raw);
  qm31 *a = reinterpret_cast<qm31 *>(reduction_a);
  qm31 *b = reinterpret_cast<qm31 *>(reduction_b);
  uint32_t size = (n_rows + BLOCK - 1u) / BLOCK;
  if (size > reduction_capacity) {
    return (int)cudaErrorInvalidValue;
  }
  reduce_coordinates_kernel<<<size, BLOCK, BLOCK * sizeof(qm31), stream>>>(
      output_0, output_1, output_2, output_3, n_rows, a);
  cudaError_t error = cudaGetLastError();
  if (error != cudaSuccess) {
    return (int)error;
  }
  qm31 *current = a;
  qm31 *next = b;
  while (size > 1u) {
    uint32_t next_size = (size + BLOCK - 1u) / BLOCK;
    reduce_qm31_kernel<<<next_size, BLOCK, BLOCK * sizeof(qm31), stream>>>(
        current, size, next);
    error = cudaGetLastError();
    if (error != cudaSuccess) {
      return (int)error;
    }
    qm31 *swap = current;
    current = next;
    next = swap;
    size = next_size;
  }
  uint32_t blocks = (n_rows + BLOCK - 1u) / BLOCK;
  shift_last_column_kernel<<<blocks, BLOCK, 0, stream>>>(
      output_0, output_1, output_2, output_3, n_rows, current,
      reinterpret_cast<qm31 *>(claimed_sum), inverse_rows);
  return (int)cudaGetLastError();
}

extern "C" int stwo_relation_prefix_scan_on(uint32_t *output, uint32_t n_rows,
                                            uint32_t *eval_scratch,
                                            void *scan_temp,
                                            size_t scan_temp_bytes,
                                            void *stream_raw) {
  if (n_rows == 0u) {
    return (int)cudaErrorInvalidValue;
  }
  cudaStream_t stream = reinterpret_cast<cudaStream_t>(stream_raw);
  return (int)inclusive_prefix_sum_prepared_on(
      stream, output, eval_scratch, scan_temp, scan_temp_bytes, n_rows);
}

extern "C" int stwo_relation_tail_global_on(
    uint32_t *const *const *output_tables, uint32_t *const *claimed_sums,
    const uint32_t *geometry, uint32_t n_instances,
    uint32_t total_row_blocks, uint32_t *reduction_partials,
    uint32_t reduction_capacity, uint32_t *scan_block_sums,
    uint32_t scan_capacity, void *stream_raw) {
  if (output_tables == nullptr || claimed_sums == nullptr ||
      geometry == nullptr || n_instances == 0u || total_row_blocks == 0u ||
      n_instances > 0xffffffffu / 4u ||
      reduction_partials == nullptr || reduction_capacity < total_row_blocks ||
      scan_block_sums == nullptr || total_row_blocks > 0xffffffffu / 4u ||
      scan_capacity < total_row_blocks * 4u || stream_raw == nullptr) {
    return (int)cudaErrorInvalidValue;
  }
  cudaStream_t stream = reinterpret_cast<cudaStream_t>(stream_raw);
  auto outputs = reinterpret_cast<m31 *const *const *>(output_tables);
  auto sums = reinterpret_cast<qm31 *const *>(claimed_sums);
  auto partials = reinterpret_cast<qm31 *>(reduction_partials);
  uint32_t total_scan_blocks = total_row_blocks * 4u;

  reduce_coordinates_ragged_kernel<<<total_row_blocks, BLOCK,
                                     BLOCK * sizeof(qm31), stream>>>(
      outputs, geometry, n_instances, partials);
  cudaError_t error = cudaGetLastError();
  if (error != cudaSuccess) {
    return (int)error;
  }
  finalize_claimed_sums_ragged_kernel<<<n_instances, BLOCK,
                                        BLOCK * sizeof(qm31), stream>>>(
      sums, geometry, n_instances, partials);
  error = cudaGetLastError();
  if (error != cudaSuccess) {
    return (int)error;
  }
  shift_scan_tiles_ragged_kernel<<<total_scan_blocks, BLOCK,
                                   BLOCK * sizeof(m31), stream>>>(
      outputs, sums, geometry, n_instances, scan_block_sums);
  error = cudaGetLastError();
  if (error != cudaSuccess) {
    return (int)error;
  }
  scan_block_totals_ragged_kernel<<<n_instances * 4u, BLOCK, 0, stream>>>(
      scan_block_sums, geometry, n_instances);
  error = cudaGetLastError();
  if (error != cudaSuccess) {
    return (int)error;
  }
  add_scan_offsets_ragged_kernel<<<total_scan_blocks, BLOCK, 0, stream>>>(
      outputs, geometry, n_instances, scan_block_sums);
  return (int)cudaGetLastError();
}
