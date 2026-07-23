// Fused relation pipeline: one kernel, one proof-wide launch, replacing the
// 3-stage `relation_pairs_global` -> `batch_inverse_secure_field_ragged` ->
// `fraction_chain_global` sequence for every fused-eligible instance. The
// denominator slab is never materialized. Tuples of at most 32 words use the
// proven suffix/recompute lane below. Wider tuples use a one-read shared-memory
// lane: every (numerator, denominator) is produced once, a 512-leaf Montgomery
// tree inverts a bounded row tile with one root inverse, and a segmented scan
// writes the canonical chain directly. Admitted 513..1024-column batches retain
// the suffix/recompute lane because host eligibility bounds them to 32-word
// tuples. The instance's
// `denominators` binding is a one-word aligned sentinel in a mode-sealed fused
// preparation, and the proof-wide `inverse_scratch` slot stays allocated but
// untouched. Neither is passed to or dereferenced by this kernel.
//
// Suffix/recompute path, per thread (= one row of one instance), with C = columns:
//   1. Backward pass c = C-1..0: recompute (num_c, d_c); stage
//      `num_c * suffix_c` (suffix_c = prod_{j>c} d_j) into output column c;
//      accumulate `suffix = prod d_j`.
//   2. ONE inversion: `running = inv(prod d_j)`.
//   3. Forward pass c = 0..C-1: recompute d_c (denominator only); now
//      `running = 1 / prod_{j>=c} d_j`, so
//      `staged_c * running = num_c * prod_{j>c} d_j / prod_{j>=c} d_j
//                          = num_c / d_c`;
//      accumulate and overwrite output column c with the partial-fraction
//      chain value, then `running *= d_c`.
//
// One-read path, per CTA (= one existing 256-row geometry block):
//   1. Choose floor(512 / C) rows (bounded by the block's remaining rows).
//   2. Compute every fraction once into a conflict-free coordinate-major SoA;
//      pad the remaining denominator leaves with one.
//   3. Build one complete product tree, invert only its root, and peel exact
//      leaf inverses back into the denominator SoA.
//   4. Multiply numerators by those inverses, then run a double-buffered
//      segmented inclusive scan in canonical column order and write each final
//      output exactly once. The denominator plane becomes the scan's alternate
//      buffer after its inverses have been consumed.
//
// The shared footprint is exact and shape-independent:
//   (512 numerators + 512 denominators + 511 tree nodes) * 16 B = 24,560 B.
// Each coordinate plane is contiguous, so a warp's same-coordinate accesses
// map one word per bank instead of the four-way conflicts of QM31 AoS storage.
// Excluding tuple-source and descriptor reads, the 3-stage path moves
// 112 HBM bytes/fraction: pair writes 32 B, inverse reads+writes 32 B, and
// chain reads 32 B then writes 16 B. This lane writes only the final 16 B:
// 96 B/fraction (85.7%) of intermediate traffic and all three global staging
// passes disappear. Compared with the suffix/recompute path's 48 logical
// bytes/fraction, it retires the second source walk and 32 logical body bytes.
// The old 1024-leaf ragged inverse deliberately stops at 32
// independent 32-leaf subtree roots and executes 32 inversions/partition; a
// full one-read tile executes one/512 fractions, a 16x lower inversion density.
// Relative to blindly widening the narrow lane, this also avoids the second
// tuple/denominator source walk and changes one inverse per row into one inverse
// per <=512-fraction row tile. Partial final tiles retain exactly one inverse.
//
// Resource gate: the last qualified adaptive sm_90 source used 80
// registers/thread, a 32 B stack, zero spills, this same 24,560 B dynamic
// shared reservation, and one 4 B static dispatch word. Its
// register/stack/occupancy envelope remains uncredited until a fresh ptxas
// receipt is captured for this exact source.
//
// Byte identity with the 3-stage lane: M31/QM31 arithmetic is exact modular
// arithmetic through the same canonical-form primitives (fields.cu), so the
// committed value at column c — the exact field element
// sum_{j<=c} num_j * d_j^{-1} — has one canonical word encoding regardless of
// how the inverses are materialized (per-element `inv`, 1024-leaf Montgomery
// tree, or this single-inversion peel). Zero denominators are outside the
// contract in both lanes (the SIMD reference asserts them away). Parity is
// gated by prepared_relation_native.rs (eager/captured/mutated-replay).
//
// Dispatch reuses the immutable 11-word geometry records and the
// RELATION_ROW_FIRST/RELATION_ROW_BLOCKS row-tile layout that
// fraction_chain_global_kernel already binary-searches; instances whose bit
// is clear in the by-value eligibility mask are skipped here and executed by
// the host on the existing per-instance 3-stage path.

#include <cstddef>
#include <cstdint>
#include <cuda_runtime.h>

#include "relation_fused.cuh"
#include "resource_attestation.cuh"

namespace {

struct relation_shared_qm31 {
  m31 *words;
  uint32_t stride;
};

__device__ __forceinline__ qm31 shared_load(relation_shared_qm31 slab,
                                            uint32_t index) {
  return {{slab.words[index], slab.words[slab.stride + index]},
          {slab.words[2u * slab.stride + index],
           slab.words[3u * slab.stride + index]}};
}

__device__ __forceinline__ void shared_store(relation_shared_qm31 slab,
                                             uint32_t index, qm31 value) {
  slab.words[index] = value.a.a;
  slab.words[slab.stride + index] = value.a.b;
  slab.words[2u * slab.stride + index] = value.b.a;
  slab.words[3u * slab.stride + index] = value.b.b;
}

__device__ __forceinline__ bool relation_qm31_is_zero(qm31 value) {
  return value.a.a == 0u && value.a.b == 0u && value.b.a == 0u &&
         value.b.b == 0u;
}

__device__ __forceinline__ void relation_reject_zero_denominator(qm31 product) {
  // A zero denominator is outside the LogUp contract. Returning zero inverses
  // would let stale output survive a captured replay, so make the CUDA launch
  // fail closed instead. In a field, a zero product is equivalent to at least
  // one zero denominator; padded wide-lane leaves are one.
  if (relation_qm31_is_zero(product)) {
    asm volatile("trap;");
  }
}

__device__ __forceinline__ bool relation_descriptors_need_one_read(
    const uint32_t *descriptors, uint32_t columns) {
  for (uint32_t column = 0; column < columns; ++column) {
    const uint32_t *descriptor =
        descriptors + column * RELATION_DESC_WORDS;
    if (descriptor[1u + 2u] > RELATION_FUSED_NARROW_MAX_TUPLE_WORDS) {
      return true;
    }
    if (descriptor[0] == 2u &&
        descriptor[1u + RELATION_USE_WORDS + 2u] >
            RELATION_FUSED_NARROW_MAX_TUPLE_WORDS) {
      return true;
    }
  }
  return false;
}

// Invert 512 shared leaves with one root inversion. Active fractions occupy
// the prefix and every padded leaf is one, so the tree is exact for arbitrary
// row_tile * columns <= 512. The tree layout is level-contiguous: 256 parents
// at offset 0 through the root at offset 510. During the reverse walk each
// child product is overwritten by its inverse; the final leaves therefore
// become the denominator-inverse plane in place.
__device__ __forceinline__ void relation_one_read_batch_inverse(
    relation_shared_qm31 leaves, relation_shared_qm31 tree) {
  uint32_t child_count = RELATION_FUSED_ONE_READ_FRACTIONS;
  relation_shared_qm31 children = leaves;
  uint32_t tree_offset = 0u;
  while (child_count > 1u) {
    uint32_t parent_count = child_count >> 1u;
    relation_shared_qm31 parents = {tree.words + tree_offset, tree.stride};
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
    relation_reject_zero_denominator(root);
    shared_store(children, 0u, inv(root));
  }
  __syncthreads();

  uint32_t parent_count = 1u;
  while (parent_count < RELATION_FUSED_ONE_READ_FRACTIONS) {
    uint32_t parent_offset =
        RELATION_FUSED_ONE_READ_FRACTIONS - (parent_count << 1u);
    relation_shared_qm31 parents = {tree.words + parent_offset, tree.stride};
    uint32_t next_count = parent_count << 1u;
    relation_shared_qm31 next =
        next_count == RELATION_FUSED_ONE_READ_FRACTIONS
            ? leaves
            : relation_shared_qm31{
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

__device__ __forceinline__ void store_coordinates(m31 *const *outputs,
                                                  uint32_t column, uint32_t row,
                                                  qm31 value) {
  uint32_t base = column * 4u;
  outputs[base][row] = value.a.a;
  outputs[base + 1u][row] = value.a.b;
  outputs[base + 2u][row] = value.b.a;
  outputs[base + 3u][row] = value.b.b;
}

__device__ __forceinline__ void relation_fused_narrow_row(
    const uint32_t *const *sources, uint32_t rows, uint32_t row,
    uint32_t columns, uint32_t n_real, uint32_t source_offset_rows,
    const uint32_t *instance_descriptors, const qm31 *alphas, qm31 z,
    m31 *const *outputs) {
  qm31 suffix = {{1, 0}, {0, 0}};
  for (uint32_t column = columns; column-- > 0u;) {
    qm31 numerator;
    qm31 denominator;
    relation_column_fraction(sources, rows, row, n_real, source_offset_rows,
                             instance_descriptors +
                                 column * RELATION_DESC_WORDS,
                             alphas, z, &numerator, &denominator);
    store_coordinates(outputs, column, row, mul(numerator, suffix));
    suffix = mul(suffix, denominator);
  }

  relation_reject_zero_denominator(suffix);
  qm31 running = inv(suffix);
  qm31 accumulated = {{0, 0}, {0, 0}};
  for (uint32_t column = 0; column < columns; ++column) {
    qm31 denominator = relation_column_denominator(
        sources, rows, row, source_offset_rows,
        instance_descriptors + column * RELATION_DESC_WORDS, alphas, z);
    uint32_t base = column * 4u;
    qm31 staged = {{outputs[base][row], outputs[base + 1u][row]},
                   {outputs[base + 2u][row], outputs[base + 3u][row]}};
    accumulated = add(accumulated, mul(staged, running));
    store_coordinates(outputs, column, row, accumulated);
    running = mul(running, denominator);
  }
}

__device__ __forceinline__ void relation_fused_one_read_block(
    const uint32_t *const *sources, uint32_t rows, uint32_t block_first_row,
    uint32_t columns, uint32_t n_real, uint32_t source_offset_rows,
    const uint32_t *instance_descriptors, const qm31 *alphas, qm31 z,
    m31 *const *outputs, m31 *shared_words) {
  // Host eligibility and immutable geometry prove this range. Keep a device
  // guard as well: a future ABI drift must fault instead of dividing by zero
  // or creating a row tile that cannot hold one complete canonical chain.
  if (columns == 0u || columns > RELATION_FUSED_ONE_READ_FRACTIONS) {
    asm volatile("trap;");
    return;
  }
  relation_shared_qm31 numerators = {shared_words,
                                     RELATION_FUSED_ONE_READ_FRACTIONS};
  relation_shared_qm31 denominators = {
      shared_words + 4u * RELATION_FUSED_ONE_READ_FRACTIONS,
      RELATION_FUSED_ONE_READ_FRACTIONS};
  relation_shared_qm31 tree = {
      shared_words + 8u * RELATION_FUSED_ONE_READ_FRACTIONS,
      RELATION_FUSED_ONE_READ_TREE_NODES};
  const qm31 one = {{1, 0}, {0, 0}};
  uint32_t tile_rows = RELATION_FUSED_ONE_READ_FRACTIONS / columns;
  tile_rows = tile_rows < RELATION_LAUNCH_BLOCK ? tile_rows
                                                : RELATION_LAUNCH_BLOCK;
  uint32_t block_last_row = block_first_row + RELATION_LAUNCH_BLOCK;
  block_last_row = block_last_row < rows ? block_last_row : rows;

  for (uint32_t tile_first_row = block_first_row;
       tile_first_row < block_last_row; tile_first_row += tile_rows) {
    uint32_t active_rows = block_last_row - tile_first_row;
    active_rows = active_rows < tile_rows ? active_rows : tile_rows;
    uint32_t active_fractions = active_rows * columns;

    // Two leaves per thread cover the exact fixed 512-leaf tree.
    shared_store(denominators, threadIdx.x, one);
    shared_store(denominators, threadIdx.x + blockDim.x, one);
    __syncthreads();

    // Produce in column-major work order so adjacent lanes share a descriptor
    // and read adjacent source rows. Store into row-major shared indices for
    // the later canonical segmented scan. On the widest generated shape this
    // turns a warp from 32 unrelated source columns into contiguous 3-row
    // groups without sacrificing active threads.
    for (uint32_t work = threadIdx.x; work < active_fractions;
         work += blockDim.x) {
      uint32_t column = work / active_rows;
      uint32_t tile_row = work - column * active_rows;
      uint32_t index = tile_row * columns + column;
      qm31 numerator;
      qm31 denominator;
      relation_column_fraction(
          sources, rows, tile_first_row + tile_row, n_real,
          source_offset_rows,
          instance_descriptors + column * RELATION_DESC_WORDS, alphas, z,
          &numerator, &denominator);
      shared_store(numerators, index, numerator);
      shared_store(denominators, index, denominator);
    }
    __syncthreads();

    relation_one_read_batch_inverse(denominators, tree);
    for (uint32_t index = threadIdx.x; index < active_fractions;
         index += blockDim.x) {
      shared_store(numerators, index,
                   mul(shared_load(numerators, index),
                       shared_load(denominators, index)));
    }
    __syncthreads();

    // Exact field addition is associative, so this segmented parallel scan has
    // the same canonical value at every column as the left-to-right LogUp
    // chain. Source and destination alternate only after a CTA-wide fence.
    relation_shared_qm31 scan_source = numerators;
    relation_shared_qm31 scan_destination = denominators;
    for (uint32_t offset = 1u; offset < columns; offset <<= 1u) {
      for (uint32_t index = threadIdx.x; index < active_fractions;
           index += blockDim.x) {
        uint32_t column = index % columns;
        qm31 value = shared_load(scan_source, index);
        if (column >= offset) {
          value = add(value, shared_load(scan_source, index - offset));
        }
        shared_store(scan_destination, index, value);
      }
      __syncthreads();
      relation_shared_qm31 swap = scan_source;
      scan_source = scan_destination;
      scan_destination = swap;
    }

    for (uint32_t index = threadIdx.x; index < active_fractions;
         index += blockDim.x) {
      uint32_t tile_row = index / columns;
      uint32_t column = index - tile_row * columns;
      store_coordinates(outputs, column, tile_first_row + tile_row,
                        shared_load(scan_source, index));
    }
    __syncthreads();
  }
}

__global__ void relation_fused_kernel(
    const uint32_t *const *const *source_tables,
    const uint32_t *const *descriptors, m31 *const *const *output_tables,
    const uint32_t *geometry, uint32_t n_instances, const qm31 *alphas,
    const qm31 *z_ptr, relation_fused_mask mask) {
  uint32_t local_block = 0u;
  uint32_t instance = relation_instance_for_block(
      geometry, n_instances, blockIdx.x, RELATION_ROW_FIRST,
      RELATION_ROW_BLOCKS, &local_block);
  if (instance == n_instances || !relation_fused_mask_test(mask, instance)) {
    return;
  }
  const uint32_t *g = geometry + instance * RELATION_GEOMETRY_WORDS;
  uint32_t rows = g[RELATION_ROWS];
  uint32_t block_first_row = local_block * RELATION_LAUNCH_BLOCK;
  uint32_t columns = g[RELATION_COLUMNS];
  uint32_t n_real = g[RELATION_REAL_ROWS];
  uint32_t source_offset_rows = g[RELATION_SOURCE_OFFSET];
  const uint32_t *const *sources = source_tables[instance];
  const uint32_t *instance_descriptors = descriptors[instance];
  m31 *const *outputs = output_tables[instance];
  qm31 z = z_ptr[0];
  extern __shared__ m31 shared_words[];
  __shared__ uint32_t one_read_lane;
  if (threadIdx.x == 0u) {
    one_read_lane =
        relation_descriptors_need_one_read(instance_descriptors, columns);
  }
  __syncthreads();
  if (one_read_lane != 0u) {
    relation_fused_one_read_block(
        sources, rows, block_first_row, columns, n_real, source_offset_rows,
        instance_descriptors, alphas, z, outputs, shared_words);
    return;
  }
  uint32_t row = block_first_row + threadIdx.x;
  if (row < rows) {
    relation_fused_narrow_row(sources, rows, row, columns, n_real,
                              source_offset_rows, instance_descriptors, alphas,
                              z, outputs);
  }
}

// Test-only control for the pre-adaptive selector. It deliberately duplicates
// the old kernel dispatch instead of adding selector control flow or arguments
// to relation_fused_kernel. The receipt still queries both loaded functions;
// neither source shape receives timing credit without those exact facts.
__global__ void relation_fused_all_one_read_test_kernel(
    const uint32_t *const *const *source_tables,
    const uint32_t *const *descriptors, m31 *const *const *output_tables,
    const uint32_t *geometry, uint32_t n_instances, const qm31 *alphas,
    const qm31 *z_ptr, relation_fused_mask mask) {
  uint32_t local_block = 0u;
  uint32_t instance = relation_instance_for_block(
      geometry, n_instances, blockIdx.x, RELATION_ROW_FIRST,
      RELATION_ROW_BLOCKS, &local_block);
  if (instance == n_instances || !relation_fused_mask_test(mask, instance)) {
    return;
  }
  const uint32_t *g = geometry + instance * RELATION_GEOMETRY_WORDS;
  uint32_t rows = g[RELATION_ROWS];
  uint32_t block_first_row = local_block * RELATION_LAUNCH_BLOCK;
  uint32_t columns = g[RELATION_COLUMNS];
  uint32_t n_real = g[RELATION_REAL_ROWS];
  uint32_t source_offset_rows = g[RELATION_SOURCE_OFFSET];
  const uint32_t *const *sources = source_tables[instance];
  const uint32_t *instance_descriptors = descriptors[instance];
  m31 *const *outputs = output_tables[instance];
  qm31 z = z_ptr[0];
  extern __shared__ m31 shared_words[];
  if (columns <= RELATION_FUSED_ONE_READ_FRACTIONS) {
    relation_fused_one_read_block(
        sources, rows, block_first_row, columns, n_real, source_offset_rows,
        instance_descriptors, alphas, z, outputs, shared_words);
    return;
  }
  uint32_t row = block_first_row + threadIdx.x;
  if (row < rows) {
    relation_fused_narrow_row(sources, rows, row, columns, n_real,
                              source_offset_rows, instance_descriptors, alphas,
                              z, outputs);
  }
}

} // namespace

extern "C" int stwo_relation_fused_on(
    const uint32_t *const *const *source_tables,
    const uint32_t *const *descriptors, uint32_t *const *const *output_tables,
    const uint32_t *geometry, uint32_t n_instances, uint32_t total_row_blocks,
    const uint32_t *alpha_powers, uint32_t n_alpha_powers, const uint32_t *z,
    const uint32_t *eligible_mask_words, void *stream_raw) {
  if (source_tables == nullptr || descriptors == nullptr ||
      output_tables == nullptr || geometry == nullptr || n_instances == 0u ||
      n_instances > RELATION_FUSED_MAX_INSTANCES || total_row_blocks == 0u ||
      total_row_blocks > 0x7fffffffu || alpha_powers == nullptr ||
      n_alpha_powers == 0u || z == nullptr || eligible_mask_words == nullptr ||
      stream_raw == nullptr) {
    return (int)cudaErrorInvalidValue;
  }
  // Host-side mask words are copied into the by-value kernel parameter here,
  // before launch/capture; nothing device-resident carries eligibility.
  relation_fused_mask mask;
  for (uint32_t word = 0; word < RELATION_FUSED_MASK_WORDS; ++word) {
    mask.bits[word] = eligible_mask_words[word];
  }
  cudaStream_t stream = reinterpret_cast<cudaStream_t>(stream_raw);
  relation_fused_kernel<<<total_row_blocks, RELATION_LAUNCH_BLOCK,
                          RELATION_FUSED_ONE_READ_SHARED_BYTES, stream>>>(
      source_tables, descriptors,
      reinterpret_cast<m31 *const *const *>(output_tables), geometry,
      n_instances, reinterpret_cast<const qm31 *>(alpha_powers),
      reinterpret_cast<const qm31 *>(z), mask);
  return (int)cudaGetLastError();
}

extern "C" int stwo_relation_fused_all_one_read_test_on(
    const uint32_t *const *const *source_tables,
    const uint32_t *const *descriptors, uint32_t *const *const *output_tables,
    const uint32_t *geometry, uint32_t n_instances, uint32_t total_row_blocks,
    const uint32_t *alpha_powers, uint32_t n_alpha_powers, const uint32_t *z,
    const uint32_t *eligible_mask_words, void *stream_raw) {
  if (source_tables == nullptr || descriptors == nullptr ||
      output_tables == nullptr || geometry == nullptr || n_instances == 0u ||
      n_instances > RELATION_FUSED_MAX_INSTANCES || total_row_blocks == 0u ||
      total_row_blocks > 0x7fffffffu || alpha_powers == nullptr ||
      n_alpha_powers == 0u || z == nullptr || eligible_mask_words == nullptr ||
      stream_raw == nullptr) {
    return (int)cudaErrorInvalidValue;
  }
  relation_fused_mask mask;
  for (uint32_t word = 0; word < RELATION_FUSED_MASK_WORDS; ++word) {
    mask.bits[word] = eligible_mask_words[word];
  }
  cudaStream_t stream = reinterpret_cast<cudaStream_t>(stream_raw);
  relation_fused_all_one_read_test_kernel
      <<<total_row_blocks, RELATION_LAUNCH_BLOCK,
         RELATION_FUSED_ONE_READ_SHARED_BYTES, stream>>>(
          source_tables, descriptors,
          reinterpret_cast<m31 *const *const *>(output_tables), geometry,
          n_instances, reinterpret_cast<const qm31 *>(alpha_powers),
          reinterpret_cast<const qm31 *>(z), mask);
  return (int)cudaGetLastError();
}

extern "C" int stwo_relation_fused_test_function_attributes(
    uint32_t strategy, StwoCudaFunctionAttributes *out) {
  switch (strategy) {
  case 0u:
    return (int)stwo_cuda_function_attributes(relation_fused_kernel, out);
  case 1u:
    return (int)stwo_cuda_function_attributes(
        relation_fused_all_one_read_test_kernel, out);
  default:
    return (int)cudaErrorInvalidValue;
  }
}
