// Single-pass relation tail: one decoupled-lookback (Merrill-Garland) scan
// over every instance's committed cumsum column, plus one shift fixup.
//
// Replaces the 5-kernel segmented tail (`stwo_relation_tail_global_on`) with
//   memset(partition descriptors) -> scan kernel -> shift-fixup kernel
// behind `STWO_CUDA_RELATION_SCAN_TAIL=1` (relation_graph.rs).
//
// Element semantics are IDENTICAL to the segmented tail:
//   * The scanned sequence is the instance's LAST interaction column, read as
//     one QM31 (4 coordinate columns) per element, in the coset scan order of
//     `relation_coset_scan_row` (relation_scan.cuh) — the same bijection the
//     segmented tiles gather/scatter through.
//   * The scan is INCLUSIVE. The scan kernel writes the UNSHIFTED inclusive
//     prefix P_i in place and the instance's claimed_sum (the inclusive total
//     over all rows, exactly what `finalize_claimed_sums_ragged_kernel`
//     reduces) into the same claimed-sum slot the transcript D2D reads.
//   * The fixup kernel then rewrites every element as
//     `P_i - (i+1) * (inverse_rows * claimed_sum)`, with `inverse_rows` the
//     host-computed M31 inverse from geometry word RELATION_INVERSE_ROWS —
//     the same per-coordinate `mul(inverse_rows, sum)` shift the segmented
//     `shift_scan_tiles_ragged_kernel` subtracts per element.
// Byte identity: every M31/QM31 primitive (fields.cu) is an exact mod-p map
// returning the canonical representative, so the algebraically equal
// regrouping `sum_{j<=i} (x_j - s) = P_i - (i+1)*s` produces the identical
// canonical words. Gated by prepared_relation_native.rs against the host
// reference and the segmented lane.
//
// Ragged dispatch: tiles are the RELATION_ROW_FIRST/RELATION_ROW_BLOCKS row
// blocks already used by the fused/chain kernels; the lookback chain of a
// tile never crosses its instance's first tile (which publishes its inclusive
// prefix immediately, with identity exclusive prefix). Blocks acquire their
// tile through a ticket counter (descriptor word 0) so tile order matches
// hardware scheduling order and the lookback spin cannot deadlock.

#include <cstddef>
#include <cstdint>
#include <cuda_runtime.h>

#include "relation_fused.cuh"
#include "relation_scan.cuh"

namespace {

constexpr uint32_t BLOCK = RELATION_LAUNCH_BLOCK;
constexpr uint32_t WARP = 32;

__device__ __forceinline__ void relation_scan_store_qm31(
    volatile uint32_t *words, qm31 value) {
  words[0] = value.a.a;
  words[1] = value.a.b;
  words[2] = value.b.a;
  words[3] = value.b.b;
}

__device__ __forceinline__ qm31 relation_scan_load_qm31(
    const volatile uint32_t *words) {
  return qm31{{words[0], words[1]}, {words[2], words[3]}};
}

// Lane 0 receives the exact modular sum of all 32 lane values (order of
// association is irrelevant: field addition is exact and canonical).
__device__ __forceinline__ qm31 relation_scan_warp_total(qm31 value) {
  for (uint32_t offset = WARP / 2u; offset != 0u; offset >>= 1u) {
    qm31 other;
    other.a.a = __shfl_down_sync(0xffffffffu, value.a.a, offset);
    other.a.b = __shfl_down_sync(0xffffffffu, value.a.b, offset);
    other.b.a = __shfl_down_sync(0xffffffffu, value.b.a, offset);
    other.b.b = __shfl_down_sync(0xffffffffu, value.b.b, offset);
    value = add(value, other);
  }
  return value;
}

// Warp-parallel decoupled lookback over the predecessor tiles
// [first_tile, tile). Executed by the block's first warp; only lane 0's
// return value is meaningful. Lanes whose probe falls below `first_tile`
// report a synthetic identity PREFIX, so the walk terminates at the instance
// boundary and chains never cross instances.
__device__ qm31 relation_scan_lookback(volatile uint32_t *descriptors,
                                       uint32_t tile, uint32_t first_tile) {
  const uint32_t lane = threadIdx.x;
  qm31 exclusive = {{0, 0}, {0, 0}};
  uint32_t window_end = tile; // inspect predecessors [window_end - 32, window_end)
  for (;;) {
    uint32_t flag = RELATION_SCAN_FLAG_PREFIX;
    qm31 contribution = {{0, 0}, {0, 0}};
    // Invariant: window_end > first_tile (established below).
    if (lane < window_end - first_tile) {
      uint32_t look = window_end - 1u - lane;
      volatile uint32_t *desc =
          descriptors + RELATION_SCAN_TICKET_WORDS +
          look * RELATION_SCAN_DESC_STRIDE;
      flag = desc[RELATION_SCAN_DESC_FLAG];
      if (flag == RELATION_SCAN_FLAG_PREFIX) {
        contribution = relation_scan_load_qm31(desc + RELATION_SCAN_DESC_PREFIX);
      } else if (flag == RELATION_SCAN_FLAG_AGGREGATE) {
        contribution =
            relation_scan_load_qm31(desc + RELATION_SCAN_DESC_AGGREGATE);
      }
    }
    uint32_t prefix_mask =
        __ballot_sync(0xffffffffu, flag == RELATION_SCAN_FLAG_PREFIX);
    uint32_t missing_mask =
        __ballot_sync(0xffffffffu, flag == RELATION_SCAN_FLAG_NONE);
    if (prefix_mask != 0u) {
      // Lane numbering walks backwards: lane 0 is the closest predecessor,
      // so the lowest prefix lane is the first prefix on the walk.
      uint32_t nearest = __ffs(prefix_mask) - 1u;
      if ((missing_mask & ((1u << nearest) - 1u)) == 0u) {
        qm31 lane_value =
            lane <= nearest ? contribution : qm31{{0, 0}, {0, 0}};
        exclusive = add(exclusive, relation_scan_warp_total(lane_value));
        return exclusive;
      }
    } else if (missing_mask == 0u) {
      // A full window of aggregates. The instance's first tile only ever
      // publishes PREFIX, so none of these lanes was first_tile and the
      // invariant window_end - 32 > first_tile holds.
      exclusive = add(exclusive, relation_scan_warp_total(contribution));
      window_end -= WARP;
      continue;
    }
#if __CUDA_ARCH__ >= 700
    __nanosleep(64);
#endif
  }
}

__global__ void relation_scan_ragged_kernel(
    m31 *const *const *output_tables, qm31 *const *claimed_sums,
    const uint32_t *geometry, uint32_t n_instances, uint32_t *descriptors) {
  __shared__ uint32_t shared_tile;
  __shared__ qm31 shared_scan[BLOCK];
  __shared__ qm31 shared_exclusive;
  if (threadIdx.x == 0u) {
    // Ticket: tiles are processed in hardware scheduling order, making the
    // lookback spin below deadlock-free even on oversubscribed grids.
    shared_tile = atomicAdd(descriptors, 1u);
  }
  __syncthreads();
  uint32_t tile = shared_tile;
  uint32_t local_tile = 0u;
  uint32_t instance = relation_instance_for_block(
      geometry, n_instances, tile, RELATION_ROW_FIRST, RELATION_ROW_BLOCKS,
      &local_tile);
  if (instance == n_instances) {
    return;
  }
  const uint32_t *g = geometry + instance * RELATION_GEOMETRY_WORDS;
  uint32_t rows = g[RELATION_ROWS];
  uint32_t first_tile = g[RELATION_ROW_FIRST];
  m31 *const *outputs = output_tables[instance];
  uint32_t last = (g[RELATION_COLUMNS] - 1u) * 4u;
  uint32_t scan_index = local_tile * BLOCK + threadIdx.x;
  uint32_t row = 0u;
  qm31 value = {{0, 0}, {0, 0}};
  if (scan_index < rows) {
    row = relation_coset_scan_row(scan_index, rows);
    value = qm31{{outputs[last][row], outputs[last + 1u][row]},
                 {outputs[last + 2u][row], outputs[last + 3u][row]}};
  }

  // Tile-local inclusive scan; padded lanes carry the additive identity, so
  // shared_scan[BLOCK - 1] is the tile aggregate for partial tiles too.
  shared_scan[threadIdx.x] = value;
  __syncthreads();
  for (uint32_t offset = 1u; offset < BLOCK; offset <<= 1u) {
    qm31 scanned = shared_scan[threadIdx.x];
    if (threadIdx.x >= offset) {
      scanned = add(scanned, shared_scan[threadIdx.x - offset]);
    }
    __syncthreads();
    shared_scan[threadIdx.x] = scanned;
    __syncthreads();
  }
  qm31 aggregate = shared_scan[BLOCK - 1u];

  volatile uint32_t *desc = descriptors + RELATION_SCAN_TICKET_WORDS +
                            tile * RELATION_SCAN_DESC_STRIDE;
  if (tile == first_tile) {
    if (threadIdx.x == 0u) {
      relation_scan_store_qm31(desc + RELATION_SCAN_DESC_AGGREGATE, aggregate);
      relation_scan_store_qm31(desc + RELATION_SCAN_DESC_PREFIX, aggregate);
      __threadfence();
      desc[RELATION_SCAN_DESC_FLAG] = RELATION_SCAN_FLAG_PREFIX;
      shared_exclusive = qm31{{0, 0}, {0, 0}};
    }
  } else {
    if (threadIdx.x == 0u) {
      relation_scan_store_qm31(desc + RELATION_SCAN_DESC_AGGREGATE, aggregate);
      __threadfence();
      desc[RELATION_SCAN_DESC_FLAG] = RELATION_SCAN_FLAG_AGGREGATE;
    }
    if (threadIdx.x < WARP) {
      qm31 exclusive = relation_scan_lookback(descriptors, tile, first_tile);
      if (threadIdx.x == 0u) {
        relation_scan_store_qm31(desc + RELATION_SCAN_DESC_PREFIX,
                                 add(exclusive, aggregate));
        __threadfence();
        desc[RELATION_SCAN_DESC_FLAG] = RELATION_SCAN_FLAG_PREFIX;
        shared_exclusive = exclusive;
      }
    }
  }
  __syncthreads();

  if (scan_index < rows) {
    qm31 inclusive = add(shared_exclusive, shared_scan[threadIdx.x]);
    outputs[last][row] = inclusive.a.a;
    outputs[last + 1u][row] = inclusive.a.b;
    outputs[last + 2u][row] = inclusive.b.a;
    outputs[last + 3u][row] = inclusive.b.b;
  }
  // The instance's inclusive total IS the claimed sum, written to the same
  // slot the segmented finalize kernel fills and the transcript D2D reads.
  if (threadIdx.x == 0u && local_tile + 1u == g[RELATION_ROW_BLOCKS]) {
    claimed_sums[instance][0] = add(shared_exclusive, aggregate);
  }
}

// Rewrite the unshifted inclusive prefix P_i as P_i - (i+1) * shift, with
// shift = inverse_rows * claimed_sum per coordinate — exactly the element
// shift the segmented tail applies before its scan. `scan_index + 1 <= rows
// < P`, so the factor is a canonical M31 scalar.
__global__ void relation_scan_shift_ragged_kernel(
    m31 *const *const *output_tables, qm31 *const *claimed_sums,
    const uint32_t *geometry, uint32_t n_instances) {
  uint32_t local_tile = 0u;
  uint32_t instance = relation_instance_for_block(
      geometry, n_instances, blockIdx.x, RELATION_ROW_FIRST,
      RELATION_ROW_BLOCKS, &local_tile);
  if (instance == n_instances) {
    return;
  }
  const uint32_t *g = geometry + instance * RELATION_GEOMETRY_WORDS;
  uint32_t rows = g[RELATION_ROWS];
  uint32_t scan_index = local_tile * BLOCK + threadIdx.x;
  if (scan_index >= rows) {
    return;
  }
  m31 *const *outputs = output_tables[instance];
  uint32_t last = (g[RELATION_COLUMNS] - 1u) * 4u;
  qm31 shift = mul(g[RELATION_INVERSE_ROWS], claimed_sums[instance][0]);
  uint32_t row = relation_coset_scan_row(scan_index, rows);
  qm31 value = {{outputs[last][row], outputs[last + 1u][row]},
                {outputs[last + 2u][row], outputs[last + 3u][row]}};
  qm31 shifted = sub(value, mul((m31)(scan_index + 1u), shift));
  outputs[last][row] = shifted.a.a;
  outputs[last + 1u][row] = shifted.a.b;
  outputs[last + 2u][row] = shifted.b.a;
  outputs[last + 3u][row] = shifted.b.b;
}

} // namespace

extern "C" int stwo_relation_scan_tail_on(
    uint32_t *const *const *output_tables, uint32_t *const *claimed_sums,
    const uint32_t *geometry, uint32_t n_instances, uint32_t total_row_blocks,
    uint32_t *partition_descriptors, uint32_t descriptor_capacity_words,
    void *stream_raw) {
  if (output_tables == nullptr || claimed_sums == nullptr ||
      geometry == nullptr || n_instances == 0u || total_row_blocks == 0u ||
      total_row_blocks > 0x7fffffffu || partition_descriptors == nullptr ||
      stream_raw == nullptr) {
    return (int)cudaErrorInvalidValue;
  }
  uint64_t required_words =
      (uint64_t)RELATION_SCAN_TICKET_WORDS +
      (uint64_t)total_row_blocks * RELATION_SCAN_DESC_STRIDE;
  if (required_words > descriptor_capacity_words) {
    return (int)cudaErrorInvalidValue;
  }
  cudaStream_t stream = reinterpret_cast<cudaStream_t>(stream_raw);
  auto outputs = reinterpret_cast<m31 *const *const *>(output_tables);
  auto sums = reinterpret_cast<qm31 *const *>(claimed_sums);
  // Reset ticket + partition flags. A memset is capture-safe: it becomes a
  // memset node replayed before the scan on every graph launch.
  cudaError_t error = cudaMemsetAsync(
      partition_descriptors, 0, (size_t)required_words * sizeof(uint32_t),
      stream);
  if (error != cudaSuccess) {
    return (int)error;
  }
  relation_scan_ragged_kernel<<<total_row_blocks, BLOCK, 0, stream>>>(
      outputs, sums, geometry, n_instances, partition_descriptors);
  error = cudaGetLastError();
  if (error != cudaSuccess) {
    return (int)error;
  }
  relation_scan_shift_ragged_kernel<<<total_row_blocks, BLOCK, 0, stream>>>(
      outputs, sums, geometry, n_instances);
  return (int)cudaGetLastError();
}
