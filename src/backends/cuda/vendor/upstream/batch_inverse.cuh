#ifndef BATCH_INVERSE_H
#define BATCH_INVERSE_H

#include <cuda_runtime.h>
#include "fields.cuh"

// Shared immutable per-instance ABI for the proof-wide relation launches:
// [pair_first, pair_blocks, inverse_first, inverse_blocks, row_first,
//  row_blocks, rows, columns, n_real, source_offset_rows, inverse_rows].
constexpr uint32_t RELATION_GEOMETRY_WORDS = 11;
constexpr uint32_t RELATION_PAIR_FIRST = 0;
constexpr uint32_t RELATION_PAIR_BLOCKS = 1;
constexpr uint32_t RELATION_INVERSE_FIRST = 2;
constexpr uint32_t RELATION_INVERSE_BLOCKS = 3;
constexpr uint32_t RELATION_ROW_FIRST = 4;
constexpr uint32_t RELATION_ROW_BLOCKS = 5;
constexpr uint32_t RELATION_ROWS = 6;
constexpr uint32_t RELATION_COLUMNS = 7;
constexpr uint32_t RELATION_REAL_ROWS = 8;
constexpr uint32_t RELATION_SOURCE_OFFSET = 9;
constexpr uint32_t RELATION_INVERSE_ROWS = 10;

extern "C"
void batch_inverse_base_field(m31 *from, m31 *dst, int size);

extern "C"
void batch_inverse_secure_field(qm31 *from, qm31 *dst, int size);

// Allocation/sync/default-stream-free body for prepared graph execution.
cudaError_t batch_inverse_secure_field_on(
    cudaStream_t stream, qm31 *from, qm31 *dst, int size);

// Invert `columns` contiguous, equal-length columns in one launch. For the
// power-of-two prepared-relation rows this preserves the exact 1024-element
// Montgomery-tree partition used by one call per column.
cudaError_t batch_inverse_secure_field_columns_on(
    cudaStream_t stream, qm31 *from, qm31 *dst, int rows, int columns);

// One launch across heterogeneous relation denominator slabs. See the shared
// geometry ABI in batch_inverse.cu.
cudaError_t batch_inverse_secure_field_ragged_on(
    cudaStream_t stream, qm31 *const *slabs, const uint32_t *geometry,
    int instances, int total_blocks);

#endif // BATCH_INVERSE_H
