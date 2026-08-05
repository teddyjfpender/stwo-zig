// Capture-safe fixed-table witness materialization.
//
// Every input and output address is supplied through a device-resident pointer
// table prepared before capture. One cell is one word-major (column, row)
// output, so the same launch covers BaseTrace copies and flattened
// LookupInputs without temporary storage.
#include <cuda_runtime.h>
#include <cstdint>
#include <cstdio>

#define FTM_DESC_STRIDE 4u
#define FTM_CONSTANT 0u
#define FTM_SOURCE_COLUMN 1u
#define FTM_MULTIPLICITY_COLUMN 2u
#define FTM_EXPANDED_XOR_A 3u
#define FTM_EXPANDED_XOR_B 4u
#define FTM_EXPANDED_XOR 5u

__device__ __forceinline__ uint32_t fixed_table_lookup_value(
    const uint32_t *descriptor,
    uint32_t row,
    const uint32_t *const *source_columns,
    const uint32_t *const *multiplicity_columns
) {
    const uint32_t kind = descriptor[0];
    const uint32_t value_or_column = descriptor[1];
    if (kind == FTM_CONSTANT) {
        return value_or_column;
    }
    if (kind == FTM_SOURCE_COLUMN) {
        return source_columns[value_or_column][row];
    }
    if (kind == FTM_MULTIPLICITY_COLUMN) {
        return multiplicity_columns[value_or_column][row];
    }

    const uint32_t limb_bits = descriptor[2];
    const uint32_t expand_bits = descriptor[3];
    const uint32_t expand_mask = (1u << expand_bits) - 1u;
    const uint32_t limb_mask = (1u << limb_bits) - 1u;
    const uint32_t a =
        (value_or_column >> expand_bits) * (1u << limb_bits) + (row >> limb_bits);
    const uint32_t b =
        (value_or_column & expand_mask) * (1u << limb_bits) + (row & limb_mask);
    if (kind == FTM_EXPANDED_XOR_A) {
        return a;
    }
    if (kind == FTM_EXPANDED_XOR_B) {
        return b;
    }
    return a ^ b;
}

__global__ void fixed_table_materialize_kernel(
    const uint32_t *const *source_columns,
    const uint32_t *const *multiplicity_columns,
    const uint32_t *trace_multiplicity_columns,
    uint32_t *const *trace_outputs,
    uint32_t n_trace_outputs,
    const uint32_t *lookup_descriptors,
    uint32_t *const *lookup_outputs,
    uint32_t n_lookup_outputs,
    uint32_t row_count
) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t output = blockIdx.y;
    if (row >= row_count) {
        return;
    }
    if (output < n_trace_outputs) {
        trace_outputs[output][row] =
            multiplicity_columns[trace_multiplicity_columns[output]][row];
        return;
    }

    const uint32_t lookup_output = output - n_trace_outputs;
    lookup_outputs[lookup_output][row] = fixed_table_lookup_value(
        lookup_descriptors + (size_t)lookup_output * FTM_DESC_STRIDE,
        row,
        source_columns,
        multiplicity_columns);
}

extern "C" int stwo_fixed_table_materialize_on(
    const uint32_t *const *source_columns_dev,
    const uint32_t *const *multiplicity_columns_dev,
    const uint32_t *trace_multiplicity_columns_dev,
    uint32_t *const *trace_outputs_dev,
    uint32_t n_trace_outputs,
    const uint32_t *lookup_descriptors_dev,
    uint32_t *const *lookup_outputs_dev,
    uint32_t n_lookup_outputs,
    uint32_t row_count,
    void *stream
) {
    if (multiplicity_columns_dev == nullptr ||
        trace_multiplicity_columns_dev == nullptr || trace_outputs_dev == nullptr ||
        lookup_descriptors_dev == nullptr || lookup_outputs_dev == nullptr ||
        n_trace_outputs == 0 || n_lookup_outputs == 0 || row_count == 0 ||
        n_lookup_outputs > 65535u ||
        n_trace_outputs > 65535u - n_lookup_outputs) {
        return 1;
    }
    const uint32_t block = 256;
    const dim3 grid(
        1u + (row_count - 1u) / block,
        n_trace_outputs + n_lookup_outputs);
    fixed_table_materialize_kernel<<<grid, block, 0, (cudaStream_t)stream>>>(
        source_columns_dev,
        multiplicity_columns_dev,
        trace_multiplicity_columns_dev,
        trace_outputs_dev,
        n_trace_outputs,
        lookup_descriptors_dev,
        lookup_outputs_dev,
        n_lookup_outputs,
        row_count);
    if (cudaGetLastError() != cudaSuccess) {
        fprintf(stderr, "stwo_fixed_table_materialize_on: launch failed\n");
        return 1;
    }
    return 0;
}
