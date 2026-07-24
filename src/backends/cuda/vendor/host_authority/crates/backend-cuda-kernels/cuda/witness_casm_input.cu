// Replacement-v1 opcode ingest: transpose canonical row-major Cairo states
// [pc, ap, fp] into the generated witness writer's stable input columns.
// Padding repeats row zero exactly like the host writer; enabler and optional
// iota are derived on device, so neither needs a host slab or H2D copy.
#include <cuda_runtime.h>
#include <cstdint>
#include <cstdio>

__global__ void witness_casm_input_scatter_kernel(
    const uint32_t *rows,
    uint32_t n_real,
    uint32_t consumer_rows,
    uint32_t *pc,
    uint32_t *ap,
    uint32_t *fp,
    uint32_t *enabler,
    uint32_t *iota
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= consumer_rows) {
        return;
    }
    uint32_t source_row = row < n_real ? row : 0;
    const uint32_t *state = rows + (size_t)source_row * 3;
    pc[row] = state[0];
    ap[row] = state[1];
    fp[row] = state[2];
    enabler[row] = row < n_real;
    if (iota != nullptr) {
        iota[row] = row;
    }
}

extern "C" int stwo_witness_casm_input_scatter_on(
    const uint32_t *rows_dev,
    uint32_t n_real,
    uint32_t consumer_rows,
    uint32_t *pc_dev,
    uint32_t *ap_dev,
    uint32_t *fp_dev,
    uint32_t *enabler_dev,
    uint32_t *iota_dev,
    void *stream_ptr
) {
    if (n_real == 0 || consumer_rows < 16 ||
        (consumer_rows & (consumer_rows - 1)) != 0 ||
        n_real > consumer_rows || rows_dev == nullptr ||
        pc_dev == nullptr || ap_dev == nullptr || fp_dev == nullptr ||
        enabler_dev == nullptr) {
        fprintf(stderr, "stwo_witness_casm_input_scatter_on: invalid geometry\n");
        return 1;
    }
    const uint32_t block = 256;
    uint32_t grid = static_cast<uint32_t>(
        (static_cast<uint64_t>(consumer_rows) + block - 1) / block);
    cudaStream_t stream = reinterpret_cast<cudaStream_t>(stream_ptr);
    witness_casm_input_scatter_kernel<<<grid, block, 0, stream>>>(
        rows_dev, n_real, consumer_rows, pc_dev, ap_dev, fp_dev,
        enabler_dev, iota_dev);
    if (cudaGetLastError() != cudaSuccess) {
        fprintf(stderr, "stwo_witness_casm_input_scatter_on: launch failed\n");
        return 1;
    }
    return 0;
}
