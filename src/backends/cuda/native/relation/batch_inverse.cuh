#pragma once

#include "layout.cuh"

#include <cuda_runtime_api.h>

namespace stwo::cuda::relation {

cudaError_t batch_inverse_ragged_on(
    cudaStream_t stream,
    QM31 *const *slabs,
    const std::uint32_t *geometry,
    int instances,
    int total_blocks);

}  // namespace stwo::cuda::relation
