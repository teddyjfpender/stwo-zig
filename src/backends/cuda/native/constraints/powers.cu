// Resident challenge-power expansion for Native constraint evaluation.

#include "field.cuh"

#include <stddef.h>
#include <stdint.h>

#if !defined(STWO_CUDA_HOST_TEST)
#include <cuda_runtime_api.h>
#endif

namespace stwo::cuda::constraints {

__host__ __device__ __forceinline__ void expand_powers(
    QM31 alpha,
    QM31 *output,
    uint32_t count,
    bool reversed = false) {
    QM31 current = one();
    for (uint32_t index = 0; index < count; ++index) {
        output[reversed ? count - 1u - index : index] = current;
        current = mul(current, alpha);
    }
}

#if !defined(STWO_CUDA_HOST_TEST)
__global__ void expand_powers_kernel(
    const QM31 *alpha,
    QM31 *output,
    uint32_t count,
    bool reversed) {
    if (blockIdx.x != 0 || threadIdx.x != 0) return;
    expand_powers(*alpha, output, count, reversed);
}
#endif

}  // namespace stwo::cuda::constraints

#if !defined(STWO_CUDA_HOST_TEST)
static int launch_powers(
    const stwo::cuda::constraints::QM31 *alpha,
    stwo::cuda::constraints::QM31 *output,
    size_t output_capacity,
    uint32_t count,
    void *stream,
    bool reversed) {
    if (alpha == nullptr || output == nullptr || stream == nullptr ||
        alpha == output || count == 0u ||
        output_capacity != static_cast<size_t>(count)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    stwo::cuda::constraints::expand_powers_kernel<<<
        1,
        1,
        0,
        static_cast<cudaStream_t>(stream)>>>(alpha, output, count, reversed);
    return static_cast<int>(cudaPeekAtLastError());
}
extern "C" int stwo_constraint_expand_powers_on(
    const stwo::cuda::constraints::QM31 *alpha,
    stwo::cuda::constraints::QM31 *output,
    size_t output_capacity, uint32_t count, void *stream) {
    return launch_powers(alpha, output, output_capacity, count, stream, false);
}

extern "C" int stwo_constraint_expand_reversed_powers_on(
    const stwo::cuda::constraints::QM31 *alpha,
    stwo::cuda::constraints::QM31 *output,
    size_t output_capacity, uint32_t count, void *stream) {
    return launch_powers(alpha, output, output_capacity, count, stream, true);
}
#endif
