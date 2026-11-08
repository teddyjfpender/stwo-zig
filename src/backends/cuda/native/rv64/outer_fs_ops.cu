#include "outer_fs_ops.h"
#include "custody.cuh"
#include "om31.cuh"

namespace stwo::cuda::rv64 {
__global__ void outer_fs_lookup_params(const uint32_t* z_alpha, uint32_t* params,
                                        uint32_t* status) {
    const OM31 z = from_words(z_alpha), alpha = from_words(z_alpha + 8);
    if (!canonical(z) || !canonical(alpha)) {
        atomicOr(status, 1u);
        return;
    }
    store(params, 1, 0, z);
    OM31 power = one();
    for (uint32_t i = 0; i < 6; ++i) {
        store(params + 8 * (i + 1), 1, 0, power);
        power = mul(power, alpha);
    }
}

__global__ void outer_fs_powers(const uint32_t* alpha_words, uint64_t first,
                                 uint32_t count, uint32_t* powers,
                                 uint32_t* status) {
    const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= count) return;
    OM31 base = from_words(alpha_words);
    if (!canonical(base)) {
        if (i == 0) atomicOr(status, 1u);
        return;
    }
    uint64_t exponent = first + i;
    OM31 result = one();
    while (exponent) {
        if (exponent & 1u) result = mul(result, base);
        exponent >>= 1;
        if (exponent) base = mul(base, base);
    }
    store(powers + uint64_t(i) * 8, 1, 0, result);
}
}  // namespace stwo::cuda::rv64

extern "C" int stwo_rv64_outer_fs_lookup_params_on(void* context, uint32_t lane,
                                                  const uint32_t* z_alpha,
                                                  uint32_t* params,
                                                  uint32_t* status) {
    using namespace stwo::cuda::rv64;
    Custody custody(context, lane);
    if (!custody.range(z_alpha, 16, false) || !custody.range(params, 56, true) ||
        !custody.range(status, 1, true))
        return custody.status;
    outer_fs_lookup_params<<<1, 1, 0, custody.stream>>>(z_alpha, params, status);
    return int(cudaPeekAtLastError());
}

extern "C" int stwo_rv64_outer_fs_powers_on(void* context, uint32_t lane,
                                           const uint32_t* alpha,
                                           uint64_t first, uint32_t count,
                                           uint32_t* powers, uint32_t* status) {
    using namespace stwo::cuda::rv64;
    if (!count || count > (1u << 20) || first > UINT64_MAX - (uint64_t(count) - 1))
        return int(cudaErrorInvalidValue);
    Custody custody(context, lane);
    if (!custody.range(alpha, 8, false) ||
        !custody.range(powers, uint64_t(count) * 8, true) ||
        !custody.range(status, 1, true))
        return custody.status;
    outer_fs_powers<<<(count + 127) / 128, 128, 0, custody.stream>>>(
        alpha, first, count, powers, status);
    return int(cudaPeekAtLastError());
}
