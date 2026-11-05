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
