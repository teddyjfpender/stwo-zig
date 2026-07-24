#ifndef STWO_ZIG_CUDA_CONSTRAINTS_FIELD_CUH
#define STWO_ZIG_CUDA_CONSTRAINTS_FIELD_CUH

#include "../common/m31.cuh"

#include <stdint.h>

namespace stwo::cuda::constraints {

struct CM31 {
    M31 real;
    M31 imag;
};

struct QM31 {
    CM31 first;
    CM31 second;
};

static_assert(sizeof(QM31) == 4 * sizeof(uint32_t));
static_assert(alignof(QM31) == alignof(uint32_t));

__host__ __device__ __forceinline__ CM31 add(CM31 left, CM31 right) {
    return {
        m31_add(left.real, right.real),
        m31_add(left.imag, right.imag),
    };
}

__host__ __device__ __forceinline__ CM31 sub(CM31 left, CM31 right) {
    return {
        m31_sub(left.real, right.real),
        m31_sub(left.imag, right.imag),
    };
}

__host__ __device__ __forceinline__ CM31 mul(CM31 left, CM31 right) {
    return {
        m31_sub(
            m31_mul(left.real, right.real),
            m31_mul(left.imag, right.imag)),
        m31_add(
            m31_mul(left.real, right.imag),
            m31_mul(left.imag, right.real)),
    };
}

__host__ __device__ __forceinline__ QM31 one() {
    return {{1u, 0u}, {0u, 0u}};
}

__host__ __device__ __forceinline__ QM31 mul(QM31 left, QM31 right) {
    const CM31 product_0 = mul(left.first, right.first);
    const CM31 product_1 = mul(left.second, right.second);
    const CM31 product_sum =
        mul(add(left.first, left.second), add(right.first, right.second));
    const CM31 extension_product = {
        m31_sub(
            m31_add(product_1.real, product_1.real),
            product_1.imag),
        m31_add(
            product_1.real,
            m31_add(product_1.imag, product_1.imag)),
    };
    return {
        add(product_0, extension_product),
        sub(product_sum, add(product_0, product_1)),
    };
}

}  // namespace stwo::cuda::constraints

#endif
