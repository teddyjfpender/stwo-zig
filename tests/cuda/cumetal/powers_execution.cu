#include <cuda_runtime.h>

#include <cstdint>
#include <cstdio>

#include "../../../src/backends/cuda/native/constraints/powers.cu"

namespace {

using DeviceQm31 = stwo::cuda::constraints::QM31;

struct Qm31 {
    std::uint32_t words[4];
};

constexpr std::uint64_t kPrime = 2147483647ull;

std::uint32_t add(std::uint32_t left, std::uint32_t right) {
    return static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(left) + right) % kPrime);
}

std::uint32_t sub(std::uint32_t left, std::uint32_t right) {
    return static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(left) + kPrime - right) % kPrime);
}

std::uint32_t mul(std::uint32_t left, std::uint32_t right) {
    return static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(left) * right) % kPrime);
}

void cmul(
    std::uint32_t left_real,
    std::uint32_t left_imag,
    std::uint32_t right_real,
    std::uint32_t right_imag,
    std::uint32_t* result_real,
    std::uint32_t* result_imag) {
    *result_real = sub(
        mul(left_real, right_real),
        mul(left_imag, right_imag));
    *result_imag = add(
        mul(left_real, right_imag),
        mul(left_imag, right_real));
}

Qm31 qm31_mul(Qm31 left, Qm31 right) {
    std::uint32_t product_0_real;
    std::uint32_t product_0_imag;
    std::uint32_t product_1_real;
    std::uint32_t product_1_imag;
    std::uint32_t product_sum_real;
    std::uint32_t product_sum_imag;
    cmul(
        left.words[0], left.words[1], right.words[0], right.words[1],
        &product_0_real, &product_0_imag);
    cmul(
        left.words[2], left.words[3], right.words[2], right.words[3],
        &product_1_real, &product_1_imag);
    cmul(
        add(left.words[0], left.words[2]),
        add(left.words[1], left.words[3]),
        add(right.words[0], right.words[2]),
        add(right.words[1], right.words[3]),
        &product_sum_real,
        &product_sum_imag);
    const std::uint32_t extension_real = sub(
        add(product_1_real, product_1_real),
        product_1_imag);
    const std::uint32_t extension_imag = add(
        product_1_real,
        add(product_1_imag, product_1_imag));
    return Qm31{{
        add(product_0_real, extension_real),
        add(product_0_imag, extension_imag),
        sub(
            product_sum_real,
            add(product_0_real, product_1_real)),
        sub(
            product_sum_imag,
            add(product_0_imag, product_1_imag)),
    }};
}

bool equal(Qm31 left, Qm31 right) {
    for (int index = 0; index < 4; ++index) {
        if (left.words[index] != right.words[index]) return false;
    }
    return true;
}

}  // namespace

int main() {
    constexpr std::uint32_t kCount = 32;
    const Qm31 alpha{{3u, 5u, 7u, 11u}};
    Qm31 observed[kCount]{};
    DeviceQm31* device_alpha = nullptr;
    DeviceQm31* device_output = nullptr;
    if (cudaMalloc(
            reinterpret_cast<void**>(&device_alpha),
            sizeof(DeviceQm31)) != cudaSuccess ||
        cudaMalloc(
            reinterpret_cast<void**>(&device_output),
            sizeof(DeviceQm31) * kCount) != cudaSuccess) {
        std::fprintf(stderr, "FAIL: CuMetal allocation failed\n");
        return 1;
    }
    if (cudaMemcpy(
            device_alpha,
            &alpha,
            sizeof(alpha),
            cudaMemcpyHostToDevice) != cudaSuccess) {
        std::fprintf(stderr, "FAIL: CuMetal alpha upload failed\n");
        return 1;
    }
    stwo::cuda::constraints::expand_powers_kernel<<<1, 1>>>(
        device_alpha,
        device_output,
        kCount);
    if (cudaDeviceSynchronize() != cudaSuccess ||
        cudaMemcpy(
            observed,
            device_output,
            sizeof(observed),
            cudaMemcpyDeviceToHost) != cudaSuccess) {
        std::fprintf(stderr, "FAIL: CuMetal powers launch failed\n");
        return 1;
    }
    Qm31 expected{{1u, 0u, 0u, 0u}};
    for (std::uint32_t index = 0; index < kCount; ++index) {
        if (!equal(observed[index], expected)) {
            std::fprintf(stderr, "FAIL: QM31 powers mismatch at %u\n", index);
            return 1;
        }
        expected = qm31_mul(expected, alpha);
    }
    if (cudaFree(device_alpha) != cudaSuccess ||
        cudaFree(device_output) != cudaSuccess) {
        std::fprintf(stderr, "FAIL: CuMetal free failed\n");
        return 1;
    }
    std::printf("PASS: QM31 powers match independent host oracle\n");
    return 0;
}
