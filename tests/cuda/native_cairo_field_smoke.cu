// Native canonical AIR arithmetic against independent integer modular arithmetic.
// Compile with -DSTWO_AIR_PARITY_SOURCE='"/absolute/generated/kernel.cu"'.
#include <cuda_runtime.h>
#include <cstdio>
#include <vector>
#include STWO_AIR_PARITY_SOURCE

__global__ void field_arithmetic(const unsigned *a, const unsigned *b,
                                 unsigned *output, unsigned count) {
    const unsigned i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < count) {
        output[2 * i] = stwo_m31_add(a[i], b[i]);
        output[2 * i + 1] = stwo_m31_mul(a[i], b[i]);
    }
}

int main() {
    constexpr unsigned p = 2147483647;
    const unsigned edges[] = {0, 1, 2, 3, p / 2, p / 2 + 1, p - 3, p - 2, p - 1, p};
    std::vector<unsigned> a, b;
    for (const unsigned x : edges) for (const unsigned y : edges) {
        a.push_back(x);
        b.push_back(y);
    }
    unsigned long long seed = 8191;
    for (unsigned i = 0; i < 100000; ++i) {
        seed = seed * 6364136223846793005ull + 1;
        a.push_back((seed >> 32) & p);
        seed = seed * 6364136223846793005ull + 1;
        b.push_back((seed >> 32) & p);
    }
    unsigned *da = nullptr, *db = nullptr, *device_output = nullptr;
    const size_t bytes = a.size() * sizeof(unsigned);
    if (cudaMalloc(&da, bytes) != cudaSuccess ||
        cudaMalloc(&db, bytes) != cudaSuccess ||
        cudaMalloc(&device_output, 2 * bytes) != cudaSuccess ||
        cudaMemcpy(da, a.data(), bytes, cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemcpy(db, b.data(), bytes, cudaMemcpyHostToDevice) != cudaSuccess) return 1;
    field_arithmetic<<<(a.size() + 255) / 256, 256>>>(da, db, device_output, a.size());
    if (cudaDeviceSynchronize() != cudaSuccess) return 1;
    std::vector<unsigned> output(a.size() * 2);
    if (cudaMemcpy(output.data(), device_output, 2 * bytes, cudaMemcpyDeviceToHost) != cudaSuccess) return 1;
    for (size_t i = 0; i < a.size(); ++i) {
        const unsigned sum = (static_cast<unsigned long long>(a[i]) + b[i]) % p;
        const unsigned product = (static_cast<unsigned long long>(a[i]) * b[i]) % p;
        if (output[2 * i] != sum || output[2 * i + 1] != product) {
            std::fprintf(stderr, "FAIL: field vector %zu (%u, %u)\n", i, a[i], b[i]);
            return 2;
        }
    }
    if (cudaFree(da) != cudaSuccess || cudaFree(db) != cudaSuccess ||
        cudaFree(device_output) != cudaSuccess) return 1;
    std::printf("PASS: %zu independent modular add/multiply vectors\n", a.size());
    return 0;
}
