// The caller supplies an authenticated generated witness TU and a fixture
// header made with Python's independent integer arithmetic modulo Stark's prime.
#include <cuda_runtime.h>
#include <cstdio>
#include STWO_CANONICAL_FELT_SOURCE
#include STWO_CANONICAL_FELT_FIXTURES

#if defined(STWO_FELT_INVERSE)
__global__ void canonical_felt_inverse(const unsigned* input, unsigned* output, unsigned count) {
    unsigned row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= count) return;
    felt252 value;
    stwo_wit_felt_from_w27(value, input + row * 10u);
    const felt252 inverse = felt_from_mont(felt_inverse(felt_to_mont(value)));
    stwo_wit_felt_to_w27(inverse, output + row * 10u);
}
#else
__global__ void canonical_felt_cube(const unsigned* input, unsigned* output,
    unsigned count) {
    unsigned row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= count) return;
    stwo_wit_deduce_cube_252(input + row * 10u, output + row * 10u);
}

#endif

int main() {
    unsigned *input = nullptr, *output = nullptr;
    unsigned observed[sizeof(kFeltExpected) / sizeof(unsigned)]{};
    if (cudaMalloc(reinterpret_cast<void**>(&input), sizeof(kFeltInputs)) != cudaSuccess ||
        cudaMalloc(reinterpret_cast<void**>(&output), sizeof(kFeltExpected)) != cudaSuccess)
        return 1;
    if (cudaMemcpy(input, kFeltInputs, sizeof(kFeltInputs), cudaMemcpyHostToDevice) != cudaSuccess)
        return 1;
    #if defined(STWO_FELT_INVERSE)
    canonical_felt_inverse<<<1, 128>>>(input, output, kFeltCount);
    #else
    canonical_felt_cube<<<1, 128>>>(input, output, kFeltCount);
    #endif
    if (cudaDeviceSynchronize() != cudaSuccess ||
        cudaMemcpy(observed, output, sizeof(observed), cudaMemcpyDeviceToHost) != cudaSuccess)
        return 1;
    for (unsigned i = 0; i < sizeof(observed) / sizeof(unsigned); ++i) {
        if (observed[i] != kFeltExpected[i]) {
            std::fprintf(stderr, "FAIL: felt252 arithmetic mismatch row=%u limb=%u expected=%u actual=%u\n",
                i / 10u, i % 10u, kFeltExpected[i], observed[i]);
            return 1;
        }
    }
    if (cudaFree(input) != cudaSuccess || cudaFree(output) != cudaSuccess) return 1;
    #if defined(STWO_FELT_INVERSE)
    std::printf("PASS: felt252 inverses match independent Python integer oracle\n");
    #else
    std::printf("PASS: felt252 cubes match independent Python integer oracle\n");
    #endif
    return 0;
}
