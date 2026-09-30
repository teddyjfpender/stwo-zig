// Execute generated CUDA AIR against an independent Python field oracle.
#include <cuda_runtime.h>
#include <cstdio>
#include STWO_AIR_PARITY_SOURCE
#include STWO_AIR_PARITY_FIXTURES

int main() {
    unsigned *arena = nullptr;
    StwoCairoEvalArgs *device_args = nullptr;
    const StwoCairoEvalArgs args = {8,10,11,14,18,42,43,51,59,67,8,3,3,0};
    if (cudaMalloc((void**)&arena, 75*sizeof(unsigned)) != cudaSuccess ||
        cudaMalloc((void**)&device_args, sizeof(args)) != cudaSuccess ||
        cudaMemcpy(device_args, &args, sizeof(args), cudaMemcpyHostToDevice) != cudaSuccess) return 1;
    for (unsigned c=0; c<kAirCaseCount; ++c) {
        if (cudaMemcpy(arena,kAirCases[c],75*sizeof(unsigned),cudaMemcpyHostToDevice) != cudaSuccess) return 1;
        STWO_AIR_PARITY_KERNEL<<<1,32>>>(arena,75,device_args);
        if (cudaDeviceSynchronize() != cudaSuccess) return 1;
        unsigned actual[32];
        if (cudaMemcpy(actual,arena+43,sizeof(actual),cudaMemcpyDeviceToHost) != cudaSuccess) return 1;
        for (unsigned i=0;i<32;++i) if (actual[i] != kAirExpected[c][i]) {
            std::fprintf(stderr,"FAIL: parametric AIR case %u word %u expected %u actual %u\n",c,i,kAirExpected[c][i],actual[i]);
            return 1;
        }
    }
    if (cudaFree(arena) != cudaSuccess || cudaFree(device_args) != cudaSuccess) return 1;
    std::printf("PASS: parametric AIR scalar and register-rewrite oracle (%u cases)\n",kAirCaseCount);
    return 0;
}
