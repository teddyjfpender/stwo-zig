// Actual native memory writer, checked against pinned Rust trace columns.
#include <cuda_runtime.h>
#include <cstdio>
#include <vector>
#include STWO_BIG_MEMORY_FIXTURE
#include STWO_SMALL_MEMORY_FIXTURE
#include "../../../src/backends/cuda/native/cairo/memory_base.cu"

static bool check_value(const unsigned* expected, unsigned limbs) {
    constexpr unsigned rows = 16;
    unsigned* counts = nullptr;
    std::vector<unsigned*> sources(limbs), outputs(limbs+1);
    cudaStream_t stream = nullptr;
    if (cudaStreamCreate(&stream) != cudaSuccess ||
        cudaMalloc((void**)&counts, rows*4) != cudaSuccess ||
        cudaMemcpy(counts,expected,rows*4,cudaMemcpyHostToDevice) != cudaSuccess) return false;
    for (unsigned i=0;i<limbs;i++) {
        if (cudaMalloc((void**)&sources[i],rows*4) != cudaSuccess ||
            cudaMemcpy(sources[i],expected+(i+1)*rows,rows*4,cudaMemcpyHostToDevice) != cudaSuccess) return false;
    }
    for (auto& output:outputs) if (cudaMalloc((void**)&output,rows*4) != cudaSuccess) return false;
    if (stwo_cairo_memory_value_base_on((const unsigned* const*)sources.data(),limbs,rows,counts,rows,rows,outputs.data(),stream) != 0 ||
        cudaStreamSynchronize(stream) != cudaSuccess) return false;
    for (unsigned i=0;i<limbs+1;i++) {
        unsigned actual[rows];
        if (cudaMemcpy(actual,outputs[i],sizeof(actual),cudaMemcpyDeviceToHost) != cudaSuccess) return false;
        for (unsigned row=0;row<rows;row++) if (actual[row]!=expected[i*rows+row]) {
            std::fprintf(stderr,"FAIL: Rust memory AIR column %u row %u expected %u actual %u\n",i,row,expected[i*rows+row],actual[row]);
            return false;
        }
    }
    for (auto output:outputs) if (cudaFree(output) != cudaSuccess) return false;
    for (auto source:sources) if (cudaFree(source) != cudaSuccess) return false;
    return cudaFree(counts)==cudaSuccess && cudaStreamDestroy(stream)==cudaSuccess;
}
int main() {
    if (!check_value(big_expected,28) || !check_value(small_expected,8)) return 1;
    std::puts("PASS: big and small native memory AIR column order matches pinned Rust");
}
