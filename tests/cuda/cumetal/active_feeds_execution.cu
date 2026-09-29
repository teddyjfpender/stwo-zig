// Execute the maintained CUDA kernel; compare to independent scalar counting.
#include <cuda_runtime.h>
#include <cstdio>
#include <cstdint>
#include <vector>
#include "../../../src/backends/cuda/native/witness/active_feeds.cu"

static bool ok(cudaError_t status) { return status == cudaSuccess; }

int main() {
    constexpr unsigned stride = 8, active = 5, width = 5;
    const unsigned source[width * stride] = {
        1,2,2,4,3, 1,1,1,
        0,0x40000001u,0x3fffffffu,1,0x40000000u, 0,0,0,
        2,3,4,5,7, 2,2,2,
        1,6,7,0,4, 1,1,1,
        3,5,3,5,3, 3,3,3,
    };
    const unsigned descriptors[4 * 14] = {
        0,1,0,0,0,0,0,0,8,0xffffffffu,0,0,0xffffffffu,0,
        1,1,0,0,0,0,0,0,2,0xffffffffu,1,1,2,2,
        2,3,4,0,0,0,0,0,256,0xffffffffu,3,2,0,0,
        2,2,4,3,0,0,0,0,128,0xffffffffu,4,0,0,0,
    };
    const unsigned sizes[5] = {8,2,2,256,128};
    unsigned *gpu_source = nullptr, *gpu_descriptors = nullptr, **gpu_destinations = nullptr;
    unsigned* destinations[5]{};
    cudaStream_t stream = nullptr;
    if (!ok(cudaStreamCreate(&stream)) || !ok(cudaMalloc((void**)&gpu_source,sizeof(source))) ||
        !ok(cudaMalloc((void**)&gpu_descriptors,sizeof(descriptors))) ||
        !ok(cudaMalloc((void**)&gpu_destinations,sizeof(destinations)))) return 1;
    for (unsigned i=0;i<5;i++) if (!ok(cudaMalloc((void**)&destinations[i],sizes[i]*4)) ||
        !ok(cudaMemset(destinations[i],0,sizes[i]*4))) return 1;
    if (!ok(cudaMemcpy(gpu_source,source,sizeof(source),cudaMemcpyHostToDevice)) ||
        !ok(cudaMemcpy(gpu_descriptors,descriptors,sizeof(descriptors),cudaMemcpyHostToDevice)) ||
        !ok(cudaMemcpy(gpu_destinations,destinations,sizeof(destinations),cudaMemcpyHostToDevice))) return 1;
    if (stwo_witness_feed_counts_active_on(gpu_source,stride,active,gpu_descriptors,4,nullptr,gpu_destinations,stream) != 0 ||
        !ok(cudaStreamSynchronize(stream))) return 1;
    std::vector<unsigned> expected[5];
    for (unsigned i=0;i<5;i++) expected[i].resize(sizes[i],0);
    for (unsigned row=0;row<active;row++) {
        expected[0][source[row]-1]++;
        const unsigned id=source[stride+row];
        if(id!=0x3fffffffu) expected[(id>>30)?1:2][id&0x3fffffffu]++;
        const unsigned a=source[2*stride+row],b=source[3*stride+row],c=source[4*stride+row];
        if(c==(a^b)) expected[3][a*16+b]++;
        expected[4][a*8+b]++;
    }
    for (unsigned i=0;i<5;i++) {
        std::vector<unsigned> actual(sizes[i]);
        if(!ok(cudaMemcpy(actual.data(),destinations[i],sizes[i]*4,cudaMemcpyDeviceToHost))) return 1;
        if(actual!=expected[i]) {
            for(unsigned j=0;j<sizes[i];j++) if(actual[j]!=expected[i][j])
                std::fprintf(stderr,"FAIL: active feed destination %u index %u expected %u actual %u\n",i,j,expected[i][j],actual[j]);
            return 1;
        }
    }
    // Admission must reject an active extent beyond the padded source.
    if(stwo_witness_feed_counts_active_on(gpu_source,stride,stride+1,gpu_descriptors,4,nullptr,gpu_destinations,stream)==0) return 1;
    for(auto pointer:destinations) if(!ok(cudaFree(pointer))) return 1;
    if(!ok(cudaFree(gpu_source)) || !ok(cudaFree(gpu_descriptors)) || !ok(cudaFree(gpu_destinations)) ||
        !ok(cudaStreamDestroy(stream))) return 1;
    std::puts("PASS: active feeds match independent oracle; padded rows excluded");
    return 0;
}
