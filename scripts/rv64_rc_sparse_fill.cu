// Fixture only: row-sensitive full-domain evaluation planes for exact parity.
#include "rv64/custody.cuh"
__global__ void fill_planes(uint32_t*p,uint64_t words){for(uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;i<words;i+=uint64_t(gridDim.x)*blockDim.x){const uint64_t column=i>>20,row=i&((1u<<20)-1);p[i]=uint32_t((column*7919+row*104729+(row^(row>>7))*131+173)%2147483647u);}}
extern "C" int sparse_fixture_fill(void*ctx,uint32_t*p,uint64_t words){stwo::cuda::rv64::Custody c(ctx,0);if(words!=(uint64_t(3516)<<20)||!c.range(p,words,true))return c.status?c.status:int(cudaErrorInvalidValue);fill_planes<<<65536,256,0,c.stream>>>(p,words);return int(cudaGetLastError());}
