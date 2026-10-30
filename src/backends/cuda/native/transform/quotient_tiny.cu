#include <cuda_runtime.h>
#include "quotient_tiny.cuh"
namespace {
__global__ void inverse(const uint32_t* input,size_t input_stride,uint32_t* output,size_t output_stride,uint32_t columns,uint32_t log,uint32_t initial_index) {
    const uint32_t column=blockIdx.x*blockDim.x+threadIdx.x;
    if(column>=columns)return;
    uint32_t values[4];
    for(uint32_t i=0;i<(1u<<log);++i) values[i]=input[size_t(column)*input_stride+i];
    // The ABI validates this finite public domain before launching. No
    // input-dependent domain or silent canonical-domain substitution is accepted.
    if(!stwo::cuda::quotient_tiny::invert(values,log,initial_index))return;
    for(uint32_t i=0;i<(1u<<log);++i) output[size_t(column)*output_stride+i]=values[i];
}
}
extern "C" int stwo_quotient_tiny_inverse_on(const uint32_t* input,size_t input_stride,uint32_t* output,size_t output_stride,uint32_t columns,uint32_t log,uint32_t initial_index,cudaStream_t stream) {
    if(log<1||log>2||initial_index!=(1u<<(29u-log))||!columns||!input||!output||input_stride<(1u<<log)||output_stride<(1u<<log))return int(cudaErrorInvalidValue);
    inverse<<<(columns+127)/128,128,0,stream>>>(input,input_stride,output,output_stride,columns,log,initial_index);
    return int(cudaGetLastError());
}
