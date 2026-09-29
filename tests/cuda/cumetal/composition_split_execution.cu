// Execute the production log-21 fused composition split against a scalar
// inverse transform. CuMetal evidence is never NVIDIA proof qualification.
#include <cuda_runtime.h>
#include <cstdio>
#include <vector>
#include "../../../src/backends/cuda/native/transform/b2n_fused.cuh"
using namespace stwo::cuda;
using namespace stwo::cuda::transform;
constexpr unsigned log_n = 21, rows = 1u << log_n, half = rows / 2;
unsigned multiply(unsigned a, unsigned b) { return unsigned((uint64_t(a)*b)%kM31Prime); }
unsigned add_scalar(unsigned a, unsigned b) { return unsigned((uint64_t(a)+b)%kM31Prime); }
unsigned sub_scalar(unsigned a, unsigned b) { return unsigned((uint64_t(a)+kM31Prime-b)%kM31Prime); }
unsigned circle(const std::vector<unsigned>& t, unsigned i) {
    const unsigned pair=i>>2;
    switch(i&3) { case 0:return t[2*pair+1];case 1:return sub_scalar(0,t[2*pair+1]);case 2:return sub_scalar(0,t[2*pair]);default:return t[2*pair]; }
}
int main() {
    std::vector<unsigned> input(4*rows),twiddles(half),actual(4*rows);
    for (unsigned i=0;i<half;i++) twiddles[i]=unsigned((uint64_t(i)*i*17+i*97+13)%(kM31Prime-1))+1;
    for (unsigned c=0;c<4;c++) for(unsigned i=0;i<rows;i++) input[c*rows+i]=unsigned((uint64_t(c+5)*(i+11)*65537+uint64_t(i)*i+3)%kM31Prime);
    unsigned *device=nullptr,*output=nullptr,*tw=nullptr;
    if(cudaMalloc((void**)&device,input.size()*4)!=cudaSuccess || cudaMalloc((void**)&output,actual.size()*4)!=cudaSuccess || cudaMalloc((void**)&tw,twiddles.size()*4)!=cudaSuccess) return 1;
    if(cudaMemcpy(device,input.data(),input.size()*4,cudaMemcpyHostToDevice)!=cudaSuccess || cudaMemcpy(tw,twiddles.data(),twiddles.size()*4,cudaMemcpyHostToDevice)!=cudaSuccess) return 1;
    ColumnSlab<const M31> source{device,rows};ColumnSlab<M31> work{device,rows},compact{output,half};
    b2n_init_block<1><<<dim3(1u<<(log_n-9),1,4),dim3(32,2)>>>(source,work,log_n,10,tw);
    b2n_continue<3,false,0><<<dim3((1u<<9)/32,(1u<<log_n)/(1u<<15),4),dim3(32,8)>>>(work,ColumnSlab<M31>{nullptr,0},0,log_n,10,15,tw,m31_inverse_power_of_two(log_n));
    b2n_continue<3,false,1><<<dim3((1u<<15)/32,1,4),dim3(32,8)>>>(work,compact,4,log_n,16,21,tw,m31_inverse_power_of_two(log_n));
    if(cudaDeviceSynchronize()!=cudaSuccess || cudaMemcpy(actual.data(),output,actual.size()*4,cudaMemcpyDeviceToHost)!=cudaSuccess)return 1;
    for(unsigned c=0;c<4;c++) {
        auto* values=input.data()+c*rows;
        unsigned layer_size=half,layer_offset=0;
        for(unsigned stage=1;stage<=log_n;stage++) {
            const unsigned stride=1u<<(stage-1);
            for(unsigned pair=0;pair<half;pair++) {
                const unsigned group=pair&(stride-1),butterfly=pair>>(stage-1),left=group+butterfly*2*stride,right=left+stride;
                const unsigned a=values[left],b=values[right],t=stage==1?circle(twiddles,butterfly):twiddles[layer_offset+butterfly];
                values[left]=add_scalar(a,b);values[right]=multiply(sub_scalar(a,b),t);
                if(stage==log_n) {values[left]=multiply(values[left],1u<<(31-log_n));values[right]=multiply(values[right],1u<<(31-log_n));}
            }
            if(stage>=2 && stage!=log_n){layer_size>>=1;layer_offset+=layer_size;}
        }
        for(unsigned side=0;side<2;side++)for(unsigned row=0;row<half;row++)if(actual[(c+side*4)*half+row]!=values[side*half+row]) {
            std::fprintf(stderr,"FAIL composition log21 coord=%u side=%u row=%u expected=%u actual=%u\n",c,side,row,values[side*half+row],actual[(c+side*4)*half+row]);return 1;
        }
    }
    if(cudaFree(device)!=cudaSuccess || cudaFree(output)!=cudaSuccess || cudaFree(tw)!=cudaSuccess)return 1;
    std::puts("PASS: production log21 composition split against independent scalar inverse transform");return 0;
}
