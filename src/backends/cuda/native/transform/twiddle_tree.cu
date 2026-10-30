// Canonical circle FFT tree. Only the public domain log enters from the host;
// all circle points and inverse field values are produced on the device.
#include <cuda_runtime.h>
#include "../common/m31.cuh"
namespace {
using namespace stwo::cuda;
struct Point { M31 x,y; };
__device__ Point add(Point a, Point b) {
 return {m31_sub(m31_mul(a.x,b.x),m31_mul(a.y,b.y)),m31_add(m31_mul(a.x,b.y),m31_mul(a.y,b.x))};
}
__device__ M31 power(M31 a, uint32_t n) {
 M31 r=1; while(n) {if(n&1) r=m31_mul(r,a); a=m31_mul(a,a); n>>=1;} return r;
}
__global__ void build(uint32_t log, uint32_t* forward, uint32_t* inverse) {
 const uint32_t k=blockIdx.x*blockDim.x+threadIdx.x, total=1u<<(log-1);
 if(k>=total) return;
 if(k==total-1) {forward[k]=inverse[k]=1; return;}
 uint32_t local=k, layer=0, length=total>>1;
 while(local>=length) {local-=length; length>>=1; ++layer;}
 const uint32_t bits=log-layer-2;
 const uint32_t j=bits?(__brev(local)>>(32-bits)):0;
 uint32_t exponent=(1u+4u*j)<<(30-log+layer);
 Point r{1,0}, g{2,1268011823u};
 while(exponent) {if(exponent&1) r=add(r,g); g=add(g,g); exponent>>=1;}
 forward[k]=r.x; inverse[k]=power(r.x,kM31Prime-2);
}
}
extern "C" int stwo_canonical_twiddle_tree_on(uint32_t log, uint32_t* forward, uint32_t* inverse, cudaStream_t stream) {
 if(log<1||log>30||!forward||!inverse||forward==inverse) return (int)cudaErrorInvalidValue;
 const uint32_t n=1u<<(log-1);
 build<<<(n+127)/128,128,0,stream>>>(log,forward,inverse);
 return (int)cudaGetLastError();
}
