// Exact original claim frame packing. Bounds and canonicality stay on device.
#include <cuda_runtime.h>
#include <stdint.h>
struct NativeClaimRoute { uint32_t source,destination,kind,maximum; };
static_assert(sizeof(NativeClaimRoute)==16);
__global__ void native_claim_pack(const NativeClaimRoute*routes,uint32_t nr,const uint32_t*claims,uint32_t nc,uint32_t projection_words,uint32_t*words,uint32_t nw,uint32_t*fields,uint32_t nf,uint64_t*counts,uint32_t na,uint32_t*error){
 const uint32_t i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=nr)return;const NativeClaimRoute r=routes[i];
 if(r.source>=nc||r.kind>2){atomicOr(error,1u<<20);return;}const uint32_t value=claims[r.source];
 if(value>=0x7fffffffu){atomicOr(error,1u<<20);return;}
 if(r.kind==0){if(r.destination>=nw){atomicOr(error,1u<<20);return;}words[r.destination]=value;}
 else if(r.kind==1){if(r.destination>=nf){atomicOr(error,1u<<20);return;}fields[r.destination]=value;}
 else {
  if(r.source<projection_words||r.source-projection_words<8||(r.source-projection_words-8)%40||nc-r.source<4||r.destination>=nw||nw-r.destination<2||claims[r.source+1]||claims[r.source+2]||claims[r.source+3]||value>r.maximum){atomicOr(error,1u<<20);return;}
  const uint32_t access=(r.source-projection_words-8)/40;if(access>=na){atomicOr(error,1u<<20);return;}
  words[r.destination]=value;words[r.destination+1]=0;counts[access]=value;
 }
}
extern "C" int stwo_native_claim_pack_v1(const NativeClaimRoute*routes,uint32_t nr,const uint32_t*claims,uint32_t nc,uint32_t projection_words,uint32_t*words,uint32_t nw,uint32_t*fields,uint32_t nf,uint64_t*counts,uint32_t na,uint32_t*error,cudaStream_t stream){
 if(!nr)return int(cudaSuccess);if(!routes||!claims||!words||!error||(nf&&!fields)||(na&&!counts)||projection_words>nc)return int(cudaErrorInvalidValue);
 native_claim_pack<<<(nr+127)/128,128,0,stream>>>(routes,nr,claims,nc,projection_words,words,nw,fields,nf,counts,na,error);return int(cudaGetLastError());
}
__global__ void native_root_equal(const uint32_t*expected,const uint32_t*actual,uint32_t*error){const uint32_t i=threadIdx.x;if(i<8&&expected[i]!=actual[i])atomicOr(error,1u<<21);}
extern "C" int stwo_native_root_equal_v1(const uint32_t*expected,const uint32_t*actual,uint32_t*error,cudaStream_t stream){if(!expected||!actual||!error)return int(cudaErrorInvalidValue);native_root_equal<<<1,32,0,stream>>>(expected,actual,error);return int(cudaGetLastError());}
