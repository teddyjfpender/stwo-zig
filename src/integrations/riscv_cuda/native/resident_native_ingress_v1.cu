// Stable GPU-only family bucketing of raw architectural retirement records.
// The immutable opcode map is compiled from Trace.proofOpcodeFamily; no host
// instruction classification or witness-dependent indices enter the proof.
#include <cuda_runtime.h>
#include <cub/device/device_radix_sort.cuh>
#include <stdint.h>
namespace {
constexpr uint32_t limit=1u<<24;
__global__ void keys(const uint32_t*raw,uint32_t count,const uint32_t*map,uint32_t map_size,
                     uint64_t*out_keys,uint32_t*out_indices,uint32_t*status){
 uint32_t i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=count)return;
 uint32_t opcode=raw[(size_t)i*24u+2u];uint32_t family=opcode<map_size?map[opcode]:0xffffffffu;
 if(family>=17u){atomicOr(status,1u);family=17u;}
 out_keys[i]=(uint64_t(family)<<32)|i;out_indices[i]=i;
}
__global__ void check(const uint64_t*keys,uint32_t count,const uint32_t*expected,uint32_t*status){
 uint32_t family=threadIdx.x;if(family>=17u)return;
 uint32_t lo=0,hi=count;
 while(lo<hi){uint32_t mid=lo+(hi-lo)/2;if((keys[mid]>>32)<family)lo=mid+1;else hi=mid;}
 uint32_t first=lo;hi=count;
 while(lo<hi){uint32_t mid=lo+(hi-lo)/2;if((keys[mid]>>32)<=family)lo=mid+1;else hi=mid;}
 if(lo-first!=expected[family])atomicOr(status,2u);
}
}
extern "C" int stwo_native_ingress_temp_bytes_v1(uint32_t count,size_t*bytes){
 if(!count||count>limit||!bytes)return int(cudaErrorInvalidValue);
 return int(cub::DeviceRadixSort::SortPairs(nullptr,*bytes,(const uint64_t*)nullptr,(uint64_t*)nullptr,(const uint32_t*)nullptr,(uint32_t*)nullptr,count,0,37));
}
extern "C" int stwo_native_ingress_on(const uint32_t*raw,uint32_t count,const uint32_t*map,uint32_t map_size,
 const uint32_t*expected,uint64_t*keys_in,uint64_t*keys_out,uint32_t*indices_in,uint32_t*indices_out,
 void*scratch,size_t scratch_bytes,uint32_t*status,void*stream){
 if(!raw||!count||count>limit||!map||!map_size||map_size>256u||!expected||!keys_in||!keys_out||!indices_in||!indices_out||!scratch||!status)return int(cudaErrorInvalidValue);
 size_t required=0;int e=stwo_native_ingress_temp_bytes_v1(count,&required);if(e)return e;
 if(scratch_bytes<required)return int(cudaErrorInvalidValue);
 cudaStream_t s=static_cast<cudaStream_t>(stream);
 keys<<<(count+127u)/128u,128,0,s>>>(raw,count,map,map_size,keys_in,indices_in,status);
 cudaError_t result=cudaGetLastError();if(result!=cudaSuccess)return int(result);
 result=cub::DeviceRadixSort::SortPairs(scratch,scratch_bytes,keys_in,keys_out,indices_in,indices_out,count,0,37,s);
 if(result!=cudaSuccess)return int(result);
 check<<<1,32,0,s>>>(keys_out,count,expected,status);return int(cudaGetLastError());
}
namespace {
__global__ void place(const uint32_t*logical,uint32_t*committed,uint32_t rows){
 uint32_t i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=rows)return;
 uint32_t circle=(i&1u)?rows-1u-i/2u:i/2u;
 committed[__brev(circle)>>(32u-uint32_t(__ffs(rows)-1))]=logical[i];
}
}
extern "C" int stwo_native_main_place_on(const uint32_t*logical,uint32_t*committed,uint32_t rows,void*stream){
 if(!logical||!committed||logical==committed||rows<2u||rows>limit||(rows&(rows-1u)))return int(cudaErrorInvalidValue);
 place<<<(rows+127u)/128u,128,0,static_cast<cudaStream_t>(stream)>>>(logical,committed,rows);return int(cudaGetLastError());
}
