// Exact resident parameter assembly. No host challenge/claim replay.
#include <cuda_runtime.h>
struct ParentRelationRoute { uint domain,arity,offset; };
__global__ void parent_framework_relations(const uint*draws,const ParentRelationRoute*route,uint count,uint*out,uint*status){
 uint i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=count)return;
 ParentRelationRoute r=route[i];if(r.domain>=47u||r.arity==0u||r.arity>33u){atomicOr(status,16u);return;}
 RiscvQm31 z=riscv_load_qm31(draws,8u*r.domain),alpha=riscv_load_qm31(draws,8u*r.domain+4u),power={1u,0u,0u,0u};
 uint k=4u*r.offset;out[k]=z.a;out[k+1]=z.b;out[k+2]=z.c;out[k+3]=z.d;
 for(uint j=0;j<r.arity;++j){k+=4;out[k]=power.a;out[k+1]=power.b;out[k+2]=power.c;out[k+3]=power.d;power=riscv_qm_mul(power,alpha);}
}
__global__ void parent_framework_powers(const uint*alpha,uint count,uint*out){
 uint i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=count)return;
 RiscvQm31 a=riscv_load_qm31(alpha,0),p={1u,0u,0u,0u};uint exponent=i;
 while(exponent){if(exponent&1u)p=riscv_qm_mul(p,a);a=riscv_qm_mul(a,a);exponent>>=1u;}
 out[4u*i]=p.a;out[4u*i+1]=p.b;out[4u*i+2]=p.c;out[4u*i+3]=p.d;
}
__global__ void parent_framework_claim(const uint*claim,uint*out,uint factor){
 for(uint i=threadIdx.x;i<4u;i+=blockDim.x)out[i]=riscv_m31_mul(claim[i],factor);
}
__global__ void parent_framework_add(const uint*source,uint*dest,uint count){uint i=blockIdx.x*blockDim.x+threadIdx.x;if(i<count)dest[i]=riscv_m31_add(dest[i],source[i]);}
extern "C" int stwo_resident_framework_relations_on(const uint*draws,const ParentRelationRoute*route,uint count,uint*out,uint*status,void*stream){
 if(!draws||!route||!count||!out||!status)return int(cudaErrorInvalidValue);
 parent_framework_relations<<<(count+127u)/128u,128u,0,static_cast<cudaStream_t>(stream)>>>(draws,route,count,out,status);return int(cudaGetLastError());}
extern "C" int stwo_resident_framework_powers_on(const uint*alpha,uint count,uint*out,void*stream){if(!alpha||!count||!out)return int(cudaErrorInvalidValue);parent_framework_powers<<<(count+127u)/128u,128u,0,static_cast<cudaStream_t>(stream)>>>(alpha,count,out);return int(cudaGetLastError());}
extern "C" int stwo_resident_framework_claim_on(const uint*claim,uint*out,uint factor,void*stream){if(!claim||!out)return int(cudaErrorInvalidValue);parent_framework_claim<<<1,4,0,static_cast<cudaStream_t>(stream)>>>(claim,out,factor);return int(cudaGetLastError());}
extern "C" int stwo_resident_framework_add_on(const uint*source,uint*dest,uint count,void*stream){if(!source||!dest||!count)return int(cudaErrorInvalidValue);parent_framework_add<<<(count+255u)/256u,256u,0,static_cast<cudaStream_t>(stream)>>>(source,dest,count);return int(cudaGetLastError());}
// Combine equal destinations within each active warp before the contended
// modular CAS. All participating lanes execute every shuffle in their group;
// addition remains modulo M31, including negative signed multiplicities.
__device__ void parent_framework_atomic_add(uint*address,uint value){
 uint active=__activemask();
 uint group=__match_any_sync(active,(unsigned long long)address);
 uint pending=group,sum=0u;
 while(pending){uint lane=uint(__ffs(pending)-1);sum=riscv_m31_add(sum,__shfl_sync(group,value,lane));pending&=pending-1u;}
 if((threadIdx.x&31u)!=uint(__ffs(group)-1))return;
 uint old=atomicCAS(address,0u,0u),assumed;
 do{assumed=old;old=atomicCAS(address,assumed,riscv_m31_add(assumed,sum));}while(old!=assumed);
}
__device__ uint parent_framework_table_row(uint logical,uint log){uint n=(logical&1u)?((1u<<log)-1u-logical/2u):logical/2u;return __brev(n)>>(32u-log);}
__device__ void parent_framework_count_bitwise(uint*table,uint*status,uint weight,uint a,uint b,uint out,uint op){
 if(!weight)return;if(a>=256u||b>=256u||out>=256u||op>=4u){atomicOr(status,32u);return;}
 uint expected=op==0u?(a&b):op==1u?(a|b):op==2u?(a^b):0u;if(out!=expected){atomicOr(status,32u);return;}
 parent_framework_atomic_add(table+parent_framework_table_row(a|(b<<8u)|(op<<16u),18u),weight);
}
__device__ void parent_framework_count_range(uint*table,uint*status,uint weight,uint a,uint b){if(!weight)return;if(a>=256u||b>=256u){atomicOr(status,32u);return;}parent_framework_atomic_add(table+parent_framework_table_row(a|(b<<8u),16u),weight);}
