// Opt-in exact wide accumulation. A cold request bound proves no u64 wrap even
// when every request targets one cell and has canonical weight p-1.
__device__ void parent_framework_wide_add(unsigned long long*address,uint value,uint*status){
 if(value>=2147483647u){atomicOr(status,32u);return;}
 uint active=__activemask(),group=__match_any_sync(active,(unsigned long long)address),pending=group;
 unsigned long long sum=0;
 while(pending){uint lane=uint(__ffs(pending)-1);sum+=(unsigned long long)__shfl_sync(group,value,lane);pending&=pending-1u;}
 if((threadIdx.x&31u)==uint(__ffs(group)-1))atomicAdd(address,sum);
}
__device__ void parent_framework_wide_bitwise(unsigned long long*table,uint*status,uint weight,uint a,uint b,uint out,uint op){
 if(!weight)return;if(a>=256u||b>=256u||out>=256u||op>=4u){atomicOr(status,32u);return;}
 uint expected=op==0u?(a&b):op==1u?(a|b):op==2u?(a^b):0u;if(out!=expected){atomicOr(status,32u);return;}
 parent_framework_wide_add(table+parent_framework_table_row(a|(b<<8u)|(op<<16u),18u),weight,status);
}
__device__ void parent_framework_wide_range(unsigned long long*table,uint*status,uint weight,uint a,uint b){
 if(!weight)return;if(a>=256u||b>=256u){atomicOr(status,32u);return;}
 parent_framework_wide_add(table+parent_framework_table_row(a|(b<<8u),16u),weight,status);
}
__global__ void parent_framework_wide_reduce(const unsigned long long*source,uint*dest,uint n){
 uint i=blockIdx.x*blockDim.x+threadIdx.x;if(i<n)dest[i]=uint(source[i]%2147483647ull);
}
extern "C" int stwo_resident_framework_wide_reduce_on(const unsigned long long*source,uint*dest,uint n,void*stream){
 if(!source||!dest||!n||n>(1u<<18))return int(cudaErrorInvalidValue);
 parent_framework_wide_reduce<<<(n+255u)/256u,256,0,static_cast<cudaStream_t>(stream)>>>(source,dest,n);return int(cudaGetLastError());
}
