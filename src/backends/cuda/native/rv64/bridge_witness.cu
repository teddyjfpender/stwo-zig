#include "custody.cuh"
#include "bridge_witness.h"
#include <cstdlib>
namespace stwo::cuda::rv64 { namespace bridge {
__device__ __forceinline__ uint64_t u64(const uint32_t*p){return uint64_t(p[0])|(uint64_t(p[1])<<32);}
__device__ __forceinline__ void word(uint32_t*out,uint64_t x){
 #pragma unroll
 for(uint32_t i=0;i<4;++i)out[i]=uint32_t(x>>(16*i))&65535u;
}
// Warp aggregation removes duplicate limb atomics without sharing witness ownership.
__device__ __forceinline__ void count(uint32_t*out,uint32_t value){
 const unsigned mask=__activemask(),peers=__match_any_sync(mask,value);
 if((threadIdx.x&31)==uint32_t(__ffs(peers)-1))atomicAdd(out+value,__popc(peers));
}
__device__ bool predecessor(const uint32_t*in,uint32_t epoch,uint32_t tick,bool write,uint32_t*old){
 const uint32_t packed=in[6],pe=packed&65535u,rights=packed>>16,pt=in[7];
 if(packed>>18||!(rights&1u)||(write&&!(rights&2u))||pe>epoch||pt>=(1u<<24)||(pe==epoch&&pt>=tick)||u64(in)!=u64(in+4)||(!write&&u64(in)!=u64(in+2)))return false;
 old[0]=pe;old[1]=pt&65535u;old[2]=pt>>16;old[3]=0;old[4]=0;old[5]=0;old[6]=pe==epoch;old[7]=0;old[8]=rights&1u;old[9]=rights>>1;
 if(pe==epoch){const uint32_t gap=tick-pt-1;old[4]=gap&65535u;old[5]=gap>>16;old[7]=((pt&65535u)+(gap&65535u)+1)>>16;}else old[3]=epoch-pe-1;
 return true;
}
__global__ void witness(StwoRv64BridgeWitness j){
 const uint32_t physical=blockIdx.x*blockDim.x+threadIdx.x,n=1u<<j.log;if(physical>=n)return;
 const uint32_t circle=__brev(physical)>>(32-j.log),logical=circle<n/2?2*circle:2*(n-1-circle)+1;
 const bool keccak=j.kind==0;const uint32_t width=keccak?66:134,words=keccak?25:4*j.coordinates;
 const uint32_t active=j.calls*j.coordinates;uint32_t row[134]{};
 if(logical<active){
  const uint32_t call=logical/j.coordinates,coord=logical%j.coordinates;const uint32_t*in=j.inputs+uint64_t(call)*(4+8*words);
  const uint64_t pointer=u64(in),extent=8ull*words-1;const uint32_t epoch=in[2],tick=in[3];
  bool valid=epoch&&epoch<=65535u&&tick&&tick<(1u<<24)&&!(pointer&(keccak?7ull:31ull))&&pointer<=UINT64_MAX-extent;
  if(keccak){
   const uint32_t*item=in+4+8*coord;uint32_t old[10]{};valid=valid&&predecessor(item,epoch,tick,true,old)&&(item[6]>>16)==3;
   if(valid){
    row[0]=1;row[1]=1;row[2]=old[6];row[3]=tick;word(row+4,pointer+8*coord);row[8]=old[0];row[9]=epoch;row[10]=old[1];row[11]=old[2];row[12]=tick&65535u;row[13]=tick>>16;
    word(row+14,u64(item));word(row+18,u64(item+2));row[22]=1;row[23]=1;row[24]=old[3];row[25]=old[4];row[26]=old[5];row[27]=old[7];word(row+28,pointer);row[32]=j.first_id+call;
    #pragma unroll
    for(uint32_t b=0;b<8;++b){row[33+b]=uint32_t(u64(item)>>(8*b))&255u;row[41+b]=uint32_t(u64(item+2)>>(8*b))&255u;}
    uint32_t carry=0;
    #pragma unroll
    for(uint32_t k=0;k<4;++k){carry=(row[28+k]+(k==0?8*coord:carry))>>16;row[49+k]=carry;}
    #pragma unroll
    for(uint32_t k=0;k<13;++k)row[53+k]=uint32_t(pointer>>(k+3))&1u;
   }
  }else{
   const bool writes=(j.write_mask>>coord)&1u;row[0]=1;row[1]=writes;word(row+2,pointer);word(row+6,pointer+32*coord);row[10]=tick;row[11]=epoch;row[12]=tick&65535u;row[13]=tick>>16;row[14]=j.first_id+call;
   #pragma unroll
   for(uint32_t lane=0;lane<4;++lane){const uint32_t*item=in+4+8*(4*coord+lane);uint32_t old[10]{};const bool ok=predecessor(item,epoch,tick,writes,old);valid=valid&&ok;
    #pragma unroll
    for(uint32_t k=0;k<10;++k)row[79+4*k+lane]=old[k];
    #pragma unroll
    for(uint32_t b=0;b<8;++b){row[15+8*lane+b]=uint32_t(u64(item)>>(8*b))&255u;row[47+8*lane+b]=uint32_t(u64(item+2)>>(8*b))&255u;}
   }
   uint32_t carry=0;
   #pragma unroll
   for(uint32_t k=0;k<4;++k){carry=(row[2+k]+(k==0?32*coord:carry))>>16;row[119+k]=carry;}
   #pragma unroll
   for(uint32_t k=0;k<11;++k)row[123+k]=uint32_t(pointer>>(k+5))&1u;
  }
  if(!valid){atomicOr(j.status,1u);return;}
  if(keccak){constexpr uint32_t r16[]={4,5,6,7,8,9,10,12,14,15,16,17,18,19,20,21,24,25,28,29,30,31};constexpr uint32_t r8[]={11,13,26,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48};
   #pragma unroll
   for(uint32_t k=0;k<22;++k)count(j.range16,row[r16[k]]);
   #pragma unroll
   for(uint32_t k=0;k<19;++k)count(j.range8,row[r8[k]]);
  }else{constexpr uint32_t r16[]={2,3,4,5,6,7,8,9,11,12,79,80,81,82,83,84,85,86,91,92,93,94,95,96,97,98};
   #pragma unroll
   for(uint32_t k=0;k<26;++k)count(j.range16,row[r16[k]]);
   count(j.range8,row[13]);
   #pragma unroll
   for(uint32_t k=0;k<4;++k){count(j.range8,row[87+k]);count(j.range8,row[99+k]);}
   #pragma unroll
   for(uint32_t k=15;k<79;++k)count(j.range8,row[k]);
  }
 }
 // Padding is the all-zero native row; add its histogram mass once.
 if(physical==0){const uint32_t padding=n-active;atomicAdd(j.range16,padding*(keccak?22u:26u));atomicAdd(j.range8,padding*(keccak?19u:73u));}
 #pragma unroll 1
 for(uint32_t c=0;c<width;++c)j.main[uint64_t(c)*n+physical]=row[c];
}
// ---- M8 T9 (STWO_RV64_M8_WITNESS_COALESCE=1; same ABI, integer counts so bit-identical) ----
// witness() sends ~73 range8 atomics per row into 256 global bins (all rows of
// the launch contend on 1 KB). Here range8 is privatised per CTA in shared
// memory and flushed once per nonzero bin; range16 keeps the warp-aggregated
// global atomics. Rows are computed by the same code as witness().
__global__ void __launch_bounds__(128) witness_private(StwoRv64BridgeWitness j){
 __shared__ uint32_t h8[256];
 for(uint32_t i=threadIdx.x;i<256;i+=blockDim.x)h8[i]=0;
 __syncthreads();
 const uint32_t physical=blockIdx.x*blockDim.x+threadIdx.x,n=1u<<j.log;
 const uint32_t circle=__brev(physical)>>(32-j.log),logical=circle<n/2?2*circle:2*(n-1-circle)+1;
 const bool keccak=j.kind==0;const uint32_t width=keccak?66:134,words=keccak?25:4*j.coordinates;
 const uint32_t active=j.calls*j.coordinates;uint32_t row[134]{};bool store=physical<n;
 if(store&&logical<active){
  const uint32_t call=logical/j.coordinates,coord=logical%j.coordinates;const uint32_t*in=j.inputs+uint64_t(call)*(4+8*words);
  const uint64_t pointer=u64(in),extent=8ull*words-1;const uint32_t epoch=in[2],tick=in[3];
  bool valid=epoch&&epoch<=65535u&&tick&&tick<(1u<<24)&&!(pointer&(keccak?7ull:31ull))&&pointer<=UINT64_MAX-extent;
  if(keccak){
   const uint32_t*item=in+4+8*coord;uint32_t old[10]{};valid=valid&&predecessor(item,epoch,tick,true,old)&&(item[6]>>16)==3;
   if(valid){
    row[0]=1;row[1]=1;row[2]=old[6];row[3]=tick;word(row+4,pointer+8*coord);row[8]=old[0];row[9]=epoch;row[10]=old[1];row[11]=old[2];row[12]=tick&65535u;row[13]=tick>>16;
    word(row+14,u64(item));word(row+18,u64(item+2));row[22]=1;row[23]=1;row[24]=old[3];row[25]=old[4];row[26]=old[5];row[27]=old[7];word(row+28,pointer);row[32]=j.first_id+call;
    #pragma unroll
    for(uint32_t b=0;b<8;++b){row[33+b]=uint32_t(u64(item)>>(8*b))&255u;row[41+b]=uint32_t(u64(item+2)>>(8*b))&255u;}
    uint32_t carry=0;
    #pragma unroll
    for(uint32_t k=0;k<4;++k){carry=(row[28+k]+(k==0?8*coord:carry))>>16;row[49+k]=carry;}
    #pragma unroll
    for(uint32_t k=0;k<13;++k)row[53+k]=uint32_t(pointer>>(k+3))&1u;
   }
  }else{
   const bool writes=(j.write_mask>>coord)&1u;row[0]=1;row[1]=writes;word(row+2,pointer);word(row+6,pointer+32*coord);row[10]=tick;row[11]=epoch;row[12]=tick&65535u;row[13]=tick>>16;row[14]=j.first_id+call;
   #pragma unroll
   for(uint32_t lane=0;lane<4;++lane){const uint32_t*item=in+4+8*(4*coord+lane);uint32_t old[10]{};const bool ok=predecessor(item,epoch,tick,writes,old);valid=valid&&ok;
    #pragma unroll
    for(uint32_t k=0;k<10;++k)row[79+4*k+lane]=old[k];
    #pragma unroll
    for(uint32_t b=0;b<8;++b){row[15+8*lane+b]=uint32_t(u64(item)>>(8*b))&255u;row[47+8*lane+b]=uint32_t(u64(item+2)>>(8*b))&255u;}
   }
   uint32_t carry=0;
   #pragma unroll
   for(uint32_t k=0;k<4;++k){carry=(row[2+k]+(k==0?32*coord:carry))>>16;row[119+k]=carry;}
   #pragma unroll
   for(uint32_t k=0;k<11;++k)row[123+k]=uint32_t(pointer>>(k+5))&1u;
  }
  if(!valid){atomicOr(j.status,1u);store=false;}
  else if(keccak){constexpr uint32_t r16[]={4,5,6,7,8,9,10,12,14,15,16,17,18,19,20,21,24,25,28,29,30,31};constexpr uint32_t r8[]={11,13,26,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48};
   #pragma unroll
   for(uint32_t k=0;k<22;++k)count(j.range16,row[r16[k]]);
   #pragma unroll
   for(uint32_t k=0;k<19;++k)atomicAdd(h8+row[r8[k]],1u);
  }else{constexpr uint32_t r16[]={2,3,4,5,6,7,8,9,11,12,79,80,81,82,83,84,85,86,91,92,93,94,95,96,97,98};
   #pragma unroll
   for(uint32_t k=0;k<26;++k)count(j.range16,row[r16[k]]);
   atomicAdd(h8+row[13],1u);
   #pragma unroll
   for(uint32_t k=0;k<4;++k){atomicAdd(h8+row[87+k],1u);atomicAdd(h8+row[99+k],1u);}
   #pragma unroll
   for(uint32_t k=15;k<79;++k)atomicAdd(h8+row[k],1u);
  }
 }
 // witness() returns before this on an invalid row; mirror it (store is false only then, as physical 0 < n).
 if(physical==0&&store){const uint32_t padding=n-active;atomicAdd(j.range16,padding*(keccak?22u:26u));atomicAdd(j.range8,padding*(keccak?19u:73u));}
 if(store){
  #pragma unroll 1
  for(uint32_t c=0;c<width;++c)j.main[uint64_t(c)*n+physical]=row[c];
 }
 __syncthreads();
 for(uint32_t i=threadIdx.x;i<256;i+=blockDim.x)if(h8[i])atomicAdd(j.range8+i,h8[i]);
}
// -1 = read STWO_RV64_M8_WITNESS_COALESCE once; tests may set 0/1 directly.
static int bridge_coalesce=-1;
static bool witness_coalesce(){
 if(bridge_coalesce<0){const char*v=nullptr;bridge_coalesce=!(v&&v[0]=='0'&&!v[1]); /* default ON (M8 opt-combined); kernel parity bit-exact [M] */}
 return bridge_coalesce==1;
}
} }
extern "C" __attribute__((visibility("default"))) int stwo_rv64_bridge_witness_on(void*ctx,uint32_t lane,const StwoRv64BridgeWitness*input){
 using namespace stwo::cuda::rv64;
 if(!input||input->kind>1||input->log<5||input->log>24||!input->first_id||input->first_id>=0x7fffffffu)return int(cudaErrorInvalidValue);
 const auto j=*input;const bool k=j.kind==0;const uint64_t n=1ull<<j.log;const uint32_t width=k?66:134;
 if((k&&(j.coordinates!=25||j.write_mask))||(!k&&(!j.coordinates||j.coordinates>6||j.write_mask>>j.coordinates))||uint64_t(j.calls)*j.coordinates>=n||uint64_t(j.first_id)+j.calls>0x7fffffffull||n*(k?22u:26u)>=0x7fffffffull||n*(k?19u:73u)>=0x7fffffffull||j.input_words!=uint64_t(j.calls)*(4+8*(k?25u:4*j.coordinates))||j.main_words<n*width)return int(cudaErrorInvalidValue);
 Custody c(ctx,lane);if((j.calls&&!c.range(j.inputs,j.input_words,false))||!c.range(j.main,n*width,true)||!c.range(j.range16,65536,true)||!c.range(j.range8,256,true)||!c.range(j.status,1,true))return c.status;
 if(bridge::witness_coalesce())bridge::witness_private<<<(n+127)/128,128,0,c.stream>>>(j);
 else bridge::witness<<<(n+127)/128,128,0,c.stream>>>(j);
 return int(cudaPeekAtLastError());
}
