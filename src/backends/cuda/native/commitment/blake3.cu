// Allocation-free canonical BLAKE3 commitments/transcript on one proof stream.
#include "blake3_protocol.cuh"
#include "resident_layout.cuh"
#include <cuda_runtime_api.h>
#include <limits.h>
namespace stwo::cuda::blake3 {
namespace range = stwo::cuda::blake2s; // Checked address arithmetic only.
constexpr uint32_t threads=128, max_segments=96;
struct Segment { const uint32_t *columns; size_t stride, capacity; uint32_t size, reserved; };
struct Segments { Segment items[max_segments]; };
static_assert(sizeof(Segment)==32 && sizeof(Segments)+64<4096);
inline bool pow2(uint32_t n) {return n && !(n&(n-1));}
inline uint32_t blocks(uint32_t n) {return (n-1)/threads+1;}
__device__ uint32_t lifted(uint32_t row,uint32_t size,uint32_t source) {
 if(source==1)return 0;
 const uint32_t shift=__ffs(size/source)-1;
 return shift ? ((row>>(shift+1))<<1)|(row&1) : row;
}
__global__ void mixed(uint32_t size,uint32_t count,Segments inputs,uint32_t seed_size,const State *seed,State *prefix,Hash *out) {
 const uint32_t row=blockIdx.x*blockDim.x+threadIdx.x; if(row>=size)return;
 State s; if(seed)s=seed[lifted(row,size,seed_size)]; else stwo_blake3_leaf_init(s);
 for(uint32_t k=0;k<count;++k) {const Segment d=inputs.items[k]; const uint32_t at=lifted(row,size,d.size);
  for(size_t j=0;j<d.capacity/d.stride;++j) stwo_blake3_word(s,d.columns[j*d.stride+at]);
 }
 if(prefix)prefix[row]=s; else stwo_blake3_words_finish(s,out[row].words);
}
__global__ void init_states(uint32_t n,State *states) {uint32_t i=blockIdx.x*blockDim.x+threadIdx.x;if(i<n)stwo_blake3_leaf_init(states[i]);}
__global__ void absorb(uint32_t n,uint32_t source,const uint32_t *values,size_t stride,uint32_t count,State *states) {
 uint32_t i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=n)return;State s=states[i];
 uint32_t at=lifted(i,n,source);for(uint32_t j=0;j<count;++j)stwo_blake3_word(s,values[size_t(j)*stride+at]);states[i]=s;
}
__global__ void finish(uint32_t n,const State *states,Hash *out) {uint32_t i=blockIdx.x*blockDim.x+threadIdx.x;if(i<n){State s=states[i];stwo_blake3_words_finish(s,out[i].words);}}
__global__ void nodes(uint32_t n,const Hash *in,Hash *out) {uint32_t i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=n)return;uint32_t words[16];for(int j=0;j<8;++j){words[j]=in[2*i].words[j];words[j+8]=in[2*i+1].words[j];}stwo_zig_blake3_parent(words,out[i].words);}
__global__ void fri(uint32_t n,const uint32_t *coords,size_t stride,uint32_t fold_log,Hash *out) {
 uint32_t i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=(n>>fold_log))return;State s;stwo_blake3_leaf_init(s);
 for(uint32_t row=0;row<(1u<<fold_log);++row)for(uint32_t c=0;c<4;++c)stwo_blake3_word(s,coords[c*stride+(i<<fold_log)+row]);
 stwo_blake3_words_finish(s,out[i].words);
}
// Batched framed contiguous words: independent canonical leaf/transcript oracle seam.
__global__ void messages(uint32_t count,const uint32_t *in,size_t stride,uint32_t words,uint32_t domain,Hash *out) {
 uint32_t i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=count)return;State s;stwo_blake3_frame_init(s,domain);
 for(uint32_t j=0;j<words;++j)stwo_blake3_word(s,in[size_t(i)*stride+j]);stwo_blake3_words_finish(s,out[i].words);
}
__global__ void channel(Channel *state,uint32_t *data,uint32_t count,uint32_t operation,uint32_t max_blocks) {
 if(blockIdx.x||threadIdx.x)return;if(operation!=0&&state->error)return;
 State s;
 if(operation==0){state->error=0;stwo_blake3_frame_init(s,0);stwo_blake3_words_finish(s,state->digest);state->counter[0]=state->counter[1]=0;return;}
 if(operation!=5 && operation!=9) {
  stwo_blake3_frame_init(s,operation);for(int j=0;j<8;++j)stwo_blake3_word(s,state->digest[j]);
  if(operation==1||operation==2){stwo_blake3_word(s,operation==2?count/4:count);stwo_blake3_word(s,0);}
  for(uint32_t j=0;j<count;++j)stwo_blake3_word(s,data[j]);stwo_blake3_words_finish(s,state->digest);state->counter[0]=state->counter[1]=0;return;
 }
 uint64_t counter=uint64_t(state->counter[0])|(uint64_t(state->counter[1])<<32);
 uint64_t produced=0,target=uint64_t(count)*(operation==5?4:8);uint32_t attempted=0;
 while(produced<target) {
  if(counter==UINT64_MAX||attempted++==max_blocks){state->error=1;return;}
  stwo_blake3_frame_init(s,5);for(int j=0;j<8;++j)stwo_blake3_word(s,state->digest[j]);stwo_blake3_word(s,uint32_t(counter));stwo_blake3_word(s,uint32_t(counter>>32));
  uint32_t digest[8];stwo_blake3_words_finish(s,digest);++counter;bool valid=true;
  if(operation==5){for(int j=0;j<8;++j)if(digest[j]>=0xfffffffeu)valid=false;if(!valid)continue;
   for(int j=0;j<8;++j)if(digest[j]>=0x7fffffffu)digest[j]-=0x7fffffffu;
  }
  for(int j=0;j<8&&produced<target;++j)data[produced++]=digest[j];
 }
 state->counter[0]=uint32_t(counter);state->counter[1]=uint32_t(counter>>32);
}
__global__ void init_nonce(unsigned long long *out){if(!threadIdx.x&&!blockIdx.x)*out=ULLONG_MAX;}
__global__ void grind(const Channel *state,uint32_t bits,uint64_t first,uint32_t count,unsigned long long *out) {
 __shared__ uint32_t cv[8];
 if(threadIdx.x==0){State s;stwo_blake3_frame_init(s,6);for(int j=0;j<8;++j)stwo_blake3_word(s,state->digest[j]);stwo_blake3_word(s,bits);uint32_t h[16];stwo_blake3_compress(s.cv,s.block,0,64,1,h);for(int j=0;j<8;++j)cv[j]=h[j];}__syncthreads();
 const uint64_t index=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;if(index>=count||state->error)return;
 uint64_t nonce=first+index;uint32_t block[16]={},h[16];block[0]=uint32_t(nonce);block[1]=uint32_t(nonce>>32);stwo_blake3_compress(cv,block,0,8,10,h);
 const uint32_t zeros=h[0]==0?32:uint32_t(__ffs(h[0])-1);if(zeros>=bits)atomicMin(out,(unsigned long long)nonce);
}
inline int invalid(){return int(cudaErrorInvalidValue);}
inline bool disjoint(const void *a,size_t as,const void *b,size_t bs){range::DeviceRange x{},y{};return range::byte_range(a,as,4,&x)&&range::byte_range(b,bs,4,&y)&&!range::ranges_overlap(x,y);}
} // namespace
using namespace stwo::cuda::blake3;
extern "C" int stwo_blake3_mixed_seeded_on(uint32_t size,uint32_t count,const Segment *segments,uint32_t absorbed_before,uint32_t seed_size,const State *seed,State *prefix,Hash *out,void *stream){
 if(!stream||!pow2(size)||!segments||!count||count>max_segments||((prefix==nullptr)==(out==nullptr)))return invalid();
 const void *destination=prefix?static_cast<void*>(prefix):static_cast<void*>(out);size_t bytes=size_t(size)*(prefix?sizeof(State):sizeof(Hash));
 if(seed){if(!absorbed_before||!pow2(seed_size)||seed_size>size||!disjoint(seed,size_t(seed_size)*sizeof(State),destination,bytes))return invalid();}
 else if(absorbed_before||seed_size)return invalid();
 Segments inputs{};uint64_t total=absorbed_before;
 for(uint32_t i=0;i<count;++i){const Segment d=segments[i];range::DeviceRange r{};uint32_t columns=0;
  if(d.reserved||!pow2(d.size)||d.size>size||!range::exact_word_slab_range(d.columns,d.capacity,d.stride,d.size,&columns,&r)||!disjoint(d.columns,d.capacity*4,destination,bytes))return invalid();
  total+=columns;if(total>UINT32_MAX)return invalid();inputs.items[i]=d;
 }
 mixed<<<blocks(size),threads,0,(cudaStream_t)stream>>>(size,count,inputs,seed_size,seed,prefix,out);return int(cudaPeekAtLastError());
}
extern "C" int stwo_blake3_mixed_leaf_on(uint32_t size,uint32_t count,const Segment *segments,Hash *out,void *stream){return stwo_blake3_mixed_seeded_on(size,count,segments,0,0,nullptr,nullptr,out,stream);}
extern "C" int stwo_blake3_contiguous_leaf_on(uint32_t size,const uint32_t *values,size_t stride,size_t capacity,Hash *out,void *stream){Segment s{values,stride,capacity,size,0};return stwo_blake3_mixed_leaf_on(size,1,&s,out,stream);}
extern "C" int stwo_blake3_progressive_init_on(uint32_t size,State *states,void *stream){if(!pow2(size)||!states||!stream)return invalid();init_states<<<blocks(size),threads,0,(cudaStream_t)stream>>>(size,states);return int(cudaPeekAtLastError());}
extern "C" int stwo_blake3_progressive_absorb_lifted_on(uint32_t size,uint32_t source,uint32_t before,const uint32_t *values,size_t stride,size_t capacity,State *states,void *stream){
 range::DeviceRange r{};uint32_t cols=0;if(!pow2(size)||!pow2(source)||source>size||!stream||!range::exact_word_slab_range(values,capacity,stride,source,&cols,&r)||uint64_t(before)+cols>UINT32_MAX||!disjoint(values,capacity*4,states,size_t(size)*sizeof(State)))return invalid();
 absorb<<<blocks(size),threads,0,(cudaStream_t)stream>>>(size,source,values,stride,cols,states);return int(cudaPeekAtLastError());
}
extern "C" int stwo_blake3_progressive_finalize_on(uint32_t size,uint32_t count,const State *states,Hash *out,void *stream){(void)count;if(!pow2(size)||!stream||!disjoint(states,size_t(size)*sizeof(State),out,size_t(size)*sizeof(Hash)))return invalid();finish<<<blocks(size),threads,0,(cudaStream_t)stream>>>(size,states,out);return int(cudaPeekAtLastError());}
extern "C" int stwo_blake3_layer_on(const Hash *in,uint32_t count,Hash *out,void *stream){if(!pow2(count)||!stream||!disjoint(in,size_t(count)*2*sizeof(Hash),out,size_t(count)*sizeof(Hash)))return invalid();nodes<<<blocks(count),threads,0,(cudaStream_t)stream>>>(count,in,out);return int(cudaPeekAtLastError());}
extern "C" int stwo_blake3_fri_leaf_on(uint32_t size,const uint32_t *coords,size_t stride,size_t capacity,uint32_t fold_log,Hash *out,void *stream){
 range::DeviceRange r{};uint32_t count=0;if(!pow2(size)||(fold_log!=0&&fold_log!=2)||size<(1u<<fold_log)||!stream||!range::exact_word_slab_range(coords,capacity,stride,size,&count,&r)||count!=4||!disjoint(coords,capacity*4,out,size_t(size>>fold_log)*sizeof(Hash)))return invalid();
 fri<<<blocks(size>>fold_log),threads,0,(cudaStream_t)stream>>>(size,coords,stride,fold_log,out);return int(cudaPeekAtLastError());
}
extern "C" int stwo_blake3_framed_words_on(uint32_t count,const uint32_t *words,size_t stride,size_t capacity,uint32_t length,uint32_t domain,Hash *out,void *stream){
 if(!count||!length||length>stride||stride>SIZE_MAX/count||capacity!=stride*count||domain>8||!stream||!disjoint(words,capacity*4,out,size_t(count)*sizeof(Hash)))return invalid();
 messages<<<blocks(count),threads,0,(cudaStream_t)stream>>>(count,words,stride,length,domain,out);return int(cudaPeekAtLastError());
}
extern "C" int stwo_blake3_channel_on(Channel *state,uint32_t *data,size_t capacity,uint32_t count,uint32_t operation,uint32_t max_blocks,void *stream){
 if(!state||!stream||operation>9||operation==6||operation==7||operation==8)return invalid();
 if((operation==0&&count)||(operation==2&&count%4)||(operation==3&&count!=2)||(operation==4&&count!=8))return invalid();
 uint64_t needed=uint64_t(count)*(operation==5?4:operation==9?8:1);
 if(needed>capacity||(needed&&!disjoint(state,sizeof(Channel),data,size_t(needed)*4)))return invalid();
 if((operation==5||operation==9)&&max_blocks==0)return invalid();channel<<<1,1,0,(cudaStream_t)stream>>>(state,data,count,operation,max_blocks);return int(cudaPeekAtLastError());
}
extern "C" int stwo_blake3_pow_range_on(const Channel *state,uint32_t bits,uint64_t first,uint32_t count,unsigned long long *result,void *stream){
 if(!state||bits>32||!count||first>UINT64_MAX-count||!stream||reinterpret_cast<uintptr_t>(result)%alignof(unsigned long long)||!disjoint(state,sizeof(Channel),result,sizeof(*result)))return invalid();
 init_nonce<<<1,1,0,(cudaStream_t)stream>>>(result);grind<<<blocks(count),threads,0,(cudaStream_t)stream>>>(state,bits,first,count,result);return int(cudaPeekAtLastError());
}
namespace stwo::cuda::blake3 {
__global__ void query(Channel *state,uint32_t log,uint32_t count,uint32_t *out) {
 if(threadIdx.x||blockIdx.x||state->error)return;const uint32_t mask=log?(1u<<log)-1:0;
 uint64_t counter=uint64_t(state->counter[0])|(uint64_t(state->counter[1])<<32);uint32_t at=0;
 while(at<count){if(counter==UINT64_MAX){state->error=1;return;}State s;stwo_blake3_frame_init(s,5);for(int i=0;i<8;++i)stwo_blake3_word(s,state->digest[i]);stwo_blake3_word(s,uint32_t(counter));stwo_blake3_word(s,uint32_t(counter>>32));uint32_t h[8];stwo_blake3_words_finish(s,h);++counter;
  for(int i=0;i<8&&at<count;++i)out[at++]=h[i]&mask;
 }state->counter[0]=uint32_t(counter);state->counter[1]=uint32_t(counter>>32);
}
__global__ void grind_persistent(const Channel *state,uint32_t bits,uint64_t end,unsigned long long *out) {
 __shared__ uint32_t cv[8];if(threadIdx.x==0){State s;stwo_blake3_frame_init(s,6);for(int j=0;j<8;++j)stwo_blake3_word(s,state->digest[j]);stwo_blake3_word(s,bits);uint32_t h[16];stwo_blake3_compress(s.cv,s.block,0,64,1,h);for(int j=0;j<8;++j)cv[j]=h[j];}__syncthreads();if(state->error)return;
 const uint64_t stride=uint64_t(gridDim.x)*blockDim.x;
 for(uint64_t nonce=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;nonce<end;){
  if(nonce>=atomicAdd(out,0ull))break;uint32_t block[16]={},h[16];block[0]=uint32_t(nonce);block[1]=uint32_t(nonce>>32);stwo_blake3_compress(cv,block,0,8,10,h);
  if((h[0]?uint32_t(__ffs(h[0])-1):32)>=bits){atomicMin(out,(unsigned long long)nonce);break;}
  if(end-nonce<=stride)break;nonce+=stride;
 }
}
__global__ void finish_pow(Channel *state,const unsigned long long *nonce) {
 if(threadIdx.x||blockIdx.x||state->error)return;if(*nonce==ULLONG_MAX){state->error=2;return;}
 State s;stwo_blake3_frame_init(s,3);for(int i=0;i<8;++i)stwo_blake3_word(s,state->digest[i]);stwo_blake3_word(s,uint32_t(*nonce));stwo_blake3_word(s,uint32_t(*nonce>>32));stwo_blake3_words_finish(s,state->digest);state->counter[0]=state->counter[1]=0;
}
__global__ void verdict(const Channel *states,uint32_t count,uint32_t *out) {uint32_t i=blockIdx.x*blockDim.x+threadIdx.x;if(i<count&&states[i].error)atomicOr(out,1u);}
}
extern "C" int stwo_blake3_query_on(Channel *state,uint32_t log,uint32_t count,uint32_t *out,size_t capacity,void *stream){
 if(!state||log>=32||!count||capacity<count||!stream||!disjoint(state,sizeof(Channel),out,size_t(count)*4))return invalid();query<<<1,1,0,(cudaStream_t)stream>>>(state,log,count,out);return int(cudaPeekAtLastError());
}
extern "C" int stwo_blake3_grind_on(Channel *state,uint32_t bits,uint64_t end,uint32_t grid,unsigned long long *nonce,void *stream){
 if(!state||bits>32||!end||!grid||grid>65536||!stream||reinterpret_cast<uintptr_t>(nonce)%alignof(unsigned long long)||!disjoint(state,sizeof(Channel),nonce,sizeof(*nonce)))return invalid();
 init_nonce<<<1,1,0,(cudaStream_t)stream>>>(nonce);grind_persistent<<<grid,threads,0,(cudaStream_t)stream>>>(state,bits,end,nonce);finish_pow<<<1,1,0,(cudaStream_t)stream>>>(state,nonce);return int(cudaPeekAtLastError());
}
extern "C" int stwo_blake3_channel_verdict_on(const Channel *states,uint32_t count,uint32_t *out,void *stream){if(!count||!stream||!disjoint(states,size_t(count)*sizeof(Channel),out,4))return invalid();verdict<<<blocks(count),threads,0,(cudaStream_t)stream>>>(states,count,out);return int(cudaPeekAtLastError());}
