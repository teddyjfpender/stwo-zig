#include "rc_sparse_lde.h"
#include "custody.cuh"
#include "rc_sparse_private/n2b_fused.cuh"
#include <vector>
#include <cstring>
#include <new>
extern "C" int stwo_rv64_gpu_lease_validate_range(void*,const uint32_t*,uint64_t,uint64_t,uint64_t,const uint32_t*);
extern "C" int stwo_exec_context_memcpy_h2d_async(void*,void*,const void*,size_t);
static_assert(sizeof(StwoRv64SparseLease)==40);
static_assert(sizeof(StwoRv64SparseColumn)==32);
extern "C" int stwo_rv64_rc_sparse_lde_on(void*ctx,uint32_t lane,const StwoRv64SparseLde*j,uint32_t*launches){
  if(launches)*launches=0;
  if(!j||!launches||lane!=0||j->version!=1||j->reserved||!j->session||j->source_log!=18||j->eval_log!=20||
     !j->column_count||j->column_count>512||j->cache_slots!=1024||!j->sources||!j->slots||
     j->cache.kind||j->tables.kind||j->twiddles.kind||j->cache.reserved||j->tables.reserved||j->twiddles.reserved)
    return int(cudaErrorInvalidValue);
  constexpr uint64_t N=uint64_t(1)<<20,S=uint64_t(1)<<18;
  const uint64_t out_words=N*j->cache_slots,table_words=4*j->column_count;
  if(j->cache.count!=out_words||j->tables.count<table_words||j->twiddles.count<N/2||reinterpret_cast<uintptr_t>(j->tables.words)%8)
    return int(cudaErrorInvalidValue);
  stwo::cuda::rv64::RangeCustody<528> c(ctx,lane);
  const auto span=[](const uint32_t*p,uint64_t n){const uintptr_t b=reinterpret_cast<uintptr_t>(p);return p&&n&&!(b%4)&&n<=SIZE_MAX/4&&n<=(UINTPTR_MAX-b)/4;};
  if(!span(j->cache.words,out_words)||!span(j->tables.words,table_words)||!span(j->twiddles.words,N/2))return int(cudaErrorInvalidValue);
  const auto scoped=[&](const StwoRv64SparseLease&x,uint64_t n){
    return !stwo_rv64_gpu_lease_validate_range(j->session,x.words,n,x.context_token,x.generation,j->scope);
  };
  if(!scoped(j->cache,out_words)||!scoped(j->tables,table_words)||!scoped(j->twiddles,N/2))return int(cudaErrorInvalidValue);
  if(!c.range(j->cache.words,out_words,true)||!c.range(j->tables.words,table_words,true)||!c.range(j->twiddles.words,N/2,false))return c.status;
  bool occupied[1024]{};std::vector<uint32_t> words;
  try{words.resize(table_words);}catch(const std::bad_alloc&){return int(cudaErrorMemoryAllocation);}
  for(uint32_t i=0;i<j->column_count;++i){
    const auto&s=j->sources[i];const uint32_t slot=j->slots[i];
    if(slot>=j->cache_slots||occupied[slot]||s.count!=S||!span(s.words,S)||
       stwo_rv64_gpu_lease_validate_range(j->session,s.words,S,s.context_token,s.generation,j->scope))return int(cudaErrorInvalidValue);
    occupied[slot]=true;
    if(!c.range(s.words,S,false))return c.status;
    const uint64_t address=reinterpret_cast<uintptr_t>(s.words);words[2*i]=uint32_t(address);words[2*i+1]=uint32_t(address>>32);
    words[2*j->column_count+i]=18;words[3*j->column_count+i]=slot;
  }
  // The execution context copies pageable ingress into its owned pinned ring
  // before returning, so the temporary host vector never escapes this call.
  int status=stwo_exec_context_memcpy_h2d_async(ctx,j->tables.words,words.data(),words.size()*4);
  if(status)return status;
  using namespace stwo::cuda;using namespace stwo::cuda::rc_sparse_transform;
  const ColumnSlab<const M31> input{nullptr,0,reinterpret_cast<const uint64_t*>(j->tables.words),nullptr};
  const ColumnSlab<M31> output{reinterpret_cast<M31*>(j->cache.words),N,nullptr,j->tables.words+3*j->column_count};
  const auto*tw=reinterpret_cast<const M31*>(j->twiddles.words);
  status=int(launch_n2b_first_from_coefficients(input,j->tables.words+2*j->column_count,output,20,j->column_count,6,tw,c.stream));
  if(status)return status;
  status=int(launch_n2b_continue(output,20,j->column_count,7,6,tw,c.stream));
  if(status)return status;
  status=int(launch_n2b_final<true>(output,20,j->column_count,13,8,tw,c.stream));
  if(!status)*launches=3;
  return status;
}
