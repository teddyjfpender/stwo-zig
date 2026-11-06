#if defined(STWO_CIRCUIT_OM31_HOST_EMULATION)
#define STWO_CIRCUIT_INTERACTION_HOST_EMULATION
#endif
#include "circuit_interaction.h"
#include "om31.cuh"
#include "outer_gkr_projector.cuh"
#include "../circuit/lookup_tuples.cuh"
#ifndef STWO_CIRCUIT_OM31_HOST_EMULATION
#include "custody.cuh"
#endif
namespace stwo::cuda::rv64::circuit_outer {
namespace tuples=stwo::cuda::circuit_interaction;
using namespace stwo::cuda::rv64;
inline bool overlap(const uint32_t *a,uint64_t na,const uint32_t *b,uint64_t nb) {
  if(!na || !nb) return false;
  const uintptr_t pa=reinterpret_cast<uintptr_t>(a),pb=reinterpret_cast<uintptr_t>(b);
  return pa<=pb ? pb-pa<4*na : pa-pb<4*nb;
}
inline int validate(const StwoCircuitOm31Fractions &j) {
  if(j.component>=11 || j.row_log<4 || j.row_log>27 || j.reserved[0] || j.reserved[1] ||
     !j.main || !j.parameters || !j.numerators || !j.denominators || !j.status) return 1;
  const uint64_t rows=uint64_t(1)<<j.row_log;
  if(j.fixed_words!=rows*tuples::kPpWidths[j.component] ||
     j.main_words!=rows*tuples::kBaseWidths[j.component] ||
     j.numerator_words!=8*rows*tuples::kSecure[j.component] ||
     j.denominator_words!=j.numerator_words || (j.fixed_words && !j.fixed)) return 1;
  const uint32_t *outputs[]={j.numerators,j.denominators,j.status};
  const uint64_t output_words[]={j.numerator_words,j.denominator_words,1};
  const uint32_t *inputs[]={j.fixed,j.main,j.parameters};
  const uint64_t input_words[]={j.fixed_words,j.main_words,56};
  for(unsigned o=0;o<3;++o) {
    for(unsigned i=0;i<3;++i) if(overlap(outputs[o],output_words[o],inputs[i],input_words[i])) return 1;
    for(unsigned i=0;i<o;++i) if(overlap(outputs[o],output_words[o],outputs[i],output_words[i])) return 1;
  }
  return 0;
}
inline int validate_contributions(const StwoCircuitOm31Contributions &j) {
  if(j.component>=11 || j.row_log<4 || j.row_log>27 || j.reserved[0] || j.reserved[1] ||
     !j.main || !j.parameters || !j.output || !j.status) return 1;
  const uint64_t rows=uint64_t(1)<<j.row_log;
  if(j.fixed_words!=rows*tuples::kPpWidths[j.component] ||
     j.main_words!=rows*tuples::kBaseWidths[j.component] ||
     j.output_words!=8*rows*tuples::kSecure[j.component] || (j.fixed_words && !j.fixed)) return 1;
  const uint32_t *outputs[]={j.output,j.status};
  const uint64_t output_words[]={j.output_words,1};
  const uint32_t *inputs[]={j.fixed,j.main,j.parameters};
  const uint64_t input_words[]={j.fixed_words,j.main_words,56};
  for(unsigned o=0;o<2;++o) {
    for(unsigned i=0;i<3;++i) if(overlap(outputs[o],output_words[o],inputs[i],input_words[i])) return 1;
    for(unsigned i=0;i<o;++i) if(overlap(outputs[o],output_words[o],outputs[i],output_words[i])) return 1;
  }
  return 0;
}
__host__ __device__ __forceinline__ OM31 combine(const tuples::Lookup &lookup,const uint32_t *p) {
  OM31 result=sub(zero(),from_words(p));
  for(unsigned i=0;i<lookup.len;++i) result=add(result,scale(from_words(p+8*(i+1)),lookup.tuple[i]));
  return result;
}
template<unsigned Kind,class Job>
__host__ __device__ __forceinline__ Fraction fraction(const Job &j,unsigned row,unsigned pair) {
  const unsigned rows=1u<<j.row_log;
  tuples::Columns columns{};
  for(unsigned i=0;i<tuples::pp_width<Kind>();++i) columns.pp[i]=j.fixed+uint64_t(i)*rows;
  for(unsigned i=0;i<tuples::base_width<Kind>();++i) columns.base[i]=j.main+uint64_t(i)*rows;
  const auto first=tuples::lookup_at<Kind>(2*pair,row,columns);
  const auto d0=combine(first,j.parameters);
  OM31 n=base(first.numerator),d=d0;
  if(2*pair+1<tuples::lookup_count<Kind>()) {
    const auto second=tuples::lookup_at<Kind>(2*pair+1,row,columns);
    const auto d1=combine(second,j.parameters);
    n=add(scale(d1,first.numerator),scale(d0,second.numerator)); d=mul(d0,d1);
  }
  unsigned failure=(!canonical(n)||!canonical(d))?2u:0u;
  if(is_zero(d)) failure|=4u;
  if(failure) {
#if defined(__CUDA_ARCH__)
    atomicOr(j.status,failure);
#else
    *j.status|=failure;
#endif
  }
  return {n,d};
}
template<unsigned Kind>
__host__ __device__ __forceinline__ void at(const StwoCircuitOm31Fractions &j,unsigned row,unsigned pair) {
  const auto f=fraction<Kind>(j,row,pair);
  const unsigned rows=1u<<j.row_log;
  store(j.numerators+uint64_t(pair)*8*rows,rows,row,f.n);
  store(j.denominators+uint64_t(pair)*8*rows,rows,row,f.d);
}
#ifndef STWO_CIRCUIT_OM31_HOST_EMULATION
// Compile-time pair dispatch (kernels stream, M4). lookup_at loads every base
// column of the component into c[] and then switches on the lookup index;
// with a runtime index (blockIdx.y) nothing can be pruned, so each thread
// loaded all base columns (52 for Kind 4, the Blake G gate) into a 288-byte
// local array for two lookups. A constant pair lets every case keep only the
// columns it reads. Same arithmetic in the same order: identical fractions.
template<unsigned Kind,unsigned Pair>
__device__ __forceinline__ void at_pair(const StwoCircuitOm31Fractions &j,unsigned row) {
  if constexpr(Pair<tuples::kSecure[Kind]) at<Kind>(j,row,Pair);
}
template<unsigned Kind> __global__ void generate(StwoCircuitOm31Fractions j) {
  const unsigned row=blockIdx.x*blockDim.x+threadIdx.x;
  if(row>=(1u<<j.row_log)) return;
  static_assert(tuples::kSecure[Kind]<=13,"pair dispatch covers 13 pairs");
  switch(blockIdx.y) {
    case 0: at_pair<Kind,0>(j,row); break;
    case 1: at_pair<Kind,1>(j,row); break;
    case 2: at_pair<Kind,2>(j,row); break;
    case 3: at_pair<Kind,3>(j,row); break;
    case 4: at_pair<Kind,4>(j,row); break;
    case 5: at_pair<Kind,5>(j,row); break;
    case 6: at_pair<Kind,6>(j,row); break;
    case 7: at_pair<Kind,7>(j,row); break;
    case 8: at_pair<Kind,8>(j,row); break;
    case 9: at_pair<Kind,9>(j,row); break;
    case 10: at_pair<Kind,10>(j,row); break;
    case 11: at_pair<Kind,11>(j,row); break;
    case 12: at_pair<Kind,12>(j,row); break;
    default: break;
  }
}
__device__ __forceinline__ OM31 contribution_up(OM31 value,unsigned delta,unsigned mask) {
  uint32_t words[8];
#pragma unroll
  for(unsigned i=0;i<8;++i) words[i]=__shfl_up_sync(mask,coordinate(value,i),delta);
  return from_words(words);
}
__device__ __forceinline__ OM31 contribution_down(OM31 value,unsigned delta,unsigned mask) {
  uint32_t words[8];
#pragma unroll
  for(unsigned i=0;i<8;++i) words[i]=__shfl_down_sync(mask,coordinate(value,i),delta);
  return from_words(words);
}
__device__ __forceinline__ OM31 contribution_at(OM31 value,unsigned lane,unsigned mask) {
  uint32_t words[8];
#pragma unroll
  for(unsigned i=0;i<8;++i) words[i]=__shfl_sync(mask,coordinate(value,i),lane);
  return from_words(words);
}
template<unsigned Kind,unsigned Pair>
__device__ __forceinline__ void contribute_pair(const StwoCircuitOm31Contributions &j,unsigned row,unsigned mask) {
  if constexpr(Pair<tuples::kSecure[Kind]) {
    auto f=fraction<Kind>(j,row,Pair);
    // Match global_inverse_contribute's invalid-input substitution. The
    // original failure bits were already ORed by fraction().
    if(!canonical(f.n)||!canonical(f.d)||is_zero(f.d)) f={zero(),one()};
    OM31 prefix=f.d,suffix=f.d;
    const unsigned lane=threadIdx.x&31u,rows=1u<<j.row_log;
    const unsigned active_rows=rows<32?rows:32;
#pragma unroll
    for(unsigned delta=1;delta<active_rows;delta<<=1) {
      const OM31 before=contribution_up(prefix,delta,mask),after=contribution_down(suffix,delta,mask);
      if(lane>=delta) prefix=mul(prefix,before);
      if(lane+delta<active_rows) suffix=mul(suffix,after);
    }
    const OM31 total=contribution_at(prefix,active_rows-1,mask);
    const OM31 inv_total=contribution_at(lane==0?inverse_nonzero(total):zero(),0,mask);
    const OM31 previous=contribution_up(prefix,1,mask),next=contribution_down(suffix,1,mask);
    const OM31 inverse=mul(inv_total,mul(lane?previous:one(),lane+1<active_rows?next:one()));
    store(j.output+uint64_t(Pair)*8*rows,rows,row,mul(f.n,inverse));
  }
}
template<unsigned Kind> __global__ void contributions(StwoCircuitOm31Contributions j) {
  const unsigned row=blockIdx.x*blockDim.x+threadIdx.x;
  const unsigned mask=__ballot_sync(0xffffffffu,row<(1u<<j.row_log));
  if(row>=(1u<<j.row_log)) return;
  static_assert(tuples::kSecure[Kind]<=13,"pair dispatch covers13 pairs");
#define CONTRIBUTION_PAIR(N) case N: contribute_pair<Kind,N>(j,row,mask);break
  switch(blockIdx.y) {
    CONTRIBUTION_PAIR(0);CONTRIBUTION_PAIR(1);CONTRIBUTION_PAIR(2);CONTRIBUTION_PAIR(3);
    CONTRIBUTION_PAIR(4);CONTRIBUTION_PAIR(5);CONTRIBUTION_PAIR(6);CONTRIBUTION_PAIR(7);
    CONTRIBUTION_PAIR(8);CONTRIBUTION_PAIR(9);CONTRIBUTION_PAIR(10);CONTRIBUTION_PAIR(11);CONTRIBUTION_PAIR(12);
  }
#undef CONTRIBUTION_PAIR
}
#endif
} // namespace
#ifndef STWO_CIRCUIT_OM31_HOST_EMULATION
extern "C" int stwo_circuit_om31_contributions_v1_on(void *raw,uint32_t lane,const StwoCircuitOm31Contributions *input) {
  using namespace stwo::cuda::rv64;
  if(!input||circuit_outer::validate_contributions(*input)) return int(cudaErrorInvalidValue);
  const auto j=*input;Custody c(raw,lane);
  if((j.fixed_words&&!c.range(j.fixed,j.fixed_words,false))||!c.range(j.main,j.main_words,false)||
     !c.range(j.parameters,56,false)||!c.range(j.output,j.output_words,true)||!c.range(j.status,1,true)) return c.status;
  const dim3 grid(((1u<<j.row_log)+255)/256,stwo::cuda::circuit_interaction::kSecure[j.component]);
#define CONTRIBUTION_KIND(K) case K: circuit_outer::contributions<K><<<grid,256,0,c.stream>>>(j);break
  switch(j.component) {CONTRIBUTION_KIND(0);CONTRIBUTION_KIND(1);CONTRIBUTION_KIND(2);CONTRIBUTION_KIND(3);CONTRIBUTION_KIND(4);CONTRIBUTION_KIND(5);CONTRIBUTION_KIND(6);CONTRIBUTION_KIND(7);CONTRIBUTION_KIND(8);CONTRIBUTION_KIND(9);CONTRIBUTION_KIND(10);}
#undef CONTRIBUTION_KIND
  return int(cudaPeekAtLastError());
}
extern "C" int stwo_circuit_om31_fractions_on(void *raw,uint32_t lane,const StwoCircuitOm31Fractions *input) {
  using namespace stwo::cuda::rv64;
  if(!input || circuit_outer::validate(*input)) return int(cudaErrorInvalidValue);
  const auto j=*input;
  Custody c(raw,lane);
  if((j.fixed_words && !c.range(j.fixed,j.fixed_words,false)) || !c.range(j.main,j.main_words,false) ||
     !c.range(j.parameters,56,false) || !c.range(j.numerators,j.numerator_words,true) ||
     !c.range(j.denominators,j.denominator_words,true) || !c.range(j.status,1,true)) return c.status;
  const dim3 grid(((1u<<j.row_log)+255)/256,stwo::cuda::circuit_interaction::kSecure[j.component]);
#define OUTER_CASE(K) case K: circuit_outer::generate<K><<<grid,256,0,c.stream>>>(j);break
  switch(j.component) { OUTER_CASE(0);OUTER_CASE(1);OUTER_CASE(2);OUTER_CASE(3);OUTER_CASE(4);OUTER_CASE(5);OUTER_CASE(6);OUTER_CASE(7);OUTER_CASE(8);OUTER_CASE(9);OUTER_CASE(10); }
#undef OUTER_CASE
  return int(cudaPeekAtLastError());
}
#else
extern "C" int stwo_circuit_outer_gkr_project_emulate(const StwoCircuitOuterGkrSource *source,
                                                      uint32_t index, uint32_t *out) {
  using namespace stwo::cuda::rv64;
  if (!source || !out || !outer_gkr::valid_source(*source) ||
      index >= (1u << (source->row_log + source->lane_log))) return 1;
  Fraction fraction;
  switch (source->component) {
    case 2: fraction = outer_gkr::Source<2>{*source}(index); break;
    case 3: fraction = outer_gkr::Source<3>{*source}(index); break;
    case 4: fraction = outer_gkr::Source<4>{*source}(index); break;
    case 6: fraction = outer_gkr::Source<6>{*source}(index); break;
    default: return 1;
  }
  store(out, 1, 0, fraction.n);
  store(out + 8, 1, 0, fraction.d);
  return 0;
}
extern "C" int stwo_circuit_om31_fractions_emulate(const StwoCircuitOm31Fractions *j) {
  using namespace stwo::cuda::rv64;
  if(!j || circuit_outer::validate(*j)) return 1;
#define OUTER_CASE(K) case K: circuit_outer::at<K>(*j,row,pair);break
  for(unsigned pair=0;pair<stwo::cuda::circuit_interaction::kSecure[j->component];++pair)
    for(unsigned row=0;row<(1u<<j->row_log);++row)
      switch(j->component) { OUTER_CASE(0);OUTER_CASE(1);OUTER_CASE(2);OUTER_CASE(3);OUTER_CASE(4);OUTER_CASE(5);OUTER_CASE(6);OUTER_CASE(7);OUTER_CASE(8);OUTER_CASE(9);OUTER_CASE(10); }
#undef OUTER_CASE
  return 0;
}
#endif
#ifndef STWO_CIRCUIT_OM31_HOST_EMULATION
namespace stwo::cuda::rv64::circuit_outer {
__global__ void cumulative(StwoCircuitOm31Cumulative j) {
  const uint32_t row=blockIdx.x*blockDim.x+threadIdx.x,rows=1u<<j.row_log;
  if(row>=rows)return;
  OM31 total=zero();
  for(unsigned pair=0;pair+1<j.pairs;++pair){
    total=add(total,load(j.contributions+uint64_t(pair)*8*j.stride,j.stride,row));
    store(j.output+uint64_t(pair)*8*j.stride,j.stride,row,total);
  }
  uint32_t circle=0;
  for(unsigned i=0;i<j.row_log;++i)circle=(circle<<1)|((row>>i)&1u);
  const uint32_t logical=circle<rows/2?2*circle:2*(rows-1-circle)+1;
  const uint32_t inv_rows=1u<<(31-j.row_log);
  const uint32_t correction=q::sub(1u,q::mul(logical+1,inv_rows));
  const OM31 prefix=load(j.output+uint64_t(j.pairs)*8*j.stride,j.stride,row);
  store(j.output+uint64_t(j.pairs-1)*8*j.stride,j.stride,row,add(prefix,scale(from_words(j.claim),correction)));
}
}
extern "C" int stwo_circuit_om31_cumulative_on(void*raw,uint32_t lane,const StwoCircuitOm31Cumulative*input){
  using namespace stwo::cuda::rv64;
  if(!input||input->row_log<4||input->row_log>27||!input->pairs||input->pairs>13||input->stride<(1u<<input->row_log)||input->stride>SIZE_MAX/(8*uint64_t(input->pairs+1)))return int(cudaErrorInvalidValue);
  const auto j=*input;Custody c(raw,lane);
  if(!c.range(j.output,8*uint64_t(j.pairs+1)*j.stride,true)||!c.range(j.contributions,8*uint64_t(j.pairs)*j.stride,false)||!c.range(j.claim,8,false))return c.status;
  circuit_outer::cumulative<<<((1u<<j.row_log)+127)/128,128,0,c.stream>>>(j);
  return int(cudaPeekAtLastError());
}
extern "C" int stwo_circuit_om31_cumulative_inplace_v1_on(void*raw,uint32_t lane,const StwoCircuitOm31Cumulative*input){
  using namespace stwo::cuda::rv64;
  if(!input||input->contributions!=input->output||input->row_log<4||input->row_log>27||!input->pairs||input->pairs>13||input->stride<(1u<<input->row_log)||input->stride>SIZE_MAX/(8*uint64_t(input->pairs+1)))return int(cudaErrorInvalidValue);
  const auto j=*input;Custody c(raw,lane);
  // Validate the exact alias once as one owned writable span. Claim remains
  // disjoint; no partially overlapping contribution span is permitted.
  if(!c.range(j.output,8*uint64_t(j.pairs+1)*j.stride,true)||!c.range(j.claim,8,false))return c.status;
  circuit_outer::cumulative<<<((1u<<j.row_log)+127)/128,128,0,c.stream>>>(j);
  return int(cudaPeekAtLastError());
}
#endif
