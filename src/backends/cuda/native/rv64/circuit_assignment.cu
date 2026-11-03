#include "circuit_assignment.h"
#include "custody.cuh"
#include "../oods/field.cuh"
namespace stwo::cuda::circuit_assignment {
namespace q=stwo::cuda::oods;
__host__ __device__ __forceinline__ q::QM31 load(const uint32_t*p,uint32_t i) {p+=uint64_t(i)*4;return{{p[0],p[1]},{p[2],p[3]}};}
__host__ __device__ __forceinline__ void store(uint32_t*p,uint32_t i,q::QM31 v){p+=uint64_t(i)*4;p[0]=v.a.a;p[1]=v.a.b;p[2]=v.b.a;p[3]=v.b.b;}
__host__ __device__ __forceinline__ bool zero(q::QM31 x){return !(x.a.a|x.a.b|x.b.a|x.b.b);}
__host__ __device__ __forceinline__ uint32_t word(q::QM31 v){return v.a.a|(v.a.b<<16);}
__host__ __device__ __forceinline__ q::QM31 packed(uint32_t v){return{{v&65535,v>>16},{0,0}};}
__host__ __device__ __forceinline__ uint32_t ror(uint32_t x,unsigned n){return(x>>n)|(x<<(32-n));}
__device__ void fail(uint32_t*p){atomicOr(p,1u);}
__device__ void at(const StwoCircuitAssignmentJob &j,const StwoCircuitAssignmentTask &t){
  if(t.kind>11||t.out>=j.value_count){fail(j.status);return;}
  unsigned arity=t.kind<=3?2:t.kind==4?3:t.kind==6?6:t.kind==9?2:1;
  if(t.kind==7){
    const uint32_t base=t.args[0],count=t.args[1];
    if(uint64_t(base)+uint64_t(count)*2>j.index_count){fail(j.status);return;}
    // Stable rank gives the original sort-by-u permutation without temporary
    // wide assignments or host hints. Each input/output variable is checked.
    for(uint32_t i=0;i<count;++i){
      const auto vi=j.indices[base+i];if(vi>=j.value_count){fail(j.status);return;}
      const auto x=load(j.values,vi);uint32_t rank=0;
      for(uint32_t k=0;k<count;++k){const auto vk=j.indices[base+k];if(vk>=j.value_count){fail(j.status);return;}const auto y=load(j.values,vk);rank+=(y.b.a<x.b.a||(y.b.a==x.b.a&&k<i));}
      const auto out=j.indices[base+count+rank];if(out>=j.value_count){fail(j.status);return;}store(j.values,out,x);
    }return;
  }
  q::QM31 x[6];for(unsigned i=0;i<arity;++i){if(t.args[i]>=j.value_count){fail(j.status);return;}x[i]=load(j.values,t.args[i]);}
  q::QM31 v{};
  switch(t.kind){
    case 0:v=q::add(x[0],x[1]);break;
    case 1:v=q::sub(x[0],x[1]);break;
    case 2:v=q::mul(x[0],x[1]);break;
    case 3:v={{q::mul(x[0].a.a,x[1].a.a),q::mul(x[0].a.b,x[1].a.b)},{q::mul(x[0].b.a,x[1].b.a),q::mul(x[0].b.b,x[1].b.b)}};break;
    case 4:v=packed(word(x[0])^word(x[1])^word(x[2]));break;
    case 5:v=packed(x[0].a.a);break;
    case 6:{
      if(uint64_t(t.out)+4>j.value_count){fail(j.status);return;}
      uint32_t a=word(x[0]),b=word(x[1]),c=word(x[2]),d=word(x[3]);
      a=a+b+word(x[4]);d=ror(d^a,16);c+=d;b=ror(b^c,12);a=a+b+word(x[5]);d=ror(d^a,8);c+=d;b=ror(b^c,7);
      store(j.values,t.out,packed(a));store(j.values,t.out+1,packed(b));store(j.values,t.out+2,packed(c));store(j.values,t.out+3,packed(d));return;
    }
    case 8:if(zero(x[0])){fail(j.status);return;}v=q::inverse(x[0]);break;
    case 9:if(zero(x[1])){fail(j.status);return;}v=q::mul(x[0],q::inverse(x[1]));break;
    case 10:{const auto a=x[0];v={{a.a.a?q::inverse(a.a.a):0,a.a.b?q::inverse(a.a.b):0},{a.b.a?q::inverse(a.b.a):0,a.b.b?q::inverse(a.b.b):0}};break;}
    case 11:{const auto a=x[0];v={{a.a.a&1,a.a.b&1},{a.b.a&1,a.b.b&1}};break;}
    default:fail(j.status);return;
  }
  store(j.values,t.out,v);
}
__global__ void seed(StwoCircuitAssignmentJob j){const auto i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=j.count)return;const auto &s=static_cast<const StwoCircuitAssignmentSeed*>(j.records)[j.first+i];if(s.out>=j.value_count){fail(j.status);return;}for(unsigned k=0;k<4;++k)if(s.value[k]>=q::kPrime){fail(j.status);return;}store(j.values,s.out,{{s.value[0],s.value[1]},{s.value[2],s.value[3]}});}
__global__ void level(StwoCircuitAssignmentJob j){const auto i=blockIdx.x*blockDim.x+threadIdx.x;if(i<j.count)at(j,static_cast<const StwoCircuitAssignmentTask*>(j.records)[j.first+i]);}
}
namespace {
bool valid(const StwoCircuitAssignmentJob *j){return j&&!j->reserved&&j->value_count&&j->value_count<(1u<<31)&&j->count&&uint64_t(j->first)+j->count<=j->record_count;}
}
extern "C" int stwo_circuit_assignment_seed_on(void*ctx,uint32_t lane,const StwoCircuitAssignmentJob*j){
  using namespace stwo::cuda::rv64;if(!valid(j))return int(cudaErrorInvalidValue);Custody c(ctx,lane);
  if(!c.range(j->values,uint64_t(j->value_count)*4,true)||!c.range(static_cast<const uint32_t*>(j->records),uint64_t(j->record_count)*5,false)||!c.range(j->status,1,true))return c.status;
  stwo::cuda::circuit_assignment::seed<<<(j->count+127)/128,128,0,c.stream>>>(*j);return int(cudaPeekAtLastError());
}
extern "C" int stwo_circuit_assignment_level_on(void*ctx,uint32_t lane,const StwoCircuitAssignmentJob*j){
  using namespace stwo::cuda::rv64;if(!valid(j))return int(cudaErrorInvalidValue);Custody c(ctx,lane);
  if(!c.range(j->values,uint64_t(j->value_count)*4,true)||!c.range(static_cast<const uint32_t*>(j->records),uint64_t(j->record_count)*8,false)||!c.range(j->status,1,true)||(j->index_count&&!c.range(j->indices,j->index_count,false)))return c.status;
  stwo::cuda::circuit_assignment::level<<<(j->count+127)/128,128,0,c.stream>>>(*j);return int(cudaPeekAtLastError());
}
