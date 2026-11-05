// Project the hybrid binding directly from authenticated original MAIN/FIXED.
// No numerator/denominator arrays are materialized, including at the late draw.
#include "outer_gkr_projector.cuh"
struct StwoCircuitOuterBinding {
  StwoCircuitOuterGkrSource source;
  const uint32_t *metadata; //26 lane weights, gamma, verified target/rows
  StwoRv64Plane eq, prefix;
};
static_assert(sizeof(StwoCircuitOuterBinding)==120,"outer binding ABI");
namespace stwo::cuda::rv64::outer_gkr {
template<unsigned Kind,unsigned Term=0>
__device__ OM31 projected_row(Source<Kind> source,const uint32_t*metadata,uint32_t row,OM31 gamma) {
  if constexpr(Term<tuples::lookup_count<Kind>()) {
    const auto f=source.template at_row<Term>(row);
    const OM31 weight=from_words(metadata+8*Term);
    if(!canonical(weight)){source.fail(4u);return zero();}
    return add(mul(weight,add(f.n,mul(gamma,f.d))),projected_row<Kind,Term+1>(source,metadata,row,gamma));
  }
  return zero();
}
template<unsigned Kind>
__global__ void binding_rows(StwoCircuitOuterBinding job) {
  const uint32_t row=blockIdx.x*blockDim.x+threadIdx.x;
  if(row>=(1u<<job.source.row_log))return;
  Source<Kind> source{job.source};
  const OM31 gamma=from_words(job.metadata+8*26),target=from_words(job.metadata+8*27);
  const OM31 eq=load(job.eq.words,job.eq.stride,row);
  if(!canonical(gamma)||!canonical(target)||!canonical(eq)){
    source.fail(4u);store(job.prefix.words,job.prefix.stride,row,zero());return;
  }
  const OM31 projection=projected_row<Kind>(source,job.metadata,row,gamma);
  store(job.prefix.words,job.prefix.stride,row,sub(mul(eq,projection),target));
}
template<unsigned Kind>
int bind(void*ctx,uint32_t lane,const StwoCircuitOuterBinding &job) {
  Custody c(ctx,lane);const uint32_t rows=1u<<job.source.row_log;
  const Source<Kind> source{job.source};
  if(!source.validate(c,1u<<(job.source.row_log+job.source.lane_log))||
     !c.range(job.metadata,28*8,false)||!c.plane(job.eq,rows,8,false)||!c.plane(job.prefix,rows,8,true))return c.status;
  binding_rows<Kind><<<(rows+127)/128,128,0,c.stream>>>(job);
  return int(cudaPeekAtLastError());
}
}
extern "C" int stwo_circuit_outer_gkr_binding_on(void*ctx,uint32_t lane,const StwoCircuitOuterBinding*raw) {
  using namespace stwo::cuda::rv64::outer_gkr;
  if(!raw||!valid_source(raw->source))return int(cudaErrorInvalidValue);
  const auto job=*raw;
  switch(job.source.component){case 2:return bind<2>(ctx,lane,job);case 3:return bind<3>(ctx,lane,job);case 4:return bind<4>(ctx,lane,job);case 6:return bind<6>(ctx,lane,job);default:return int(cudaErrorInvalidValue);}
}
