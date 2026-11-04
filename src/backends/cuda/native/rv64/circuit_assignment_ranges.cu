#include "circuit_assignment_ranges.h"
#include <cstdint>
#include <cstddef>
#include <climits>
#ifndef STWO_CIRCUIT_RANGE_HOST_EMULATION
#include <cuda_runtime_api.h>
#endif
extern "C" int stwo_exec_context_lane_stream(void*,uint32_t,void**);
extern "C" int stwo_exec_context_validate_allocation(void*,const void*,size_t);
namespace {
bool metadata(const StwoCircuitAssignmentRangeJob *j) {
  if(!j||!j->session||j->reserved||j->full_count<3||j->full_count>=(1u<<31)||j->prefix_count<3||j->prefix_count>=j->full_count||!j->range_count||j->range_count>4) return false;
  if(j->values.kind||j->status.kind||j->values.reserved||j->status.reserved||!j->values.context_token||j->values.context_token!=j->status.context_token||!j->values.generation||!j->status.generation||j->values.count!=uint64_t(j->full_count)*4||j->status.count!=1) return false;
  uint64_t next=j->prefix_count;
  for(unsigned i=0;i<4;++i){const auto&r=j->ranges[i];
    if(i>=j->range_count){if(r.first||r.count||r.value||r.reserved)return false;continue;}
    if(r.reserved||!r.count||(r.value!=0&&r.value!=2)||r.first!=next)return false;
    next+=r.count;if(next>j->full_count)return false;
  }
  return next==j->full_count;
}
#ifndef STWO_CIRCUIT_RANGE_HOST_EMULATION
__global__ void fill(uint32_t *values,StwoCircuitAssignmentRange r){
  const uint32_t i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=r.count)return;
  uint32_t*p=values+uint64_t(r.first+i)*4;p[0]=r.value;p[1]=p[2]=p[3]=0;
}
#endif
}
extern "C" int stwo_circuit_assignment_ranges_on(void*ctx,uint32_t lane,const StwoCircuitAssignmentRangeJob*j){
  if(!metadata(j))return 1;
  void*stream=nullptr;int rc=stwo_exec_context_lane_stream(ctx,lane,&stream);if(rc||!stream)return rc?rc:1;
  if(stwo_rv64_gpu_lease_validate(j->session,&j->values,j->scope)||stwo_rv64_gpu_lease_validate(j->session,&j->status,j->scope))return 1;
  if(stwo_exec_context_validate_allocation(ctx,j->values.words,j->values.count*4)||stwo_exec_context_validate_allocation(ctx,j->status.words,4))return 1;
  const auto begin=reinterpret_cast<uintptr_t>(j->values.words),status=reinterpret_cast<uintptr_t>(j->status.words);
  if(!begin||!status||j->values.count>(UINTPTR_MAX-begin)/4||status>UINTPTR_MAX-4)return 1;
  if(begin<status+4&&status<begin+j->values.count*4)return 1;
  // Every descriptor/lease is validated before the first enqueue. Only the
  // existing full mutable values lease is written; seed/status bits persist.
  for(unsigned r=0;r<j->range_count;++r){
#ifdef STWO_CIRCUIT_RANGE_HOST_EMULATION
    for(uint32_t i=0;i<j->ranges[r].count;++i){auto*p=j->values.words+uint64_t(j->ranges[r].first+i)*4;p[0]=j->ranges[r].value;p[1]=p[2]=p[3]=0;}
#else
    fill<<<(j->ranges[r].count+255)/256,256,0,reinterpret_cast<cudaStream_t>(stream)>>>(j->values.words,j->ranges[r]);
    rc=int(cudaPeekAtLastError());if(rc)return rc;
#endif
  }
  return 0;
}
