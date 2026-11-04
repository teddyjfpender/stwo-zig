#pragma once
#include "pcs_native.h"
struct StwoCircuitAssignmentRange { uint32_t first,count,value,reserved; };
struct StwoCircuitAssignmentRangeJob {
  void *session;
  StwoRv64GpuLease values,status;
  uint32_t scope[8],full_count,prefix_count,range_count,reserved;
  StwoCircuitAssignmentRange ranges[4];
};
static_assert(sizeof(StwoCircuitAssignmentRange)==16);
static_assert(sizeof(StwoCircuitAssignmentRangeJob)==200);
extern "C" int stwo_circuit_assignment_ranges_on(void*,uint32_t,const StwoCircuitAssignmentRangeJob*);
