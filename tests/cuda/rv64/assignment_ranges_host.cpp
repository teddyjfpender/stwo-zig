// CPU emulation of the optional range ABI; not a physical CUDA qualification.
#include "circuit_assignment_ranges.h"
#include <cassert>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <array>
static std::array<uint32_t,64> values;
static uint32_t status;
static StwoRv64GpuLease value_lease,status_lease;
extern "C" int stwo_exec_context_lane_stream(void*c,uint32_t lane,void**out){if(c!=(void*)1||lane!=1)return 1;*out=(void*)3;return 0;}
extern "C" int stwo_exec_context_validate_allocation(void*c,const void*p,size_t n){if(c!=(void*)1)return 1;return !((p==values.data()&&n==sizeof(values))||(p==&status&&n==4));}
extern "C" int stwo_rv64_gpu_lease_validate(void*s,const StwoRv64GpuLease*l,const uint32_t scope[8]){
 if(s!=(void*)2)return 1;for(unsigned i=0;i<8;++i)if(scope[i]!=7)return 1;
 const auto&e=l->words==values.data()?value_lease:status_lease;
 return l->words!=e.words||l->count!=e.count||l->context_token!=e.context_token||l->generation!=e.generation||l->kind!=e.kind||l->reserved;
}
static StwoCircuitAssignmentRangeJob good(){
 StwoCircuitAssignmentRangeJob j{};j.session=(void*)2;j.values=value_lease;j.status=status_lease;for(auto&v:j.scope)v=7;
 j.full_count=16;j.prefix_count=3;j.range_count=2;j.ranges[0]={3,4,2,0};j.ranges[1]={7,9,0,0};return j;
}
static void rejected(const StwoCircuitAssignmentRangeJob&j){auto before=values;const auto old=status;assert(stwo_circuit_assignment_ranges_on((void*)1,1,&j)!=0);assert(before==values&&old==status);}
int main(){
 value_lease={3,4,values.data(),values.size(),0,0};status_lease={3,5,&status,1,0,0};
 values.fill(0x12345678);status=0x80;auto j=good();assert(stwo_circuit_assignment_ranges_on((void*)1,1,&j)==0);
 for(unsigned v=0;v<3;++v)for(unsigned k=0;k<4;++k)assert(values[v*4+k]==0x12345678);
 for(unsigned v=3;v<16;++v)for(unsigned k=0;k<4;++k)assert(values[v*4+k]==(k==0&&v<7?2u:0u));
 assert(status==0x80); // A seed/assignment error must never be cleared.
 values.fill(0x89abcdef);
 j=good();j.ranges[0].value=1;rejected(j);j=good();j.ranges[1].first=6;rejected(j);
 j=good();j.ranges[1].first=8;rejected(j);j=good();j.ranges[1].count=UINT32_MAX;rejected(j);
 j=good();j.ranges[2].count=1;rejected(j);j=good();j.range_count=0;rejected(j);
 j=good();j.range_count=5;rejected(j);j=good();j.prefix_count=0;rejected(j);
 j=good();j.values.context_token=4;rejected(j);j=good();j.values.generation=6;rejected(j);
 j=good();j.status.generation=6;rejected(j);j=good();j.scope[7]=8;rejected(j);
 j=good();j.values.kind=4;rejected(j);j=good();j.status.words=values.data();rejected(j);
 value_lease.kind=4;j=good();j.values.kind=0;rejected(j);value_lease.kind=0;
 j=good();j.values.count-=1;rejected(j);j=good();j.reserved=1;rejected(j);
 j=good();assert(stwo_circuit_assignment_ranges_on((void*)99,1,&j)!=0);assert(stwo_circuit_assignment_ranges_on((void*)1,2,&j)!=0);
 std::puts("ASSIGNMENT_RANGE_HOST_EMULATION exact_values=true prefix_unchanged=true status_preserved=true malformed_no_writes=true token_generation_scope_checked=true GPU_QUALIFIED=false");
}
