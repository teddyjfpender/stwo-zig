// UNCOMPILED future bounded numerical fixture. Not an accepting circuit proof.
#include "context_owner.cuh"
#include "rv64/circuit_assignment.h"
#include <cassert>
#include <cstring>
#include <algorithm>
static std::vector<uint32_t> words(const void*p,size_t bytes){std::vector<uint32_t> v(bytes/4);std::memcpy(v.data(),p,bytes);return v;}
int main(){try{
 Owner o(0);const uint32_t count=263;
 std::vector<StwoCircuitAssignmentTask> tasks;
 auto add=[&](uint32_t out,uint32_t a,uint32_t b){StwoCircuitAssignmentTask t{};t.out=out;t.args[0]=a;t.args[1]=b;tasks.push_back(t);};
 add(2,0,1);add(3,2,1);for(uint32_t v=4;v<261;++v)add(v,3,1);add(261,260,1);add(262,261,1);
 const StwoCircuitAssignmentSeed seeds[2]={{0,{3,0,0,0}},{1,{2,0,0,0}}};
 auto record=o.plane(tasks.size()*8,1),seed=o.plane(10,1),ref=o.plane(count*4,1),fused=o.plane(count*4,1),status=o.plane(1,1);
 o.upload(record,words(tasks.data(),tasks.size()*sizeof(tasks[0])));o.upload(seed,words(seeds,sizeof(seeds)));
 o.upload(ref,std::vector<uint32_t>(count*4));o.upload(fused,std::vector<uint32_t>(count*4));o.upload(status,{0});CHECK(stwo_exec_context_sync(o.ctx));
 auto job=[&](StwoRv64Plane values){return StwoCircuitAssignmentJob{values.words,record.words,nullptr,status.words,count,uint32_t(tasks.size()),0,0,2,0};};
 for(auto values:{ref,fused}){auto j=job(values);j.records=seed.words;j.record_count=2;CHECK(stwo_circuit_assignment_seed_on(o.ctx,1,&j));}
 auto j=job(fused);const uint32_t first_ends[2]={1,2};
 const auto baseline=o.read(fused);
 auto rejected=[&](const StwoCircuitAssignmentJob&bad,const uint32_t*ends,uint32_t n){if(!stwo_circuit_assignment_narrow_run_on(o.ctx,1,&bad,ends,n))throw std::runtime_error("accepted malformed run");if(o.read(fused)!=baseline)throw std::runtime_error("bad run mutated output before rejection");};
 const uint32_t backwards[2]={2,1},wide[2]={257,258},incomplete[2]={1,3};
 rejected(j,backwards,2);rejected(j,wide,2);rejected(j,incomplete,2);rejected(j,first_ends,1);rejected(j,first_ends,257);
 auto bad=j;bad.reserved=1;rejected(bad,first_ends,2);bad=j;bad.status=bad.values;rejected(bad,first_ends,2);bad=j;bad.records=bad.values;rejected(bad,first_ends,2);
 {Owner other(0);if(!stwo_circuit_assignment_narrow_run_on(other.ctx,1,&j,first_ends,2))throw std::runtime_error("accepted wrong context");}
 // Original one-kernel-per-level route, including a257-task broad barrier.
 auto r=job(ref);uint32_t begin=0;for(uint32_t end:{1u,2u,259u,260u,261u}){r.first=begin;r.count=end-begin;CHECK(stwo_circuit_assignment_level_on(o.ctx,1,&r));begin=end;}
 CHECK(stwo_circuit_assignment_narrow_run_on(o.ctx,1,&j,first_ends,2));
 j.first=2;j.count=257;CHECK(stwo_circuit_assignment_level_on(o.ctx,1,&j));
 j.first=259;j.count=2;const uint32_t last_ends[2]={260,261};CHECK(stwo_circuit_assignment_narrow_run_on(o.ctx,1,&j,last_ends,2));
 const auto a=o.read(ref),b=o.read(fused);if(a!=b)throw std::runtime_error("grouped assignment differs from original levels");
 std::vector<uint32_t> expected(count*4);expected[0]=3;expected[4]=2;expected[8]=5;expected[12]=7;for(uint32_t v=4;v<261;++v)expected[v*4]=9;expected[261*4]=11;expected[262*4]=13;
 if(b!=expected||o.read(status)[0])throw std::runtime_error("CPU scalar oracle mismatch");
 // Invalid task status must not strand other threads before the next barrier.
 tasks[0].args[0]=count; o.upload(record,words(tasks.data(),tasks.size()*sizeof(tasks[0])));o.upload(status,{0});CHECK(stwo_exec_context_sync(o.ctx));j=job(fused);
 CHECK(stwo_circuit_assignment_narrow_run_on(o.ctx,1,&j,first_ends,2));if(o.read(status)[0]!=1)throw std::runtime_error("invalid task did not preserve error status");
 std::puts("{\"scope\":\"tiny assignment numerical only\",\"narrow_run_calls\":3,\"original_level_calls\":5,\"broad_barriers\":1,\"native_and_cpu_values_equal\":true,\"invalid_task_barrier_completed\":true}");o.close();return 0;
}catch(const std::exception&e){std::fprintf(stderr,"%s\n",e.what());return 1;}}
