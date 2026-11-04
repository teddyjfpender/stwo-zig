#include <cuda_runtime_api.h>
#include <cassert>
#include <cstdio>
#include <cstdint>
extern "C" int stwo_exec_context_alloc_u32(void*, size_t, uint32_t**);
static unsigned failures = 0, attempts = 0, copy_attempts=0;
extern "C" int stwo_exec_context_memcpy_d2d_async(void*,void*,const void*,size_t);
extern "C" int counted_device_copy(void*ctx,void*destination,const void*source,size_t bytes){
 ++copy_attempts;return stwo_exec_context_memcpy_d2d_async(ctx,destination,source,bytes);
}
extern "C" int injected_context_alloc(void* context, size_t words, uint32_t** out) {
    ++attempts;
    if (failures) {
        --failures;
        *out = nullptr;
        size_t available = 0, total = 0;
        assert(cudaMemGetInfo(&available, &total) == cudaSuccess);
        void* impossible = nullptr;
        assert(cudaMalloc(&impossible, total * 2) == cudaErrorMemoryAllocation);
        return int(cudaErrorMemoryAllocation);
    }
    return stwo_exec_context_alloc_u32(context, words, out);
}
#define stwo_exec_context_alloc_u32 injected_context_alloc
#define stwo_exec_context_memcpy_d2d_async counted_device_copy
#include "../../../src/backends/cuda/native/rv64/pcs_native.cu"
#undef stwo_exec_context_alloc_u32
#undef stwo_exec_context_memcpy_d2d_async
static void copy_coalescing() {
 using rv64_pcs_pipeline::Coefficient;using rv64_pcs_pipeline::CoefficientTransfer;
 using rv64_pcs_pipeline::appendCoefficientTransfer;
 ResidentOwner owner(0,64*1024*1024);Scope scope{};scope[0]=7;
 auto lease=owner.lease(96,2,scope);auto destination=owner.plane(128,1);
 std::vector<uint32_t> pattern(96);for(uint32_t i=0;i<96;++i)pattern[i]=i*i+17;
 assert(cudaMemcpy(lease.words,pattern.data(),384,cudaMemcpyHostToDevice)==cudaSuccess);
 auto column=[&](uint32_t offset){return Coefficient{{lease.words+offset,32},1,lease.context_token,lease.generation};};
 std::vector<CoefficientTransfer> plan;
 for(uint32_t i=0;i<3;++i){auto c=column(i*32);const auto kind=owner.validateCoefficient(c,scope.data());appendCoefficientTransfer(plan,c,i*32,kind,scope);}
 assert(plan.size()==1 && plan[0].source.size()==96);
 const auto before=copy_attempts;owner.uploadCoefficient({destination.words,96,1,0},plan[0].source,scope.data());owner.sync();assert(copy_attempts==before+1);
 std::vector<uint32_t> actual(96);assert(cudaMemcpy(actual.data(),destination.words,384,cudaMemcpyDeviceToHost)==cudaSuccess);assert(actual==pattern);
 unsigned rejected=0;
 auto reject=[&](Coefficient c,Scope authority){const auto calls=copy_attempts;try{owner.uploadCoefficient({destination.words,c.size(),1,0},c,authority.data());}catch(const std::exception&){++rejected;assert(copy_attempts==calls);return;}assert(false);};
 auto c=column(0);c.count=97;reject(c,scope);c=column(0);c.token++;reject(c,scope);c=column(0);c.generation++;reject(c,scope);c=column(0);auto wrong=scope;wrong[0]++;reject(c,wrong);c=column(0);c.kind=2;reject(c,scope);
 auto scratch=owner.lease(32,0,scope);reject({{scratch.words,32},1,scratch.context_token,scratch.generation},scope);
 unsigned split=0;
 for(uint32_t change=0;change<8;++change){plan.clear();auto left=column(0),right=column(32);auto target=scope;uint64_t offset=32;uint32_t kind=2;
  if(change==0)right.token++;if(change==1)right.generation++;if(change==2)kind=4;if(change==3)target[0]++;if(change==4)offset++;if(change==5)right.pointer++;if(change==6){left.kind=0;right.kind=0;}if(change==7)right.kind=0;
  appendCoefficientTransfer(plan,left,0,2,scope);appendCoefficientTransfer(plan,right,offset,kind,target);assert(plan.size()==2);++split;
 }
 owner.release(scratch);owner.release(lease);owner.reset();std::printf("PASS coefficient coalescing copies=1 columns=3 native_rejects=%u authority_splits=%u\n",rejected,split);
}
static void phase_retirement() {
 ResidentOwner o(0,64*1024*1024);Scope scope{};scope[0]=23;
 auto a=o.plane(1024,1),b=o.plane(512,1);auto live=o.lease(64,2,scope);
 const uint32_t pattern=0x12345678;
 assert(cudaMemcpy(live.words,&pattern,4,cudaMemcpyHostToDevice)==cudaSuccess);
 unsigned rejects=0;
 auto reject=[&](std::vector<StwoRv64Plane> planes){try{o.retirePlanes(planes);}catch(const std::exception&){++rejects;return;}assert(false);};
 auto partial=b;partial.stride--;
 reject({a,partial});assert(o.blocks[0].used&&o.blocks[1].used);
 reject({a,a});assert(o.blocks[0].used&&o.blocks[1].used);
 reject({{live.words,live.count,1,0}});
 auto protected_source=o.sourcePlane(256,1);reject({a,protected_source});assert(o.blocks[0].used);
 std::array<uint32_t,4> circle{1,0,0,1};
 auto domain=o.domain(5,{},rv64_pcs_pipeline::Words{circle.data(),circle.size()});
 reject({domain});
 std::array<uint32_t,64> legacy{};auto legacy_domain=o.domain(5,rv64_pcs_pipeline::Words{legacy.data(),legacy.size()},{});reject({legacy_domain});
 void*raw=nullptr;CHECK(stwo_exec_context_lane_stream(o.ctx,1,&raw));
 assert(cudaMemsetAsync(a.words,0x5a,4096,reinterpret_cast<cudaStream_t>(raw))==cudaSuccess);
 o.retirePlanes({a,b});assert(!o.blocks[0].used&&!o.blocks[1].used);
 reject({a});
 auto reuse=o.plane(800,1);assert(reuse.words==a.words&&o.blocks[0].words==1024&&o.blocks[0].active_words==800);
 reject({a});assert(o.blocks[0].used);
 o.retirePlane(reuse);assert(!o.blocks[0].used);
 uint32_t actual=0;assert(cudaMemcpy(&actual,live.words,4,cudaMemcpyDeviceToHost)==cudaSuccess&&actual==pattern);
 assert(o.leases.size()==1&&o.domains.size()==1);
 assert(rejects==8);o.release(live);o.reset();auto retagged=o.plane(200,1);assert(retagged.words==protected_source.words);o.retirePlane(retagged);
 std::printf("PASS phase retirement rejects=%u exact_oversized_reuse=1 source_and_domain_preserved=1\n",rejects);
}
int main() {
    phase_retirement();
    copy_coalescing();
    ResidentOwner owner(0, 256 * 1024 * 1024);
    Scope scope{}; scope[0] = 1;
    auto live = owner.lease(1024, 2, scope);
    const auto idle = owner.plane(4 * 1024 * 1024, 1);
    owner.reset();
    const auto active = owner.plane(8 * 1024 * 1024, 1);
    assert(owner.blocks.size() == 2);
    assert(!owner.blocks[0].used && owner.blocks[1].used);
    const uint32_t pattern = 0x12345678;
    assert(cudaMemset(live.words, 0x5a, live.count * 4) == cudaSuccess);
    assert(cudaMemcpy(active.words, &pattern, 4, cudaMemcpyHostToDevice) == cudaSuccess);
    const unsigned before = attempts;
    failures = 1;
    auto result = owner.lease(16 * 1024 * 1024, 0, scope);
    assert(attempts == before + 2 && failures == 0);
    assert(cudaPeekAtLastError() == cudaSuccess);
    assert(owner.blocks.size() == 1 && owner.blocks[0].ptr == active.words);
    assert(owner.blocks[0].used);
    assert(owner.leases.size() == 2);
    assert(owner.retained == (1024ull + 8 * 1024 * 1024 + 16 * 1024 * 1024) * 4);
    uint32_t actual = 0;
    assert(cudaMemcpy(&actual, live.words, 4, cudaMemcpyDeviceToHost) == cudaSuccess);
    assert(actual == 0x5a5a5a5a);
    assert(cudaMemcpy(&actual, active.words, 4, cudaMemcpyDeviceToHost) == cudaSuccess);
    assert(actual == pattern);
    const auto retained = owner.retained;
    failures = 2;
    bool rejected = false;
    try { (void)owner.lease(1024, 0, scope); }
    catch (const std::exception&) { rejected = true; }
    assert(rejected && failures == 0 && owner.retained == retained && owner.leases.size() == 2);
    (void)cudaGetLastError();
    owner.release(result);
    owner.release(live);
    owner.reset();
    (void)idle;
    std::puts("PASS idle PCS eviction, active cache/live leases preserved, exact accounting, bounded failure custody");
}
