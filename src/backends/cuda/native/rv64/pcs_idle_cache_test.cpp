// CPU-only native policy/phase-owner emulation; no CUDA stubs or GPU timings.
#include "pcs_idle_cache.h"
#include <algorithm>
#include <cstdio>
#include <string>
using namespace rv64_pcs_idle_cache;
namespace {
unsigned checks = 0;
void check(bool value) { ++checks; if (!value) throw std::runtime_error("idle cache test failed"); }
template<class F> void rejects(F run) { bool rejected=false;try {run();}catch(const std::runtime_error&){rejected=true;}check(rejected); }
struct Block { uintptr_t ptr; uint64_t words; bool used; uint64_t active_words; bool retirable; };
struct Owner {
  Limit limit;
  std::vector<Block> blocks;
  uint64_t retained=0, lease_bytes=0, domain_bytes=0;
  bool joined=false, poisoned=false;
  std::vector<uintptr_t> freed;
  size_t fail_on=SIZE_MAX;
  Owner()=default;
  Owner(Limit l,std::vector<Block> b,uint64_t bytes,uint64_t leases=0,uint64_t domains=0):limit(l),blocks(std::move(b)),retained(bytes),lease_bytes(leases),domain_bytes(domains){}
  Trim retire() {
    if(poisoned) throw std::runtime_error("terminal owner");
    joined=true; // actual retirePlanes/reset already sync before trim
    try {
      return trim(limit,blocks,retained,[&](uintptr_t ptr){
        check(joined);
        if(freed.size()==fail_on)throw std::runtime_error("free failed");
        freed.push_back(ptr);
      });
    }catch(...){poisoned=true;throw;}
  }
};
void parsing() {
  check(!parse(nullptr,28ull<<30).enabled);
  check(parse("0",28ull<<30).enabled&&parse("0",28ull<<30).bytes==0);
  check(parse("2147483648",28ull<<30).bytes==(2ull<<30));
  check(parse("30064771072",28ull<<30).bytes==(28ull<<30));
  check(parse("18446744073709551615",UINT64_MAX).bytes==UINT64_MAX);
  for(const char*text:{""," "," 1","1 ","+1","-1","00","01","0x10","1_000","1.0","nan","inf","2GB","18446744073709551616","999999999999999999999"})rejects([&]{parse(text,UINT64_MAX);});
  rejects([]{parse("30064771073",28ull<<30);});
  unsigned created=0;
  auto create=[&](const char*text){const auto policy=parse(text,28ull<<30);++created;return policy;};
  rejects([&]{create("not-a-cap");});check(created==0);
}
void custody() {
  Owner o{{true,128},{{1,32,false,0,true},{2,32,false,0,true},{3,48,false,0,true},{4,128,true,128,false}},1960,500,500};
  const auto result=o.retire();
  check(result.before==448&&result.after==128&&result.released==2);
  check(o.freed==std::vector<uintptr_t>({3,1}));
  check(o.retained==1640&&o.lease_bytes==500&&o.domain_bytes==500);
  check(o.blocks.size()==2&&o.blocks[0].ptr==2&&o.blocks[1].ptr==4&&o.blocks[1].used&&o.blocks[1].active_words==128&&!o.blocks[1].retirable);
  Owner legacy{{false,0},{{1,32,false,0,true},{2,128,true,128,false}},640};
  const auto before=legacy.blocks;const auto disabled=legacy.retire();
  check(legacy.freed.empty()&&legacy.retained==640&&legacy.blocks.size()==before.size()&&disabled.released==0);
  Owner active{{true,0},{{1,128,true,128,true},{2,256,true,256,false}},1536};
  active.retire();check(active.freed.empty()&&active.retained==1536);
  Owner exact{{true,128},{{1,32,false,0,true}},128};
  exact.retire();check(exact.freed.empty());
}
void failure() {
  Owner o{{true,0},{{1,64,false,0,true},{2,48,false,0,true},{3,16,false,0,true},{4,32,true,32,false}},640};
  o.fail_on=1;
  rejects([&]{o.retire();});
  check(o.poisoned&&o.freed==std::vector<uintptr_t>({1}));
  check(o.retained==384&&o.blocks.size()==3&&o.blocks[0].ptr==2&&o.blocks[0].words==48);
  rejects([&]{o.retire();});check(o.freed.size()==1);
  // No failed-free descriptor is erased; native terminal teardown retains it.
  check(o.blocks[0].ptr==2&&o.blocks[1].ptr==3&&o.blocks[2].ptr==4);
  Owner invalid{{true,0},{{1,UINT64_MAX,false,0,true}},UINT64_MAX};
  rejects([&]{invalid.retire();});check(invalid.freed.empty());
  Owner ledger{{true,0},{{1,64,false,0,true}},255};
  rejects([&]{ledger.retire();});check(ledger.freed.empty());
}
void exhaustive() {
  for(unsigned mask=0;mask<256;++mask)for(uint64_t cap:{0ull,4ull,64ull,512ull}){
    Owner o; o.limit={true,cap}; o.lease_bytes=1000;o.domain_bytes=500;o.retained=1500;
    uint64_t idle=0;
    std::vector<std::pair<uint64_t,uintptr_t>> reference;
    for(unsigned i=0;i<8;++i){const auto words=uint64_t((i%3)+1)*8;const bool used=(mask>>i)&1;o.blocks.push_back({i+1,words,used,used?words:0,bool(i%2)});o.retained+=words*4;if(!used){idle+=words*4;reference.push_back({words,i+1});}}
    std::stable_sort(reference.begin(),reference.end(),[](auto a,auto b){return a.first>b.first;});
    std::vector<uintptr_t> expected;uint64_t after=idle;
    for(auto entry:reference){if(after<=cap)break;after-=entry.first*4;expected.push_back(entry.second);}
    const auto before=o.retained;const auto result=o.retire();
    check(o.freed==expected&&result.before==idle&&result.after==after&&after<=cap);
    check(o.retained==before-(idle-after)&&o.lease_bytes==1000&&o.domain_bytes==500);
    for(auto block:o.blocks)if(block.used)check(((mask>>(block.ptr-1))&1)&&block.active_words==block.words);
  }
}
}
int main(){try{parsing();custody();failure();exhaustive();std::printf("PCS_IDLE_CACHE_HOST checks=%u passed=true gpu_qualified=false\n",checks);return 0;}catch(const std::exception&e){std::fprintf(stderr,"%s\n",e.what());return 1;}}
