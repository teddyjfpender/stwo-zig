#include "context_owner.cuh"
#include "fixture_words.cuh"
#include "rv64/family_witness.h"
#include "rv64/arithmetic_witness.h"
#include "rv64/memory_witness.h"
static void exercise(const std::string &dir,uint32_t id) {
 FixtureWords f(dir+"/case-"+std::to_string(id)+".bin");const auto h=f.take(9);
 if(h[0]!=0x46574e31 || h[1]!=id || h[2]>9 || h[3]!=5)throw std::runtime_error("family fixture shape");
 const auto input=f.take(h[4]*((h[2]==7||h[2]==8)?16:8)), expected=f.take(uint64_t(h[5])<<h[3]);
 const auto c16=f.take(h[6]), ands=f.take(h[7]), shifts=f.take(h[8]);const auto pairs=(h[2]==5||h[2]==7||h[2]==8)?f.take(65536):std::vector<uint32_t>{};const auto support_expected=h[2]==6?f.take(h[4]*16):std::vector<uint32_t>{};if(f.position!=f.data.size())throw std::runtime_error("trailing fixture");
 Owner o(0);const auto in=o.plane(input.size(),1),out=o.plane(1u<<h[3],h[5]),r=o.plane(65536,1),b=o.plane(65536,1),s=o.plane(1u<<20,1),selection=o.plane(131072,1),bytes=o.plane(256,1),support=o.plane(h[4]*16,1),status=o.plane(1,1);
 o.upload(in,input);o.upload(r,std::vector<uint32_t>(65536));o.upload(b,std::vector<uint32_t>(65536));o.upload(s,std::vector<uint32_t>(1u<<20));o.upload(selection,std::vector<uint32_t>(131072));o.upload(bytes,std::vector<uint32_t>(256));o.upload(status,{0});CHECK(stwo_exec_context_sync(o.ctx));
 const StwoRv64FamilyWitness job{in.words,out.words,r.words,b.words,s.words,status.words,h[4],h[3],h[2],0};
 if(h[2]<=4) {CHECK(stwo_rv64_family_witness_on(o.ctx,1,&job));}
 else if(h[2]==5 || h[2]==6) {const StwoRv64ArithmeticWitness ar{in.words,out.words,r.words,bytes.words,b.words,status.words,h[2]==6?support.words:nullptr,h[4],h[3],h[2]==6?1u:0u,0};CHECK(stwo_rv64_arithmetic_witness_on(o.ctx,1,&ar));}
 else if(h[2]==9){CHECK(stwo_rv64_boundary_witness_on(o.ctx,1,in.words,h[4],h[3],out.words,status.words));}
 else {const StwoRv64MemoryWitness mem{in.words,out.words,r.words,bytes.words,b.words,selection.words,status.words,h[4],h[3],h[2]==8?1u:0u,0};CHECK(stwo_rv64_memory_witness_on(o.ctx,1,&mem));}CHECK(stwo_exec_context_sync(o.ctx));
 fixture_equal("family physicalMAIN",o.read(out),expected);if(h[2]==6)fixture_equal("DIV support MUL/MULHU compact facts",o.read(support),support_expected);if(h[6])fixture_equal("family U16",o.read(r),c16);if(h[7])fixture_equal("family AND/U8",o.read((h[2]==5||h[2]==7||h[2]==8)?bytes:b),ands);if(h[8])fixture_equal("family SHIFT/selection",o.read(h[2]==7?selection:s),shifts);if(o.read(status)[0])throw std::runtime_error("valid fact rejected");
 if(h[2]==5||h[2]==7||h[2]==8){
   o.upload(b,std::vector<uint32_t>(65536));o.upload(r,std::vector<uint32_t>(65536));o.upload(selection,std::vector<uint32_t>(131072));CHECK(stwo_exec_context_sync(o.ctx));
   if(h[2]==5){const StwoRv64ArithmeticWitness ar{in.words,out.words,r.words,bytes.words,b.words,status.words,nullptr,h[4],h[3],0,1};CHECK(stwo_rv64_arithmetic_witness_on(o.ctx,1,&ar));}
   else{const StwoRv64MemoryWitness mem{in.words,out.words,r.words,bytes.words,b.words,selection.words,status.words,h[4],h[3],h[2]==8?1u:0u,1};CHECK(stwo_rv64_memory_witness_on(o.ctx,1,&mem));}
   CHECK(stwo_exec_context_sync(o.ctx));fixture_equal("fused-pair physicalMAIN",o.read(out),expected);fixture_equal("fused-pair ledger",o.read(b),pairs);if(o.read(status)[0])throw std::runtime_error("valid fused fact rejected");
 }
 std::printf("PASS family kind=%u nativeMAIN+ledgers cells=%zu\n",h[2],expected.size());o.close();
}
int main(int argc,char **argv){try{if(argc!=2)throw std::runtime_error("directory required");for(uint32_t id=0;id<10;++id)exercise(argv[1],id);return 0;}catch(const std::exception&e){std::fprintf(stderr,"FAIL %s\n",e.what());return 1;}}
