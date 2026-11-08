// Whole-matrix reads are qualification-only; production keeps MAIN resident.
#include "context_owner.cuh"
#include "fixture_words.cuh"
#include "rv64/bridge_witness.h"
int main(int argc,char**argv){try{
 if(argc!=2)throw std::runtime_error("expected compact+native oracle fixture");
 FixtureWords f(argv[1]);const auto h=f.take(9);if(h[0]!=0x52564252||h[1]!=1)throw std::runtime_error("bridge fixture header");
 const uint32_t log=h[3],calls=h[4],width=h[5],kind=h[6],coords=h[7],mask=h[8];const uint64_t n=1ull<<log,words=n*width;
 const auto input=f.take(uint64_t(calls)*(4+8*(kind?4*coords:25)));const auto expected=f.take(words),r16=f.take(65536),r8=f.take(256);if(f.position!=f.data.size())throw std::runtime_error("trailing words");
 Owner o(0);const auto in=o.plane(std::max<size_t>(input.size(),1),1),out=o.plane(words+16,1),status=o.plane(1,1),count16=o.plane(65536,1),count8=o.plane(256,1);
 o.upload(in,input.empty()?std::vector<uint32_t>{0}:input);o.upload(status,{0});o.upload(count16,std::vector<uint32_t>(65536,0));o.upload(count8,std::vector<uint32_t>(256,0));CHECK(stwo_exec_context_sync(o.ctx));CHECK(cudaMemset(out.words,0xa5,(words+16)*4));
 StwoRv64BridgeWitness j{in.words,out.words,count16.words,count8.words,status.words,input.size(),words,calls,7,log,kind,coords,mask};CHECK(stwo_rv64_bridge_witness_on(o.ctx,1,&j));if(o.read(status)[0])throw std::runtime_error("bridge valid advice rejected");
 const auto actual=o.read(out);for(uint64_t i=0;i<words;++i)if(actual[i]!=expected[i]){std::fprintf(stderr,"mismatch col=%llu row=%llu actual=%u expected=%u\n",(unsigned long long)(i/n),(unsigned long long)(i%n),actual[i],expected[i]);throw std::runtime_error("bridge native MAIN differs");}
 for(uint64_t i=words;i<words+16;++i)if(actual[i]!=0xa5a5a5a5u)throw std::runtime_error("guard overwritten");if(o.read(count16)!=r16||o.read(count8)!=r8)throw std::runtime_error("bridge range multiplicities differ");
 unsigned mutations=0;auto reject=[&](const StwoRv64BridgeWitness&bad){if(!stwo_rv64_bridge_witness_on(o.ctx,1,&bad))throw std::runtime_error("bridge invalid shape accepted");++mutations;};
 auto bad=j;bad.input_words+=1;reject(bad);bad=j;bad.main=in.words;reject(bad);bad=j;bad.range8=out.words;reject(bad);bad=j;bad.coordinates=0;reject(bad);bad=j;bad.first_id=0;reject(bad);bad=j;bad.main_words-=1;reject(bad);
 if(calls){auto mutated=input;mutated[3]=0;o.upload(in,mutated);o.upload(status,{0});CHECK(stwo_rv64_bridge_witness_on(o.ctx,1,&j));if(!o.read(status)[0])throw std::runtime_error("zero clock accepted");++mutations;
  mutated=input;mutated[4+6]|=4u<<16;o.upload(in,mutated);o.upload(status,{0});CHECK(stwo_rv64_bridge_witness_on(o.ctx,1,&j));if(!o.read(status)[0])throw std::runtime_error("invalid rights accepted");++mutations;
  mutated=input;mutated[4+4]^=1;o.upload(in,mutated);o.upload(status,{0});CHECK(stwo_rv64_bridge_witness_on(o.ctx,1,&j));if(!o.read(status)[0])throw std::runtime_error("predecessor mismatch accepted");++mutations;
 }
 o.close();std::printf("PASS bridge case=%u kind=%u calls=%u cols=%u rows=%llu mutations=%u\n",h[2],kind,calls,width,(unsigned long long)n,mutations);return 0;
}catch(const std::exception&e){std::fprintf(stderr,"FAIL %s\n",e.what());return 1;}}
