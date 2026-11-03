// Qualification-only whole-matrix readback. Production never reads MAIN back.
#include "context_owner.cuh"
#include "fixture_words.cuh"
#include "rv64/arith256_witness.h"
#include <fstream>
int main(int argc,char**argv){try{
 if(argc!=3)throw std::runtime_error("expected compact fixture and output path");
 FixtureWords f(argv[1]);const auto h=f.take(6);
 if(h[0]!=0x52564152||h[1]!=1||h[5]!=401||h[3]<8||h[3]>22)throw std::runtime_error("arith256 fixture header");
 const uint32_t log=h[3],calls=h[4];const uint64_t rows=1ull<<log,words=401*rows;
 const auto inputs=f.take(uint64_t(calls)*40);if(f.position!=f.data.size())throw std::runtime_error("trailing fixture words");
 Owner o(0);const auto in=o.plane(std::max<size_t>(inputs.size(),1),1),out=o.plane(words+16,1),status=o.plane(1,1),counts=o.plane(256,1);
 o.upload(in,inputs.empty()?std::vector<uint32_t>{0}:inputs);o.upload(status,{0});CHECK(stwo_exec_context_sync(o.ctx));
 CHECK(cudaMemset(out.words,0xa5,(words+16)*4));
 StwoRv64Arith256Witness j{in.words,out.words,counts.words,status.words,uint64_t(calls)*40,words,calls,1,log,0};
 CHECK(stwo_rv64_arith256_witness_on(o.ctx,1,&j));
 if(o.read(status)[0])throw std::runtime_error("arith256 witness rejected");
 const auto actual=o.read(out);for(uint64_t i=words;i<words+16;++i)if(actual[i]!=0xa5a5a5a5u)throw std::runtime_error("arith256 guard overwritten");
 std::ofstream output(argv[2],std::ios::binary);output.write(reinterpret_cast<const char*>(actual.data()),words*4);output.close();if(!output)throw std::runtime_error("arith256 output write failed");
 auto bad=j;bad.main=in.words;if(!stwo_rv64_arith256_witness_on(o.ctx,1,&bad))throw std::runtime_error("arith256 short MAIN accepted");
 bad=j;bad.input_words+=1;if(!stwo_rv64_arith256_witness_on(o.ctx,1,&bad))throw std::runtime_error("arith256 bad input count accepted");
 bad=j;bad.reserved=1;if(!stwo_rv64_arith256_witness_on(o.ctx,1,&bad))throw std::runtime_error("arith256 reserved accepted");
 bad=j;bad.status=out.words;if(!stwo_rv64_arith256_witness_on(o.ctx,1,&bad))throw std::runtime_error("arith256 output alias accepted");
 bad=j;bad.log=4;if(!stwo_rv64_arith256_witness_on(o.ctx,1,&bad))throw std::runtime_error("arith256 short domain accepted");
 bad=j;bad.byte_counts=out.words;if(!stwo_rv64_arith256_witness_on(o.ctx,1,&bad))throw std::runtime_error("arith256 ledger alias accepted");
 o.close();std::printf("PASS arith256 native witness case=%u calls=%u rows=%llu words=%llu mutants=6\n",h[2],calls,(unsigned long long)rows,(unsigned long long)words);return 0;
}catch(const std::exception&e){std::fprintf(stderr,"FAIL %s\n",e.what());return 1;}}
