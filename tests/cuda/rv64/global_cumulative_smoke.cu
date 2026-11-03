// Qualification of in-place native cumulative encoding, not a block benchmark.
#include "context_owner.cuh"
#include "rv64/global.h"
#include "rv64/om31.cuh"
using namespace stwo::cuda::rv64;
static uint32_t physical(uint32_t r,uint32_t log){const uint32_t n=1u<<log,c=r&1?n-1-r/2:r/2;uint32_t out=0;for(uint32_t i=0;i<log;++i)out=(out<<1)|((c>>i)&1);return out;}
static uint64_t scan_words(uint32_t n){uint64_t words=0;while(n>1){n=(n+127)/128;words+=uint64_t(n)*8;}return words;}
static void test(uint32_t pairs){
 const uint32_t log=5,rows=1u<<log;Owner o(0);
 const auto output=o.plane(uint64_t(pairs+1)*8*rows,1),n=o.plane(uint64_t(pairs)*8*rows,1),scratch=o.plane(scan_words(rows),1),claim=o.plane(8,1),status=o.plane(1,1);
 std::vector<uint32_t> d(output.stride,0),num(n.stride),expected(n.stride);OM31 sum=zero();
 for(uint32_t logical=0;logical<rows;++logical){const auto row=physical(logical,log);
  for(uint32_t p=0;p<pairs;++p){const uint32_t dw[8]={logical+1,p+3,5,7,11,13,17,19},nw[8]={3*(logical+1),p+1,23,0,0,0,0,0};
   const auto den=from_words(dw),numerator=from_words(nw);store(d.data()+uint64_t(p)*8*rows,rows,row,den);store(num.data()+uint64_t(p)*8*rows,rows,row,numerator);
   sum=add(sum,mul(numerator,inverse_nonzero(den)));store(expected.data()+uint64_t(p)*8*rows,rows,row,sum);
  }
 }
 for(uint32_t p=0;p<pairs;++p)for(uint32_t row=0;row<rows;++row)store(expected.data()+uint64_t(p)*8*rows,rows,row,sub(load(expected.data()+uint64_t(p)*8*rows,rows,row),sum));
 o.upload(output,d);o.upload(n,num);o.upload(status,{0});CHECK(stwo_exec_context_sync(o.ctx));
 StwoRv64GlobalPairs job{output.words,n.words,scratch.words,claim.words,status.words,rows,scan_words(rows),log,pairs,{0,0}};CHECK(stwo_rv64_global_pairs_on(o.ctx,1,&job));
 StwoRv64GlobalCumulative convert{output.words,n.words,rows,log,pairs};CHECK(stwo_rv64_global_cumulative_on(o.ctx,1,&convert));
 if(o.read(status)[0])throw std::runtime_error("cumulative rejected");const auto actual=o.read(output),got_claim=o.read(claim);
 for(uint32_t i=0;i<8;++i)if(got_claim[i]!=coordinate(sum,i))throw std::runtime_error("native cumulative claim mismatch");
 for(size_t i=0;i<expected.size();++i)if(actual[i]!=expected[i])throw std::runtime_error("native cumulative batch mismatch");
 auto bad=convert;bad.pairs=0;if(!stwo_rv64_global_cumulative_on(o.ctx,1,&bad))throw std::runtime_error("zero pairs accepted");bad=convert;bad.pairs=641;if(!stwo_rv64_global_cumulative_on(o.ctx,1,&bad))throw std::runtime_error("excess pairs accepted");bad=convert;bad.row_log=4;if(!stwo_rv64_global_cumulative_on(o.ctx,1,&bad))throw std::runtime_error("short log accepted");bad=convert;bad.stride=rows-1;if(!stwo_rv64_global_cumulative_on(o.ctx,1,&bad))throw std::runtime_error("short stride accepted");bad=convert;bad.contributions=output.words;if(!stwo_rv64_global_cumulative_on(o.ctx,1,&bad))throw std::runtime_error("output alias accepted");
 o.close();std::printf("PASS native cumulative batches pairs=%u mutants=5\n",pairs);
}
int main(){try{for(uint32_t pairs:{1u,3u,640u})test(pairs);return 0;}catch(const std::exception&e){std::fprintf(stderr,"FAIL %s\n",e.what());return 1;}}
