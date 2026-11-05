// Exact real native lookup tuples, O8 fraction kernel, partial-warp inversion
// and cumulative native INTER. No accepting block/recursion claim is made here.
#include "context_owner.cuh"
#include "fixture_words.cuh"
#include "rv64/circuit_interaction.h"
#include "rv64/global.h"
#include <algorithm>
static void exercise(const std::string &directory,unsigned component) {
  FixtureWords f(directory+"/case-"+std::to_string(component)+".bin");
  const auto h=f.take(7);
  if(h[0]!=0x434f4638 || h[1]!=1 || h[2]!=component || h[3]!=4) throw std::runtime_error("outer fraction header");
  const unsigned rows=1u<<h[3],pairs=h[6];
  const auto fixed=f.take(rows*h[4]),main=f.take(rows*h[5]),parameters=f.take(56),n=f.take(rows*pairs*8),d=f.take(rows*pairs*8),final=f.take(rows*pairs*8),claim=f.take(8);
  if(f.position!=f.data.size())throw std::runtime_error("outer fraction trailing data");
  Owner o(0);
  auto upload=[&](const std::vector<uint32_t>&data){auto p=o.plane(std::max<size_t>(data.size(),1),1);o.upload(p,data.empty()?std::vector<uint32_t>{0}:data);return p;};
  const auto fp=upload(fixed),mp=upload(main),pp=upload(parameters),np=o.plane(n.size(),1),dp=o.plane(d.size()+rows*8,1),status=o.plane(1,1),scratch=o.plane(8,1),result_claim=o.plane(8,1);
  o.upload(status,{0});
  const StwoCircuitOm31Fractions fractions{fp.words,mp.words,pp.words,np.words,dp.words,status.words,fixed.size(),main.size(),n.size(),d.size(),component,h[3],{0,0}};
  CHECK(stwo_circuit_om31_fractions_on(o.ctx,1,&fractions));
  if(o.read(status)[0])throw std::runtime_error("outer fractions status");
  const auto gotn=o.read(np),gotd=o.read(dp);
  if(gotn!=n || !std::equal(d.begin(),d.end(),gotd.begin()))throw std::runtime_error("outer fraction native tuple mismatch");
  const StwoRv64GlobalPairs pairs_job{dp.words,np.words,scratch.words,result_claim.words,status.words,rows,8,h[3],pairs,{0,0}};
  CHECK(stwo_rv64_global_pairs_on(o.ctx,1,&pairs_job));
  const StwoCircuitOm31Cumulative cumulative{dp.words,np.words,result_claim.words,rows,h[3],pairs};
  CHECK(stwo_circuit_om31_cumulative_on(o.ctx,1,&cumulative));
  const auto gotfinal=o.read(dp);
  if(o.read(status)[0] || o.read(result_claim)!=claim || !std::equal(final.begin(),final.end(),gotfinal.begin()))throw std::runtime_error("outer cumulative native INTER mismatch");
  auto bad=fractions;bad.numerator_words--;if(!stwo_circuit_om31_fractions_on(o.ctx,1,&bad))throw std::runtime_error("short numerator accepted");
  bad=fractions;bad.denominators=np.words;if(!stwo_circuit_om31_fractions_on(o.ctx,1,&bad))throw std::runtime_error("aliased N D accepted");
  o.close();std::printf("PASS circuit OM31 component=%u native_N_D_INTER_claim_exact=true mutants=2\n",component);
}
int main(int argc,char**argv){try{if(argc!=2)throw std::runtime_error("usage: fixture_directory");for(unsigned component=0;component<11;++component)exercise(argv[1],component);return 0;}catch(const std::exception&e){std::fprintf(stderr,"FAIL %s\n",e.what());return 1;}}
