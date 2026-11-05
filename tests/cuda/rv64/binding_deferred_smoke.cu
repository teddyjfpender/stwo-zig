// Focused parity: deferred P and its final Eq*P-uniform contributions against
// the scalar OM31 oracle and the previously qualified nondeferred kernel.
#include "context_owner.cuh"
#include "rv64/binding.h"
#include "rv64/om31.cuh"
using namespace stwo::cuda::rv64;
static void exercise(uint32_t log, uint32_t lane_log, bool base_n) {
  const uint32_t rows=1u<<log, lanes=1u<<lane_log, facts=rows*lanes;
  Owner owner(0);
  auto n=owner.plane(facts,base_n?1:8), d=owner.plane(facts,8);
  auto eq=owner.plane(rows,8), p=owner.plane(rows,8);
  auto direct=owner.plane(rows,8), final=owner.plane(rows,8);
  auto metadata=owner.plane(260*8,1), status=owner.plane(1,1);
  std::vector<uint32_t> ns(uint64_t(facts)*(base_n?1:8)), ds(uint64_t(facts)*8);
  std::vector<uint32_t> es(uint64_t(rows)*8), meta(260*8,0);
  for(size_t i=0;i<ns.size();++i) ns[i]=(i*73+19)%2147483647u;
  for(size_t i=0;i<ds.size();++i) ds[i]=(i*53+41)%2147483647u;
  for(size_t i=0;i<es.size();++i) es[i]=(i*19+13)%2147483647u;
  for(uint32_t lane=0;lane<lanes;++lane)
    for(uint32_t c=0;c<8;++c) meta[lane*8+c]=(lane*31+c*53+17)%2147483647u;
  for(uint32_t c=0;c<8;++c){meta[256*8+c]=c*59+37;meta[257*8+c]=c*61+23;}
  std::vector<uint32_t> expected(uint64_t(rows)*8), expected_final(uint64_t(rows)*8);
  const OM31 eta=from_words(meta.data()+256*8), target=from_words(meta.data()+257*8);
  for(uint32_t row=0;row<rows;++row){
    OM31 pn=zero(),pd=zero();
    for(uint32_t lane=0;lane<lanes;++lane){
      const uint32_t at=row*lanes+lane;
      const auto weight=from_words(meta.data()+lane*8);
      pn=add(pn,base_n?scale(weight,ns[at]):mul(weight,load(ns.data(),facts,at)));
      pd=add(pd,mul(weight,load(ds.data(),facts,at)));
    }
    const auto projected=add(pn,mul(eta,pd));
    store(expected.data(),rows,row,projected);
    store(expected_final.data(),rows,row,sub(mul(load(es.data(),rows,row),projected),target));
  }
  owner.upload(n,ns);owner.upload(d,ds);owner.upload(eq,es);
  owner.upload(metadata,meta);owner.upload(status,{0});
  CHECK(stwo_exec_context_sync(owner.ctx));
  StwoRv64BindingProjection old{n,d,eq,direct,metadata.words,status.words,log,lane_log,{0,0}};
  StwoRv64BindingDeferred deferred{n,d,p,metadata.words,status.words,log,lane_log,{0,0}};
  StwoRv64BindingFinalize finish{p,eq,final,metadata.words,status.words,log,{0,0,0}};
  auto bad=deferred;bad.output=n;
  if(!stwo_rv64_binding_deferred_on(owner.ctx,1,&bad))throw std::runtime_error("deferred alias accepted");
  bad=deferred;bad.reserved[0]=1;
  if(!stwo_rv64_binding_deferred_on(owner.ctx,1,&bad))throw std::runtime_error("deferred reserved accepted");
  auto bad_finish=finish;bad_finish.output=eq;
  if(!stwo_rv64_binding_finalize_on(owner.ctx,1,&bad_finish))throw std::runtime_error("finalize alias accepted");
  CHECK(stwo_rv64_binding_project_on(owner.ctx,1,&old));
  CHECK(stwo_rv64_binding_deferred_on(owner.ctx,1,&deferred));
  CHECK(stwo_rv64_binding_finalize_on(owner.ctx,1,&finish));
  if(owner.read(p)!=expected||owner.read(final)!=expected_final||owner.read(direct)!=expected_final)
    throw std::runtime_error("deferred/finalized projection differs from scalar/native kernel");
  if(owner.read(status)[0])throw std::runtime_error("unexpected deferred binding verdict");
  owner.close();
}
int main(){try{for(auto log:{1u,5u,12u})for(auto lane:{0u,4u,8u})for(bool base_n:{false,true})exercise(log,lane,base_n);std::printf("DEFERRED_BINDING cases=18 scalar_om31_and_existing_native_kernel=PASS max_facts=1048576\n");}catch(const std::exception& e){std::fprintf(stderr,"%s\n",e.what());return 1;}}
