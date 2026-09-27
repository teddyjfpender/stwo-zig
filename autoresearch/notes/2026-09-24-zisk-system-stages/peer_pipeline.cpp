#include "ntt_goldilocks.hpp"
#include "blake3_goldilocks.hpp"
#include <vector>
#include <chrono>
extern "C" uint64_t peer_pipeline(uint32_t log,uint32_t width,uint32_t rounds,uint32_t constant,uint64_t*times,uint64_t*root){
 uint64_t n=1ull<<log,sum=0;NTT_Goldilocks plan(n,1);std::vector<Goldilocks::Element> in(n*width),out(2*n*width),aux(2*n*width),tree(16*n);
 times[0]=times[1]=0;
 for(unsigned r=0;r<rounds;r++){
  for(uint64_t i=0;i<in.size();i++)in[i]=Goldilocks::fromU64(constant?1:i+1);
  auto t=std::chrono::steady_clock::now();plan.LDE(out.data(),in.data(),2*n,n,width,aux.data());
  times[0]+=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-t).count();
  if(constant)for(auto v:out)if(Goldilocks::toU64(v)!=1)return UINT64_MAX;
  t=std::chrono::steady_clock::now();Blake3Goldilocks::merkletree(tree.data(),out.data(),width,2*n,2,1);
  for(unsigned i=0;i<4;i++){root[i]=Goldilocks::toU64(tree[(4*n-2)*4+i]);sum+=root[i];}
  times[1]+=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-t).count();
 }return sum;
}
