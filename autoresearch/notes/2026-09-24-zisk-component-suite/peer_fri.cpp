#include "fri.hpp"
extern "C" uint64_t peer_fri_batch(uint32_t log,uint32_t rounds,uint32_t constant){
 uint64_t n=1ull<<log,sum=0;std::vector<Goldilocks::Element>in(n*3),work(n*3);
 for(uint64_t i=0;i<n;i++)for(int j=0;j<3;j++)in[i*3+j]=Goldilocks::fromU64(constant?j+1:i*3+j+1);
 Goldilocks::Element alpha[3]={Goldilocks::fromU64(17),Goldilocks::fromU64(29),Goldilocks::fromU64(41)};
 for(unsigned r=0;r<rounds;r++){
  std::copy(in.begin(),in.end(),work.begin());FRI<Goldilocks::Element>::fold(1,work.data(),alpha,log,log,log-1);
  for(uint64_t i=0;i<n/2;i++)for(int j=0;j<3;j++){auto v=Goldilocks::toU64(work[i*3+j]);if(constant&&v!=uint64_t(j+1))return UINT64_MAX;sum+=v;}
 }return sum;
}
