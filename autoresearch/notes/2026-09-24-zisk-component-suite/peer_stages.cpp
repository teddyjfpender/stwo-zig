#include "goldilocks_base_field.hpp"
#include "ntt_goldilocks.hpp"
#include <vector>
extern "C" uint64_t peer_field(uint32_t op,uint64_t a,uint64_t b) {
 auto x=Goldilocks::fromU64(a), y=Goldilocks::fromU64(b);
 return Goldilocks::toU64(op==0?Goldilocks::add(x,y):op==1?Goldilocks::mul(x,y):Goldilocks::inv(x));
}
extern "C" uint64_t peer_field_batch(uint32_t op,uint32_t rounds) {
 auto x=Goldilocks::fromU64(19), y=Goldilocks::fromU64(65537);uint64_t sum=0;
 for(uint32_t i=0;i<rounds;i++) {
  if(op==0)x=Goldilocks::add(x,y);
  else if(op==1)x=Goldilocks::mul(x,y);
  else x=Goldilocks::inv(Goldilocks::fromU64(uint64_t(i)+1));
  sum+=Goldilocks::toU64(x);
 } return sum;
}
struct Transform {
 uint64_t n; NTT_Goldilocks plan; std::vector<Goldilocks::Element> input,a,b,aux;
 Transform(unsigned log):n(1ull<<log),plan(n,1),input(n),a(n*2),b(n*2),aux(n*2) {
  for(uint64_t i=0;i<n;i++)input[i]=Goldilocks::fromU64(i+1);
 }
};
extern "C" void* peer_transform_create(uint32_t log){return new Transform(log);}
extern "C" void peer_transform_destroy(void*p){delete (Transform*)p;}
extern "C" uint64_t peer_transform_run(void*p,uint32_t op,uint32_t rounds) {
 auto&t=*(Transform*)p;uint64_t sum=0;
 for(unsigned r=0;r<rounds;r++) {
  std::copy(t.input.begin(),t.input.end(),t.a.begin());
  if(op==0)t.plan.NTT(t.b.data(),t.a.data(),t.n,1,t.aux.data());
  else if(op==1)t.plan.INTT(t.b.data(),t.a.data(),t.n,1,t.aux.data());
  else if(op==2){t.plan.NTT(t.b.data(),t.a.data(),t.n,1,t.aux.data());t.plan.INTT(t.a.data(),t.b.data(),t.n,1,t.aux.data());for(uint64_t i=0;i<t.n;i++)if(Goldilocks::toU64(t.a[i])!=i+1)return UINT64_MAX;}
  else t.plan.LDE(t.b.data(),t.a.data(),2*t.n,t.n,1,t.aux.data());
  for(uint64_t i=0;i<(op==3?2*t.n:t.n);i++)sum+=Goldilocks::toU64(op==2?t.a[i]:t.b[i]);
 }return sum;
}
