#include "goldilocks_base_field.hpp"
#include "goldilocks_cubic_extension.hpp"
#include "blake3_goldilocks.hpp"
#include "blake3_core.hpp"
#include <vector>
extern "C" void peer_ext(uint32_t op,const uint64_t*a,const uint64_t*b,uint64_t*out){
 Goldilocks3::Element x,y,z;for(int i=0;i<3;i++){x[i]=Goldilocks::fromU64(a[i]);y[i]=Goldilocks::fromU64(b[i]);}
 if(op==0)Goldilocks3::add(z,x,y);else if(op==1)Goldilocks3::mul(z,x,y);else Goldilocks3::inv(z,x);
 for(int i=0;i<3;i++)out[i]=Goldilocks::toU64(z[i]);out[3]=0;
}
extern "C" uint64_t peer_ext_batch(uint32_t op,uint32_t rounds){
 Goldilocks3::Element x={Goldilocks::fromU64(19),Goldilocks::fromU64(29),Goldilocks::fromU64(37)},y={Goldilocks::fromU64(65537),Goldilocks::fromU64(97),Goldilocks::fromU64(103)},z;uint64_t sum=0;
 for(unsigned i=0;i<rounds;i++){if(op==0)Goldilocks3::add(z,x,y);else if(op==1)Goldilocks3::mul(z,x,y);else {x[0]=Goldilocks::fromU64(i+1);Goldilocks3::inv(z,x);}for(int j=0;j<3;j++){sum+=Goldilocks::toU64(z[j]);if(op<2)x[j]=z[j];}}return sum;
}
struct More {uint64_t n,cols;std::vector<Goldilocks::Element>input,out,tree;More(unsigned n_,unsigned c):n(n_),cols(c),input(n*c),out(n*c),tree(8*n){for(uint64_t i=0;i<input.size();i++)input[i]=Goldilocks::fromU64(i+1);}};
extern "C" void*peer_more_create(uint32_t n,uint32_t cols){return new More(n,cols);}
extern "C" void peer_more_destroy(void*p){delete (More*)p;}
extern "C" uint64_t peer_more_run(void*p,uint32_t op,uint32_t rounds,uint64_t*root){auto&t=*(More*)p;uint64_t sum=0;
 for(unsigned r=0;r<rounds;r++){
  if(op==0){Goldilocks::batchInverse(t.out.data(),t.input.data(),t.n);for(uint64_t i=0;i<t.n;i++)sum+=Goldilocks::toU64(t.out[i]);}
  else {t.input[0]=Goldilocks::fromU64(r+1);Blake3Goldilocks::merkletree(t.tree.data(),t.input.data(),t.cols,t.n,2,1);for(int i=0;i<4;i++){root[i]=Goldilocks::toU64(t.tree[(2*t.n-2)*4+i]);sum+=root[i];}}
 }return sum;
}
extern "C" uint64_t peer_native_batch(uint32_t op,uint32_t rounds){uint64_t sum=0;Goldilocks::Element in[8],out[8];for(int i=0;i<8;i++)in[i]=Goldilocks::fromU64(i+1);
 for(unsigned r=0;r<rounds;r++){in[0]=Goldilocks::fromU64(r+1);if(op==0)Blake3Goldilocks::permuteTrunc((Goldilocks::Element(&)[4])*out,in);else Blake3Goldilocks::linearHash(out,in,8);for(int j=0;j<4;j++)sum+=Goldilocks::toU64(out[j]);}return sum;
}
extern "C" void peer_more_dump(void*p,uint32_t index,uint64_t*out){auto&t=*(More*)p;for(unsigned j=0;j<4;j++)out[j]=Goldilocks::toU64(t.tree[index*4+j]);}
