#include "blake3_goldilocks.hpp"
#include <vector>
#include <cstring>
extern "C" unsigned matched_commit(unsigned log, unsigned width, const Goldilocks::Element* input, void* nodes, void* paths, void* root) {
 const size_t n=size_t(1)<<log;
 std::vector<Goldilocks::Element> tree((2*n-1)*4);
 Blake3Goldilocks::merkletree(tree.data(), const_cast<Goldilocks::Element*>(input),width,n,2,1);
 memcpy(root,tree.data()+(2*n-2)*4,32);
 if(nodes)memcpy(nodes,tree.data(),(2*n-1)*32);
 for(size_t q=0;q<70;q++) {
  size_t idx=(q*7919+17)%n,off=0,size=n;
  for(size_t level=0;level<log;level++) {
   memcpy(static_cast<char*>(paths)+(q*log+level)*32,tree.data()+(off+(idx^1))*4,32);
   idx>>=1;off+=size;size>>=1;
  }
 }
 return 0;
}

extern "C" unsigned matched_verify(unsigned log,unsigned width,const Goldilocks::Element*input,const Goldilocks::Element*paths,const void*root) {
 const size_t n=size_t(1)<<log;
 for(size_t q=0;q<70;q++) {
  size_t idx=(q*7919+17)%n;Goldilocks::Element hash[4],pair[8];
  Blake3Goldilocks::linearHash(hash,const_cast<Goldilocks::Element*>(input)+idx*width,width);
  for(size_t level=0;level<log;level++) {
   memcpy(pair+(idx&1)*4,hash,32);
   memcpy(pair+((idx&1)^1)*4,paths+(q*log+level)*4,32);
   Blake3Goldilocks::linearHash(hash,pair,8);idx>>=1;
  }
  if(memcmp(hash,root,32))return 1;
 }
 return 0;
}
