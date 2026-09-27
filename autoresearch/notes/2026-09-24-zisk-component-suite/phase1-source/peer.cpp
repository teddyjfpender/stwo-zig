#include "blake3_core.hpp"
#include "gate_bands_blake3.hpp"
#include <vector>
extern "C" void peer_hash(const uint64_t* in, uint32_t n, uint64_t* out, uint32_t mode) {
 if(mode==0) blake3core::hash_le64(in,n,out);
 else if(mode==1) { blake3core::Hasher h; h.init(); for(uint32_t i=0;i<n;i+=7)h.absorb(in+i, std::min(7u,n-i));h.finalize_xof(0,out); }
 else blake3core::permute_xof(in,n,out);
}
extern "C" void peer_compress_case(const uint32_t*cv,const uint32_t*b,uint64_t counter,uint8_t len,uint8_t flags,uint32_t*out) {
 blake3core::compress_xof(cv,b,len,counter,flags,out);
}
extern "C" void peer_expand_case(const uint32_t*cv,const uint32_t*b,uint32_t counter,uint32_t len,uint32_t flags,uint32_t*out,uint64_t*checksum) {
 namespace w=gate_bands::blake3;
 w::BlockInputs in; std::copy(cv,cv+8,in.cv);std::copy(b,b+16,in.block);in.counterLo=counter;in.blockLen=len;in.flags=flags;
 w::Multiplicities counts; w::HostSink sink{counts};
 std::vector<uint64_t> trace(w::stage1_cols(1,18)*56,0);
 uint32_t fs[16];w::expand_lane(trace.data(),w::stage1_cols(1,18),0,0,w::layout(1,18),in,sink,fs);
 for(unsigned i=0;i<8;i++){out[i]=fs[i]^fs[i+8];out[i+8]=fs[i+8]^cv[i];}
 uint64_t sum=0;for(auto x:trace)sum+=x;for(auto x:counts.table)sum+=x;for(auto x:counts.range)sum+=x;*checksum=sum;
}
extern "C" uint64_t peer_batch(uint32_t op,uint32_t words,uint32_t rounds) {
 uint64_t sum=0;std::vector<uint64_t> input(std::max(words,8u));for(uint32_t j=0;j<input.size();j++)input[j]=j*uint64_t(0x1234567);
 uint64_t out[8];uint32_t block[16],cv[8],result[16];for(unsigned j=0;j<16;j++)block[j]=j*0x1234567u;std::copy(blake3core::IV_host,blake3core::IV_host+8,cv);
 namespace w=gate_bands::blake3;
 w::Multiplicities counts;w::HostSink sink{counts};std::vector<uint64_t> trace(w::stage1_cols(1,18)*56,0);
 for(uint32_t i=0;i<rounds;i++) {
  input[0]=i;block[0]=i;
  if(op<3) {peer_hash(input.data(),words,out,op);for(unsigned j=0;j<(op==0?4:8);j++)sum+=out[j];}
  else if(op==3){blake3core::compress_xof(cv,block,64,0,11,result);for(auto x:result)sum+=x;}
  else {
   w::BlockInputs in;std::copy(cv,cv+8,in.cv);std::copy(block,block+16,in.block);in.counterLo=0;in.blockLen=64;in.flags=11;
   w::expand_lane(trace.data(),w::stage1_cols(1,18),0,0,w::layout(1,18),in,sink,result);
   for(auto x:trace)sum+=x;
  }
 }
 if(op==4) {for(auto x:counts.table)sum+=x;for(auto x:counts.range)sum+=x;}
 return sum;
}
