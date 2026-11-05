#include "custody.cuh"
#include "sha256_witness.h"
namespace stwo::cuda::rv64 {
namespace sha {
constexpr uint32_t W=1,A=2049,E=4225,SCHEDULE=6401,ROUND=6593,FINAL=7361,OUT=7377,MAIN=7409;
__device__ __constant__ uint32_t K[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
__device__ __forceinline__ uint32_t rr(uint32_t x,uint32_t n){return (x>>n)|(x<<(32-n));}
__device__ __forceinline__ uint32_t s0(uint32_t x){return rr(x,7)^rr(x,18)^(x>>3);}
__device__ __forceinline__ uint32_t s1(uint32_t x){return rr(x,17)^rr(x,19)^(x>>10);}
__device__ __forceinline__ uint32_t S0(uint32_t x){return rr(x,2)^rr(x,13)^rr(x,22);}
__device__ __forceinline__ uint32_t S1(uint32_t x){return rr(x,6)^rr(x,11)^rr(x,25);}
struct Sum{uint32_t value,lo,hi;};
template<uint32_t Count> __device__ __forceinline__ Sum add(const uint32_t(&v)[Count]){
 uint32_t lo=0,hi=0;
 #pragma unroll
 for(uint32_t i=0;i<Count;++i){lo+=v[i]&65535u;hi+=v[i]>>16;}
 const uint32_t cl=lo>>16;hi+=cl;return {(lo&65535u)|((hi&65535u)<<16),cl,hi>>16};
}
__device__ __forceinline__ void bits(uint32_t*out,uint32_t rows,uint32_t row,uint32_t col,uint32_t value,uint32_t count){
 #pragma unroll
 for(uint32_t i=0;i<count;++i)out[uint64_t(col+i)*rows+row]=(value>>i)&1u;
}
__device__ __forceinline__ uint32_t be(uint32_t v){return (v>>24)|((v>>8)&0xff00u)|((v<<8)&0xff0000u)|(v<<24);}
__global__ void witness(StwoRv64Sha256Witness j){
 const uint32_t row=blockIdx.x*blockDim.x+threadIdx.x,rows=1u<<j.log;if(row>=rows)return;
 const uint32_t circle=__brev(row)>>(32-j.log);
 const uint32_t logical=circle<rows/2?2*circle:2*(rows-1-circle)+1;
 const bool active=logical<j.calls;
 const uint32_t*input=active?j.inputs+uint64_t(logical)*24:nullptr;
 uint32_t state[8],av[4],ev[4],w[16];
 #pragma unroll
 for(uint32_t i=0;i<8;++i)state[i]=active?input[i]:0;
 j.main[row]=active?1:0;
 #pragma unroll
 for(uint32_t i=0;i<4;++i){
  av[i]=state[i];ev[i]=state[4+i];
  bits(j.main,rows,row,A+32*(3-i),av[i],32);
  bits(j.main,rows,row,E+32*(3-i),ev[i],32);
 }
 // This bounded loop avoids a7409-column per-thread temporary and a giant
 // cold NVVM expression. Only16 schedule words and two shift registers live.
 #pragma unroll 1
 for(uint32_t t=0;t<64;++t){
  uint32_t wt;
  if(t<16)wt=active?be(input[8+t]):0;
  else{
   const uint32_t v[4]={s1(w[(t-2)&15]),w[(t-7)&15],s0(w[(t-15)&15]),w[t&15]};const auto sum=add(v);wt=sum.value;
   bits(j.main,rows,row,SCHEDULE+4*(t-16),sum.lo,2);
   bits(j.main,rows,row,SCHEDULE+4*(t-16)+2,sum.hi,2);
  }
  w[t&15]=wt;bits(j.main,rows,row,W+32*t,wt,32);
  const uint32_t sigma1=S1(ev[0]),choose=(ev[0]&ev[1])^(~ev[0]&ev[2]);
  const uint32_t sigma0=S0(av[0]),majority=(av[0]&av[1])^(av[0]&av[2])^(av[1]&av[2]);
  const uint32_t e_terms[6]={av[3],ev[3],sigma1,choose,K[t],wt};
  const uint32_t a_terms[7]={ev[3],sigma1,choose,K[t],wt,sigma0,majority};
  const auto ne=add(e_terms),na=add(a_terms);
  bits(j.main,rows,row,A+32*(t+4),na.value,32);
  bits(j.main,rows,row,E+32*(t+4),ne.value,32);
  bits(j.main,rows,row,ROUND+12*t,ne.lo,3);bits(j.main,rows,row,ROUND+12*t+3,ne.hi,3);
  bits(j.main,rows,row,ROUND+12*t+6,na.lo,3);bits(j.main,rows,row,ROUND+12*t+9,na.hi,3);
  #pragma unroll
  for(uint32_t i=3;i>0;--i){av[i]=av[i-1];ev[i]=ev[i-1];}av[0]=na.value;ev[0]=ne.value;
 }
 #pragma unroll
 for(uint32_t i=0;i<8;++i){
  const uint32_t terms[2]={state[i],i<4?av[i]:ev[i-4]};const auto sum=add(terms);
  bits(j.main,rows,row,FINAL+2*i,sum.lo,1);bits(j.main,rows,row,FINAL+2*i+1,sum.hi,1);
  #pragma unroll
  for(uint32_t b=0;b<4;++b)j.main[uint64_t(OUT+4*i+b)*rows+row]=(sum.value>>(8*b))&255u;
 }
}
} // namespace sha
} // namespace stwo::cuda::rv64
extern "C" __attribute__((visibility("default"))) int stwo_rv64_sha256_witness_on(void*ctx,uint32_t lane,const StwoRv64Sha256Witness*input){
 using namespace stwo::cuda::rv64;
 if(!input||input->reserved||input->log<5||input->log>20||!input->first_id||input->first_id>=0x7fffffffu)return int(cudaErrorInvalidValue);
 const auto j=*input;const uint64_t rows=1ull<<j.log;
 if(j.calls>=rows||uint64_t(j.first_id)+j.calls>0x7fffffffull||j.input_words!=uint64_t(j.calls)*24||j.main_words<rows*sha::MAIN)return int(cudaErrorInvalidValue);
 Custody c(ctx,lane);
 if((j.calls&&!c.range(j.inputs,j.input_words,false))||!c.range(j.main,rows*sha::MAIN,true)||!c.range(j.status,1,true))return c.status;
 sha::witness<<<(rows+127)/128,128,0,c.stream>>>(j);return int(cudaPeekAtLastError());
}
