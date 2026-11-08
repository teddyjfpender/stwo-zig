// Stage-one manifest bytes from bounded, flag-checked peer-exchange slots.
#include "rv64/custody.cuh"
#include <stdint.h>
struct StwoRv64ManifestRun {
  const uint32_t *program; uint64_t program_words;
  const uint32_t *exchange; uint64_t exchange_words;
  uint32_t tag, reserved;
  uint32_t *encoded; uint64_t encoded_words;
  uint32_t *verdict; uint32_t reject_code, reserved2;
};
static_assert(sizeof(StwoRv64ManifestRun)==72, "manifest wire ABI");
namespace {
struct Sink {
  uint32_t *out; uint64_t cap, at=0; bool bad=false;
  __device__ void byte(uint32_t v) {
    if (at>=cap) { bad=true; return; }
    if ((at&3)==0) out[at>>2]=v&255;
    else out[at>>2]|=(v&255)<<(8*(at&3));
    ++at;
  }
};
__global__ void encode(StwoRv64ManifestRun r) {
  if (blockIdx.x || threadIdx.x) return;
  r.encoded[0]=0;
  // The preceding seal owns this verdict. Never erase a seal failure.
  if (*r.verdict!=0) return;
  const uint32_t *p=r.program;
  uint32_t detail=0;
  if (p[0]!=0x31574d47u || p[1]!=1 || p[2]!=r.program_words || p[6]!=r.exchange_words ||
      p[7]!=12 || uint64_t(p[8])!=12+4ull*p[3] || uint64_t(p[8])*4+p[5]>r.program_words*4 ||
      p[4]>(64u<<20) || p[4]>(r.encoded_words-1)*4 || p[9] || p[10] || p[11]) detail=2;
  Sink sink{r.encoded+1,(r.encoded_words-1)*4};
  if (!detail) for (uint32_t i=0; i<p[3] && !detail; ++i) {
    const uint32_t *op=p+12+4ull*i;
    const uint32_t kind=op[0], off=op[1], n=op[2], flag=op[3];
    const uint32_t *src=nullptr; uint64_t bytes=0, byte_off=0;
    if (kind==0) {
      if (uint64_t(off)+n>p[5] || flag!=UINT32_MAX) { detail=2; break; }
      src=p+p[8]; byte_off=off; bytes=n;
    } else {
      if (kind>2 || uint64_t(off)+n>r.exchange_words || n==0 || flag>=r.exchange_words) { detail=2; break; }
      if (r.exchange[flag]!=r.tag) { detail=1; break; }
      src=r.exchange+off; bytes=uint64_t(n)*4;
      if (kind==2) {
        const uint32_t len=src[0];
        if (n<2 || len==0 || len>(16u<<20) || len>uint64_t(n-1)*4) { detail=4; break; }
        bytes=4ull+len;
      }
    }
    for (uint64_t j=0; j<bytes; ++j) sink.byte(src[(byte_off+j)>>2]>>(8*((byte_off+j)&3)));
    if (sink.bad || sink.at>p[4]) detail=4;
  }
  if (detail) *r.verdict=r.reject_code|detail;
  else r.encoded[0]=uint32_t(sink.at);
}
}
extern "C" int stwo_rv64_manifest_encode_v1_on(void *context,uint32_t lane,const StwoRv64ManifestRun *r) {
  if (!r || !r->program || !r->exchange || !r->encoded || !r->verdict || r->program_words<12 || r->program_words>(1u<<20) ||
      !r->exchange_words || r->exchange_words>(1ull<<28) || r->encoded_words<2 || r->encoded_words>(64u<<20)/4+1 ||
      r->reserved || r->reserved2 || !r->tag || !r->reject_code || (r->reject_code&0xffffu) || r->reject_code==0xffff0000u) return int(cudaErrorInvalidValue);
  stwo::cuda::rv64::RangeCustody<4> custody(context,lane);
  if (!custody.range(r->program,r->program_words,false) || !custody.range(r->exchange,r->exchange_words,false) ||
      !custody.range(r->encoded,r->encoded_words,true) || !custody.range(r->verdict,1,true)) return custody.status;
  encode<<<1,1,0,custody.stream>>>(*r);
  return int(cudaPeekAtLastError());
}
