// Leaf statement tape and public-frame digest from live device proof data.
#include "rv64/custody.cuh"
#include "commitment/blake2s_core.cuh"
#include <stdint.h>

struct StwoRv64LeafRun {
  const uint32_t *program; uint64_t program_words;
  const uint32_t *sources[6]; uint64_t source_words[6];
  uint32_t *region; uint64_t region_words;
  uint32_t *verdict; uint32_t reject_code, reserved;
};
static_assert(sizeof(StwoRv64LeafRun)==144, "leaf suffix ABI");
namespace {
struct Hash {
  uint32_t h[8], block[16], n=0; uint64_t total=0;
  __device__ void init() { stwo::cuda::blake2s::initialize(h); }
  __device__ void word(uint32_t value) {
    if (n==16) { stwo::cuda::blake2s::compress(h,block,total,0); n=0; }
    block[n++]=value; total+=4;
  }
  __device__ void finish(uint32_t *out) {
    for (uint32_t i=n;i<16;++i) block[i]=0;
    stwo::cuda::blake2s::compress(h,block,total,0xffffffffu);
    for (uint32_t i=0;i<8;++i) {
      out[4*i]=h[i]&65535u; out[4*i+1]=h[i]>>16;
      out[4*i+2]=0; out[4*i+3]=0;
    }
  }
};
__device__ uint32_t emit(StwoRv64LeafRun r, bool frame, uint64_t &at, Hash &hash) {
  const uint32_t *p=r.program;
  const uint64_t first=frame?p[3]:0, count=frame?p[4]:p[3];
  uint64_t written=0;
  for (uint64_t i=0;i<count;++i) {
    const uint32_t *op=p+16+4*(first+i);
    const uint32_t kind=op[0], source=op[1], off=op[2], n=op[3];
    if (kind>2 || source>5 || (frame && kind==2)) return 2;
    const uint32_t *src=source?r.sources[source]:p+p[6];
    const uint64_t limit=source?r.source_words[source]:p[7];
    const uint64_t words=uint64_t(n)*(kind?8:1);
    if (uint64_t(off)+words>limit || (words && !src)) return 3;
    if (kind==2 && (source!=1 || n>4 || uint64_t(off)+44>limit || src[off+40]!=n)) return 5;
    if (kind) for (uint64_t j=0;j<words;++j) if (src[off+j]>=0x7fffffffu) return 6;
    if (frame) {
      if (written+words>p[9]) return 2;
      for (uint64_t j=0;j<words;++j) hash.word(src[off+j]);
      written+=words;
    } else if (kind) {
      if (written+words>4ull*p[8]) return 2;
      for (uint64_t j=0;j<words;++j) r.region[at++]=src[off+j];
      written+=words;
    } else {
      if (written+8ull*n>4ull*p[8]) return 2;
      for (uint64_t j=0;j<n;++j) {
        const uint32_t value=src[off+j];
        r.region[at++]=value&65535u;
        for (int k=0;k<3;++k) r.region[at++]=0;
        r.region[at++]=value>>16;
        for (int k=0;k<3;++k) r.region[at++]=0;
      }
      written+=8ull*n;
    }
  }
  return written==(frame?uint64_t(p[9]):4ull*p[8])?0:2;
}
__global__ void encode(StwoRv64LeafRun r) {
  if (blockIdx.x || threadIdx.x || *r.verdict) return;
  const uint32_t *p=r.program;
  uint32_t detail=0;
  const uint64_t pool=16+4ull*(uint64_t(p[3])+p[4]);
  const uint64_t tail=uint64_t(p[10])+p[11], outputs=tail+4ull*p[8];
  if (p[0]!=0x3157464cu || p[1]!=1 || p[2]!=r.program_words || p[5]!=16 ||
      uint64_t(p[3])+p[4]>(1u<<16) || p[6]!=pool || pool+p[7]!=r.program_words ||
      p[8]>(1u<<20) || !p[9] || p[9]>(1u<<20) || p[10]<2 || !p[11] ||
      p[11]!=r.source_words[5] || p[12]!=32 || outputs+32>r.region_words || p[13] || p[14] || p[15]) detail=2;
  if (!detail && (!r.region[0] || r.region[0]>4ull*(p[10]-1))) detail=4;
  Hash hash; hash.init(); uint64_t at=tail;
  if (!detail) detail=emit(r,false,at,hash);
  if (!detail) detail=emit(r,true,at,hash);
  if (!detail && at!=outputs) detail=2;
  if (detail) { r.region[0]=0; *r.verdict=r.reject_code|detail; }
  else hash.finish(r.region+outputs);
}
}
extern "C" int stwo_rv64_native_leaf_suffix_v1_on(void *context,uint32_t lane,const StwoRv64LeafRun *r) {
  if (!r || !r->program || r->program_words<16 || r->program_words>(1u<<20) ||
      !r->region || r->region_words<2 || r->region_words>(1ull<<28) || !r->verdict ||
      !r->reject_code || (r->reject_code&65535u) || r->reject_code==0xffff0000u || r->reserved ||
      r->sources[0] || r->source_words[0]) return int(cudaErrorInvalidValue);
  stwo::cuda::rv64::RangeCustody<8> custody(context,lane);
  if (!custody.range(r->program,r->program_words,false) || !custody.range(r->region,r->region_words,true) ||
      !custody.range(r->verdict,1,true)) return custody.status;
  for (uint32_t i=1;i<6;++i) {
    if (r->source_words[i]>(1ull<<31) || (r->source_words[i] && !r->sources[i])) return int(cudaErrorInvalidValue);
    if (r->source_words[i] && !custody.range(r->sources[i],r->source_words[i],false)) return custody.status;
  }
  encode<<<1,1,0,custody.stream>>>(*r);
  return int(cudaPeekAtLastError());
}
