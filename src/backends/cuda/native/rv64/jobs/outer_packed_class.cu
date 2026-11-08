// Reuse the reviewed cache_pack decoder; only the resident, relocatable
// single-image header is new. No per-request compressed upload or host unpack.
#define STWO_RV64_M9_STANDALONE
#include "../m9_class_unpack.cu"
#include "rv64/custody.cuh"
struct StwoRv64PackedClassRun {
  const uint32_t *program; uint64_t program_words;
  uint32_t *output; uint64_t output_words;
  uint32_t *scratch, *verdict;
  uint32_t blocks, data_bytes, reject_code, channels;
};
static_assert(sizeof(StwoRv64PackedClassRun)==64,"packed class ABI");
namespace {
__global__ void prepare(StwoRv64PackedClassRun r) {
  if (threadIdx.x || blockIdx.x) return;
  const uint32_t *p=r.program;
  const uint64_t data_at=16ull+4ull*r.blocks;
  bool ok=p[0]==0x3143504fu && p[1]==2 && p[2]==r.program_words && p[3]==r.output_words &&
      p[4]==r.blocks && p[5]==r.data_bytes && p[6]==data_at && uint64_t(p[7])+p[8]==r.output_words &&
      data_at*4+r.data_bytes<=r.program_words*4 && p[9]==r.channels;
  for (unsigned i=10;i<16;++i) ok=ok && !p[i];
  StwoRv64M9PackedJob j{};
  j.data=reinterpret_cast<const uint8_t*>(p+data_at);
  j.blocks=reinterpret_cast<const StwoRv64M9PackedBlock*>(p+16);
  j.output=r.output; j.data_bytes=r.data_bytes; j.words=ok?r.output_words:0; j.channels=r.channels;
  *reinterpret_cast<StwoRv64M9PackedJob*>(r.scratch)=j;
  *r.verdict=ok?0:STWO_RV64_M9_UNPACK_SHAPE;
}
__global__ void finish(uint32_t *verdict,uint32_t reject) {
  if (!blockIdx.x && !threadIdx.x && *verdict) *verdict=reject|(*verdict&65535u);
}
}
extern "C" int stwo_rv64_outer_packed_class_v2_on(void *ctx,uint32_t lane,const StwoRv64PackedClassRun *r) {
  if (!r || !r->program || !r->output || !r->scratch || !r->verdict || r->program_words<16 ||
      r->program_words>(1ull<<30) || !r->output_words || r->output_words>0xffffffffull ||
      !r->blocks || r->blocks!=(r->output_words+16383)/16384 || !r->channels || r->channels>128 ||
      (r->channels&(r->channels-1)) || r->output_words%r->channels ||
      !r->reject_code || (r->reject_code&65535u) || 16ull+4ull*r->blocks+(uint64_t(r->data_bytes)+3)/4>r->program_words)
    return int(cudaErrorInvalidValue);
  stwo::cuda::rv64::RangeCustody<4> custody(ctx,lane);
  if (!custody.range(r->program,r->program_words,false) || !custody.range(r->output,r->output_words,true) ||
      !custody.range(r->scratch,12,true) || !custody.range(r->verdict,1,true)) return custody.status;
  prepare<<<1,1,0,custody.stream>>>(*r);
  int status=stwo_rv64_m9_class_unpack_stream(custody.stream,reinterpret_cast<const StwoRv64M9PackedJob*>(r->scratch),1,r->blocks,r->verdict);
  if (status) return status;
  finish<<<1,1,0,custody.stream>>>(r->verdict,r->reject_code);
  return int(cudaPeekAtLastError());
}
