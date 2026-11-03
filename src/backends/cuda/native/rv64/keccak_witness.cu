#include "keccak_witness.h"
#include "custody.cuh"
namespace stwo::cuda::rv64 {
__device__ __constant__ uint64_t keccak_rc[24]={
  0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
  0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
  0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
  0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
  0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
  0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL};
__device__ __constant__ uint32_t keccak_rho[25]={0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14};
__device__ uint32_t keccak_physical(uint32_t logical,uint32_t log) {
  const uint32_t n=1u<<log, circle=logical&1?n-1-logical/2:logical/2;
  return __brev(circle)>>(32-log);
}
__device__ uint64_t keccak_at(uint64_t value,uint32_t lane) {return __shfl_sync(0xffffffffu,value,lane);}
__device__ uint64_t keccak_rot(uint64_t value,uint32_t amount) {return amount?(value<<amount)|(value>>(64-amount)):value;}
__device__ uint32_t keccak_bit(uint64_t value,uint32_t z) {return uint32_t((value>>(z&63))&1);}
__device__ void keccak_write(StwoRv64KeccakWitness j,uint32_t logical,uint64_t a,uint64_t b,
    uint64_t pa,uint64_t pb,uint32_t lane,uint32_t id,bool second,uint32_t plane,bool parity) {
  const uint32_t p=keccak_physical(logical,j.log);const uint64_t n=uint64_t(1)<<j.log;
  if(lane<25) for(uint32_t bit=0;bit<64;++bit)
    j.main[(uint64_t(64*lane+bit)*n)+p]=plane==1?1-keccak_bit(a,bit):plane==2?keccak_bit(a,bit):plane==3?keccak_bit(b,bit):keccak_bit(a,bit)+8*keccak_bit(b,bit);
  if(parity&&lane<5) for(uint32_t bit=0;bit<64;++bit)
    j.main[(uint64_t(1600+64*lane+bit)*n)+p]=keccak_bit(pa,bit)+8*keccak_bit(pb,bit);
  if(!lane) {j.main[1920*n+p]=1;j.main[1921*n+p]=second;j.main[1922*n+p]=id;}
}
__device__ void keccak_count(uint32_t *counts,uint32_t row,uint32_t log,uint32_t *status) {
  if(atomicAdd(counts+keccak_physical(row,log),1u)>=0x7ffffffeu) atomicOr(status,1u);
}
__global__ void keccak_witness(StwoRv64KeccakWitness j) {
  const uint32_t lane=threadIdx.x&31,pair=(blockIdx.x*blockDim.x+threadIdx.x)/32;
  if(pair>=(j.calls+1)/2)return;
  const uint32_t x=lane<25?lane%5:0,y=lane<25?lane/5:0,id=j.first_id+2*pair,base=(j.policy?29:27)*pair;
  const bool second=2*pair+1<j.calls;
  uint64_t a=0,b=0;
  if(lane<25) {
    const uint32_t *p=j.inputs+uint64_t(2*pair)*50+2*lane;
    a=uint64_t(p[0])|(uint64_t(p[1])<<32);
    if(second){p+=50;b=uint64_t(p[0])|(uint64_t(p[1])<<32);}
  }
  keccak_write(j,base,a,b,0,0,lane,id,second,j.policy?2:1,false);
  if(j.policy)keccak_write(j,base+1,a,b,0,0,lane,id,second,3,false);
  for(uint32_t round=0;round<24;++round) {
    uint64_t pa=0,pb=0;
#pragma unroll
    for(uint32_t yy=0;yy<5;++yy){pa^=keccak_at(a,x+5*yy);pb^=keccak_at(b,x+5*yy);}
    keccak_write(j,base+(j.policy?2:1)+round,a,b,pa,pb,lane,id,second,false,true);
    // Original throughput table indices: one five-output chi fact per(y,z),
    // one three-position xor5 fact. The inactive odd B still executes zero's
    // permutation, exactly as the native paired witness authority does.
    if(j.policy) {
      for(uint32_t event=lane;event<1600;event+=32) {
        const uint32_t xx=(event/64)%5,yy=event/320,z=event%64;uint32_t row=0,power=1;
        for(uint32_t offset=0;offset<3;++offset) {
          const uint32_t target=(xx+offset)%5,sx=(target+3*yy)%5,sy=target,sz=(z+64-keccak_rho[sx+5*sy])&63;
          const uint32_t aa=keccak_bit(keccak_at(a,sx+5*sy),sz)+keccak_bit(keccak_at(pa,(sx+4)%5),sz)+keccak_bit(keccak_at(pa,(sx+1)%5),(sz+63)&63);
          const uint32_t bb=keccak_bit(keccak_at(b,sx+5*sy),sz)+keccak_bit(keccak_at(pb,(sx+4)%5),sz)+keccak_bit(keccak_at(pb,(sx+1)%5),(sz+63)&63);
          row+=power*(aa+4*bb);power*=16;
        }
        if(!xx&&!yy&&keccak_bit(keccak_rc[round],z))row+=4096;
        keccak_count(j.chi,row,13,j.status);
      }
      for(uint32_t event=lane;event<320;event+=32) {
        const uint32_t xx=event/64,z=event%64;uint32_t row=0,power=1;
        for(uint32_t yy=0;yy<5;++yy){const uint32_t aa=keccak_bit(keccak_at(a,xx+5*yy),z),bb=keccak_bit(keccak_at(b,xx+5*yy),z);row+=power*(aa+2*bb);power*=4;}
        keccak_count(j.xor5,row,10,j.status);
      }
    } else {
    for(uint32_t event=lane;event<320;event+=32) {
      const uint32_t yy=event/64,z=event%64;uint32_t row=0,power=1;
      for(uint32_t xx=0;xx<5;++xx) {
        const uint32_t sx=(xx+3*yy)%5,sy=xx,sz=(z+64-keccak_rho[sx+5*sy])&63;
        const uint32_t ta=keccak_bit(keccak_at(a,sx+5*sy),sz)+keccak_bit(keccak_at(pa,(sx+4)%5),sz)+keccak_bit(keccak_at(pa,(sx+1)%5),(sz+63)&63);
        const uint32_t tb=keccak_bit(keccak_at(b,sx+5*sy),sz)+keccak_bit(keccak_at(pb,(sx+4)%5),sz)+keccak_bit(keccak_at(pb,(sx+1)%5),(sz+63)&63);
        row+=power*(ta+4*tb);power*=16;
      }
      if(!yy&&keccak_bit(keccak_rc[round],z))row+=1u<<20;
      keccak_count(j.chi,row,21,j.status);
    }
    for(uint32_t group=0;group<4;++group) {
      const uint32_t event=lane+32*group;uint32_t row=0,power=1;
      for(uint32_t i=0;i<3;++i) {
        const uint32_t position=3*event+i,xx=position<320?position/64:0,z=position%64;
        uint32_t sa=0,sb=0;
#pragma unroll
        for(uint32_t yy=0;yy<5;++yy) {
          const uint32_t aa=keccak_bit(keccak_at(a,xx+5*yy),z),bb=keccak_bit(keccak_at(b,xx+5*yy),z);
          if(position<320){sa+=aa;sb+=bb;}
        }
        row+=power*(sa+6*sb);power*=36;
      }
      if(event<107)keccak_count(j.xor5,row,16,j.status);
    }
    }
    const uint64_t ta=a^keccak_at(pa,(x+4)%5)^keccak_rot(keccak_at(pa,(x+1)%5),1);
    const uint64_t tb=b^keccak_at(pb,(x+4)%5)^keccak_rot(keccak_at(pb,(x+1)%5),1);
    // Invert(x,y)->(y,2x+3y) so each lane gathers its rho/pi source.
    uint32_t source=0;
    for(uint32_t s=0;s<25;++s)if(s/5+5*((2*(s%5)+3*(s/5))%5)==lane)source=s;
    const uint64_t ra=keccak_rot(keccak_at(ta,source),keccak_rho[source]),rb=keccak_rot(keccak_at(tb,source),keccak_rho[source]);
    a=ra^((~keccak_at(ra,(x+1)%5+5*y))&keccak_at(ra,(x+2)%5+5*y));
    b=rb^((~keccak_at(rb,(x+1)%5+5*y))&keccak_at(rb,(x+2)%5+5*y));
    if(!lane){a^=keccak_rc[round];b^=keccak_rc[round];}
  }
  keccak_write(j,base+(j.policy?26:25),a,b,0,0,lane,id,second,0,false);
  keccak_write(j,base+(j.policy?27:26),a,b,0,0,lane,id,second,j.policy?2:1,false);
  if(j.policy)keccak_write(j,base+28,a,b,0,0,lane,id,second,3,false);
}
}
extern "C" int stwo_rv64_keccak_witness_on(void *ctx,uint32_t lane,const StwoRv64KeccakWitness *p) {
  using namespace stwo::cuda::rv64;
  if(!p||p->policy>1||!p->calls||p->log<5||p->log>22||!p->first_id||uint64_t(p->first_id)+p->calls>0x7fffffffu||
      uint64_t((p->calls+1)/2)*(p->policy?29:27)>(uint64_t(1)<<p->log)||p->input_words<uint64_t(p->calls)*50||p->main_words<(uint64_t(1923)<<p->log))return int(cudaErrorInvalidValue);
  Custody c(ctx,lane);
  if(!c.range(p->inputs,uint64_t(p->calls)*50,false)||!c.range(p->main,uint64_t(1923)<<p->log,true)||
      !c.range(p->chi,1u<<(p->policy?13:21),true)||!c.range(p->xor5,1u<<(p->policy?10:16),true)||!c.range(p->status,1,true))return c.status;
  int status=int(cudaMemsetAsync(p->main,0,(uint64_t(1923)<<p->log)*4,c.stream));
  if(!status)status=int(cudaMemsetAsync(p->chi,0,(1u<<(p->policy?13:21))*4,c.stream));
  if(!status)status=int(cudaMemsetAsync(p->xor5,0,(1u<<(p->policy?10:16))*4,c.stream));
  if(!status)status=int(cudaMemsetAsync(p->status,0,4,c.stream));
  if(status)return status;
  keccak_witness<<<((p->calls+1)/2+3)/4,128,0,c.stream>>>(*p);
  return int(cudaPeekAtLastError());
}
