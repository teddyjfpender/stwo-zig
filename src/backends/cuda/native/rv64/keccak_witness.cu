#include "keccak_witness.h"
#include "custody.cuh"
#include <stdlib.h>
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
// ---- M8 T9 coalesced path (STWO_RV64_M8_WITNESS_COALESCE=1; same ABI, same counts) ----
// keccak_witness writes every bit-column of one logical row with a 4-byte store
// to keccak_physical(row): a store instruction touches 25 sectors, and the 8
// rows of a 32 B sector belong to pairs n/4 logical rows apart, so DRAM sees a
// read-modify-write per 4 bytes ([M] census2: 38-75 GB/s). Physical-row tiles
// cannot be formed inside one CTA (32 consecutive physical rows come from 32
// logical rows n/32 apart). So the work is split in two coalesced passes:
//   1. keccak_witness_staged: each warp runs its pair's permutation exactly as
//      keccak_witness does (same lookup events, same atomics), and stages the
//      25 distinct states + 24 parities in shared memory. The CTA then writes
//      its 4 pairs' rows in CIRCLE order (even logical rows ascend from row/2,
//      odd rows descend from n-1-row/2), so a warp store is 32 consecutive
//      words. Every column of an active row is written (zeros included).
//   2. keccak_bitrev: in-place circle -> bit-reversed physical permutation of
//      each column, 32x32 shared tiles (both tiles of a brev pair are read
//      before either is written), coalesced loads and stores. Inactive circle
//      rows are read as zero, so MAIN needs no memset.
constexpr uint32_t keccak_stage_warps=4;
struct KeccakStage {uint64_t a[25][25],b[25][25],pa[24][5],pb[24][5];};  // 11,920 B per warp
static_assert(sizeof(KeccakStage)*keccak_stage_warps<=48u*1024u,"static shared memory");
// One round's lookup events, verbatim from keccak_witness (same tuples, same
// order). Global: the original atomics + overflow status. Shared: privatised
// table indexed by logical row (policy 1 only; keccak_witness_counts flushes
// bin i to keccak_physical(i), where keccak_count puts it).
template<bool Shared>
__device__ __forceinline__ void keccak_events(const StwoRv64KeccakWitness &j,uint32_t round,uint32_t lane,uint64_t a,uint64_t b,
    uint64_t pa,uint64_t pb,uint32_t *chi,uint32_t *xor5) {
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
      if(Shared)atomicAdd(chi+row,1u);else keccak_count(chi,row,13,j.status);
    }
    for(uint32_t event=lane;event<320;event+=32) {
      const uint32_t xx=event/64,z=event%64;uint32_t row=0,power=1;
      for(uint32_t yy=0;yy<5;++yy){const uint32_t aa=keccak_bit(keccak_at(a,xx+5*yy),z),bb=keccak_bit(keccak_at(b,xx+5*yy),z);row+=power*(aa+2*bb);power*=4;}
      if(Shared)atomicAdd(xor5+row,1u);else keccak_count(xor5,row,10,j.status);
    }
  } else if(!Shared) {
  for(uint32_t event=lane;event<320;event+=32) {
    const uint32_t yy=event/64,z=event%64;uint32_t row=0,power=1;
    for(uint32_t xx=0;xx<5;++xx) {
      const uint32_t sx=(xx+3*yy)%5,sy=xx,sz=(z+64-keccak_rho[sx+5*sy])&63;
      const uint32_t ta=keccak_bit(keccak_at(a,sx+5*sy),sz)+keccak_bit(keccak_at(pa,(sx+4)%5),sz)+keccak_bit(keccak_at(pa,(sx+1)%5),(sz+63)&63);
      const uint32_t tb=keccak_bit(keccak_at(b,sx+5*sy),sz)+keccak_bit(keccak_at(pb,(sx+4)%5),sz)+keccak_bit(keccak_at(pb,(sx+1)%5),(sz+63)&63);
      row+=power*(ta+4*tb);power*=16;
    }
    if(!yy&&keccak_bit(keccak_rc[round],z))row+=1u<<20;
    keccak_count(chi,row,21,j.status);
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
    if(event<107)keccak_count(xor5,row,16,j.status);
  }
  }
}
// Permutation of one pair (warp), exactly as keccak_witness; Stage records
// the 25 states and 24 parities, Count emits the lookup events.
template<bool Stage,uint32_t Count>  // Count: 0 none, 1 global, 2 shared
__device__ __forceinline__ void keccak_pair(const StwoRv64KeccakWitness &j,uint32_t pair,uint32_t lane,KeccakStage *st,uint32_t *chi,uint32_t *xor5) {
  const uint32_t x=lane<25?lane%5:0,y=lane<25?lane/5:0;
  uint64_t a=0,b=0;
  if(lane<25) {
    const uint32_t *p=j.inputs+uint64_t(2*pair)*50+2*lane;
    a=uint64_t(p[0])|(uint64_t(p[1])<<32);
    if(2*pair+1<j.calls){p+=50;b=uint64_t(p[0])|(uint64_t(p[1])<<32);}
  }
  if(Stage&&lane<25){st->a[0][lane]=a;st->b[0][lane]=b;}
  for(uint32_t round=0;round<24;++round) {
    uint64_t pa=0,pb=0;
#pragma unroll
    for(uint32_t yy=0;yy<5;++yy){pa^=keccak_at(a,x+5*yy);pb^=keccak_at(b,x+5*yy);}
    if(Stage&&lane<5){st->pa[round][lane]=pa;st->pb[round][lane]=pb;}
    if(Count)keccak_events<Count==2>(j,round,lane,a,b,pa,pb,chi,xor5);
    const uint64_t ta=a^keccak_at(pa,(x+4)%5)^keccak_rot(keccak_at(pa,(x+1)%5),1);
    const uint64_t tb=b^keccak_at(pb,(x+4)%5)^keccak_rot(keccak_at(pb,(x+1)%5),1);
    uint32_t source=0;
    for(uint32_t s=0;s<25;++s)if(s/5+5*((2*(s%5)+3*(s/5))%5)==lane)source=s;
    const uint64_t ra=keccak_rot(keccak_at(ta,source),keccak_rho[source]),rb=keccak_rot(keccak_at(tb,source),keccak_rho[source]);
    a=ra^((~keccak_at(ra,(x+1)%5+5*y))&keccak_at(ra,(x+2)%5+5*y));
    b=rb^((~keccak_at(rb,(x+1)%5+5*y))&keccak_at(rb,(x+2)%5+5*y));
    if(!lane){a^=keccak_rc[round];b^=keccak_rc[round];}
    if(Stage&&lane<25){st->a[round+1][lane]=a;st->b[round+1][lane]=b;}
  }
}
// Count: policy 0 counts here with the original global atomics (its 2^21/2^16
// tables do not fit in shared memory); policy 1 counts in keccak_witness_counts.
template<bool Count>
__global__ void __launch_bounds__(32*keccak_stage_warps) keccak_witness_staged(StwoRv64KeccakWitness j) {
  __shared__ KeccakStage stage[keccak_stage_warps];
  const uint32_t lane=threadIdx.x&31,warp=threadIdx.x/32,pairs=(j.calls+1)/2,pair=blockIdx.x*keccak_stage_warps+warp;
  if(pair<pairs)keccak_pair<true,Count?1u:0u>(j,pair,lane,stage+warp,j.chi,j.xor5);
  __syncthreads();
  // Emit: thread k<count owns one logical row of this CTA (evens first, then
  // odds), so lane-consecutive threads hold consecutive circle rows.
  const uint32_t first_pair=blockIdx.x*keccak_stage_warps;
  if(first_pair>=pairs)return;
  const uint32_t rows=j.policy?29:27,live=min(keccak_stage_warps,pairs-first_pair),count=rows*live,first=rows*first_pair;
  const uint32_t evens=(count+1)/2,k=threadIdx.x;  // first is even: rows*keccak_stage_warps is even
  if(k>=count)return;
  const uint64_t n=uint64_t(1)<<j.log;
  const uint32_t r=k<evens?2*k:2*(k-evens)+1,circle=k<evens?first/2+k:uint32_t(n-1)-first/2-(k-evens);
  const uint32_t w=r/rows,o=r%rows,id=j.first_id+2*(first_pair+w);
  const bool second=2*(first_pair+w)+1<j.calls;
  // Row offset -> (state, plane, parity round); plane 0=a+8b, 1=1-a, 2=a, 3=b.
  uint32_t s,plane,parity=24;
  if(!j.policy){
    if(!o){s=0;plane=1;}else if(o<=24){s=o-1;plane=0;parity=o-1;}else{s=24;plane=o==25?0:1;}
  }else{
    if(o<2){s=0;plane=o?3:2;}else if(o<=25){s=o-2;plane=0;parity=o-2;}else{s=24;plane=o==26?0:o==27?2:3;}
  }
  const KeccakStage &src=stage[w];
  uint32_t *out=j.main+circle;
  for(uint32_t l=0;l<25;++l) {
    const uint64_t va=src.a[s][l],vb=src.b[s][l];
#pragma unroll 8
    for(uint32_t bit=0;bit<64;++bit) {
      const uint32_t ab=keccak_bit(va,bit),bb=keccak_bit(vb,bit);
      out[uint64_t(64*l+bit)*n]=plane==1?1-ab:plane==2?ab:plane==3?bb:ab+8*bb;
    }
  }
  for(uint32_t l=0;l<5;++l) {
    const uint64_t va=parity<24?src.pa[parity][l]:0,vb=parity<24?src.pb[parity][l]:0;
#pragma unroll 8
    for(uint32_t bit=0;bit<64;++bit)out[uint64_t(1600+64*l+bit)*n]=keccak_bit(va,bit)+8*keccak_bit(vb,bit);
  }
  out[1920*n]=1;out[1921*n]=second;out[1922*n]=id;
}
// Policy 1 lookup counts: chi (2^13) and xor5 (2^10) privatised per CTA in
// 36 KB of shared memory, persistent grid-stride over pairs, one flush per
// nonzero bin. The overflow status matches keccak_count's: some increment
// saw >= 0x7ffffffe <=> the final total >= 0x7fffffff <=> some flush ends there.
constexpr uint32_t keccak_count_warps=8;
__global__ void __launch_bounds__(32*keccak_count_warps) keccak_witness_counts(StwoRv64KeccakWitness j) {
  __shared__ uint32_t chi[1u<<13],xor5[1u<<10];
  for(uint32_t i=threadIdx.x;i<(1u<<13);i+=blockDim.x)chi[i]=0;
  for(uint32_t i=threadIdx.x;i<(1u<<10);i+=blockDim.x)xor5[i]=0;
  __syncthreads();
  const uint32_t lane=threadIdx.x&31,pairs=(j.calls+1)/2;
  for(uint32_t pair=blockIdx.x*keccak_count_warps+threadIdx.x/32;pair<pairs;pair+=gridDim.x*keccak_count_warps)
    keccak_pair<false,2>(j,pair,lane,nullptr,chi,xor5);
  __syncthreads();
  for(uint32_t i=threadIdx.x;i<(1u<<13);i+=blockDim.x)
    if(chi[i]&&atomicAdd(j.chi+keccak_physical(i,13),chi[i])+chi[i]-1>=0x7ffffffeu)atomicOr(j.status,1u);
  for(uint32_t i=threadIdx.x;i<(1u<<10);i+=blockDim.x)
    if(xor5[i]&&atomicAdd(j.xor5+keccak_physical(i,10),xor5[i])+xor5[i]-1>=0x7ffffffeu)atomicOr(j.status,1u);
}
__device__ __forceinline__ uint32_t keccak_brev(uint32_t v,uint32_t bits) {return bits?__brev(v)>>(32-bits):0;}
// circle rows [even_end, odd_begin) were never written: read them as zero.
__global__ void __launch_bounds__(256) keccak_bitrev(uint32_t *main,uint32_t log,uint32_t even_end,uint32_t odd_begin) {
  __shared__ uint32_t t0[32][33],t1[32][33];
  const uint32_t mbits=log-10,m=blockIdx.x,mp=keccak_brev(m,mbits);
  if(m>mp)return;
  const uint64_t n=uint64_t(1)<<log;uint32_t *base=main+uint64_t(blockIdx.y)*n;
  const uint32_t tx=threadIdx.x&31,ty=threadIdx.x/32,high=log-5;
#pragma unroll
  for(uint32_t a=ty;a<32;a+=8) {
    const uint32_t c=(a<<high)|(m<<5)|tx,cp=(a<<high)|(mp<<5)|tx;
    t0[a][tx]=c<even_end||c>=odd_begin?base[c]:0;
    if(m!=mp)t1[a][tx]=cp<even_end||cp>=odd_begin?base[cp]:0;
  }
  __syncthreads();
  const uint32_t rb=__brev(tx)>>27;
#pragma unroll
  for(uint32_t a=ty;a<32;a+=8) {
    const uint32_t ra=__brev(a)>>27;
    base[(a<<high)|(mp<<5)|tx]=t0[rb][ra];
    if(m!=mp)base[(a<<high)|(m<<5)|tx]=t1[rb][ra];
  }
}
// log 5..9: one CTA per column holds the whole column.
__global__ void __launch_bounds__(256) keccak_bitrev_small(uint32_t *main,uint32_t log,uint32_t even_end,uint32_t odd_begin) {
  __shared__ uint32_t column[512];
  const uint32_t n=1u<<log;uint32_t *base=main+uint64_t(blockIdx.x)*n;
  for(uint32_t c=threadIdx.x;c<n;c+=blockDim.x)column[c]=c<even_end||c>=odd_begin?base[c]:0;
  __syncthreads();
  for(uint32_t p=threadIdx.x;p<n;p+=blockDim.x)base[p]=column[__brev(p)>>(32-log)];
}
// -1 = read STWO_RV64_M8_WITNESS_COALESCE once; tests may set 0/1 directly.
static int keccak_coalesce=-1;
static bool witness_coalesce() {
  if(keccak_coalesce<0){const char *v=nullptr;keccak_coalesce=!(v&&v[0]=='0'&&!v[1]); /* default ON (M8 opt-combined): keccak_witness 0.342 -> staged+bitrev 0.021 GPU-s per warm 24628607 request [M] */}
  return keccak_coalesce==1;
}
}
extern "C" int stwo_rv64_keccak_witness_on(void *ctx,uint32_t lane,const StwoRv64KeccakWitness *p) {
  using namespace stwo::cuda::rv64;
  if(!p||p->policy>1||!p->calls||p->log<5||p->log>22||!p->first_id||uint64_t(p->first_id)+p->calls>0x7fffffffu||
      uint64_t((p->calls+1)/2)*(p->policy?29:27)>(uint64_t(1)<<p->log)||p->input_words<uint64_t(p->calls)*50||p->main_words<(uint64_t(1923)<<p->log))return int(cudaErrorInvalidValue);
  Custody c(ctx,lane);
  if(!c.range(p->inputs,uint64_t(p->calls)*50,false)||!c.range(p->main,uint64_t(1923)<<p->log,true)||
      !c.range(p->chi,1u<<(p->policy?13:21),true)||!c.range(p->xor5,1u<<(p->policy?10:16),true)||!c.range(p->status,1,true))return c.status;
  const bool coalesce=witness_coalesce();
  int status=coalesce?0:int(cudaMemsetAsync(p->main,0,(uint64_t(1923)<<p->log)*4,c.stream));
  if(!status)status=int(cudaMemsetAsync(p->chi,0,(1u<<(p->policy?13:21))*4,c.stream));
  if(!status)status=int(cudaMemsetAsync(p->xor5,0,(1u<<(p->policy?10:16))*4,c.stream));
  if(!status)status=int(cudaMemsetAsync(p->status,0,4,c.stream));
  if(status)return status;
  if(!coalesce) {
    keccak_witness<<<((p->calls+1)/2+3)/4,128,0,c.stream>>>(*p);
    return int(cudaPeekAtLastError());
  }
  const uint32_t pairs=(p->calls+1)/2,active=pairs*(p->policy?29:27),even_end=(active+1)/2,odd_begin=(1u<<p->log)-active/2;
  const uint32_t grid=(pairs+keccak_stage_warps-1)/keccak_stage_warps;
  if(p->policy) {
    int sms=0,device=0;
    if(!cudaGetDevice(&device))cudaDeviceGetAttribute(&sms,cudaDevAttrMultiProcessorCount,device);
    // 2 CTAs/SM fit (36 KB each); persistent grid caps the flush at 2*SMs*9216 atomics.
    const uint32_t cgrid=min((pairs+keccak_count_warps-1)/keccak_count_warps,uint32_t(sms>0?2*sms:340));
    keccak_witness_counts<<<cgrid,32*keccak_count_warps,0,c.stream>>>(*p);
    keccak_witness_staged<false><<<grid,32*keccak_stage_warps,0,c.stream>>>(*p);
  } else keccak_witness_staged<true><<<grid,32*keccak_stage_warps,0,c.stream>>>(*p);
  if(p->log>=10)keccak_bitrev<<<dim3(1u<<(p->log-10),1923),256,0,c.stream>>>(p->main,p->log,even_end,odd_begin);
  else keccak_bitrev_small<<<1923,256,0,c.stream>>>(p->main,p->log,even_end,odd_begin);
  return int(cudaPeekAtLastError());
}
