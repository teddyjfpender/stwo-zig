// SPDX-License-Identifier: MIT
// Copyright (c) 2022 The Plonky3 Authors
// Pinned parameters: third_party/poseidon2_plonky3/PINNED.json.
// Experimental new-profile numerical substrate; NOT a selected PCS backend.
#pragma once
#include <stdint.h>
namespace stwo { namespace cuda { namespace p2m31 {
static constexpr uint32_t modulus = 2147483647u;
static __device__ __constant__ uint32_t initial[96] = {0x1feaba61u,0x53224454u,0x6bceb9e2u,0x5019f9b4u,0x48726592u,0x2b22d0a8u,0x6151bbf9u,0x2f474b21u,0x2eb5f337u,0x3b645d87u,0x942cef0u,0x65228c52u,0x78ffb30fu,0x4d2837c8u,0xe17ac4fu,0x5546686u,0x46c06ccu,0xb51c3b6u,0x568db763u,0x38b334e4u,0x57f5acf0u,0x19d32611u,0x77d02f4bu,0x6c82e9b8u,0x7148c1b6u,0x8067c75u,0x46d1e8c9u,0x30973b07u,0x20614f3bu,0x5c3ff851u,0x30503329u,0x4972e7ccu,0x2d1d8bcu,0x9d5bfa6u,0x97104c0u,0x7ba49a34u,0x4a07c2fcu,0x24c1ee69u,0x28a6ab41u,0x5d9108a0u,0x3a7851c7u,0x1dd495f9u,0x12b49ff4u,0x7bad5760u,0x5fed64c2u,0x66f5c96cu,0x7eafbd02u,0x39b3593bu,0x4a653b49u,0x75091dc1u,0x56e488e0u,0x1704a355u,0x745e4ff3u,0x392ef16eu,0x31e33fdfu,0x2c28c66u,0x36c3083au,0x3104d1fau,0x5b03cda3u,0x6641e1afu,0x37754b56u,0x396f5af9u,0x1a1a461au,0x688e26f2u,0x6f829784u,0x1bb91d69u,0x5b788016u,0x704aa5c5u,0x181869cu,0x41211e56u,0xce803a0u,0x23bff3a0u,0x17fb7064u,0x47317220u,0x76914b53u,0x219c1905u,0x16655528u,0x4df35544u,0x60808465u,0x3350f833u,0x3bccdc7u,0xa87180au,0x17a99f5u,0x6e945726u,0x15445504u,0x780533b1u,0x3b91bf38u,0x3fc77eb1u,0x4b4d960eu,0x3cd93d2eu,0xea4e976u,0x1d5306ccu,0x3a7ac284u,0xec22934u,0x4d979713u,0x51a41c65u};
static __device__ __constant__ uint32_t final_rc[96] = {0x1c662299u,0x57c955au,0x7ab6c0f2u,0x25a6ad0au,0x75850b58u,0x48fd3793u,0xb4366b1u,0xfdd0d49u,0x7db419f9u,0x49b9cc0fu,0x48949716u,0x29c35890u,0x76445485u,0x1c27d30cu,0x10aa7a3bu,0x30f34fb6u,0x6fe06435u,0x2135ecdu,0x6caaba96u,0x3eb290d0u,0x22fd8d3bu,0x768b1525u,0x5be95814u,0x523d7fe9u,0x55e94cecu,0x47c42e1fu,0x1aa53b5eu,0x2fd1fe7eu,0x59230e91u,0x7472da66u,0x6443f2dfu,0x2d9de19du,0x6f7f6a84u,0x77800430u,0xf014bc8u,0x7bf3d095u,0x26afd318u,0x582561f7u,0x5ee3198cu,0x6acc0000u,0x2f315e26u,0x27cac040u,0x2595081eu,0x5963b7dau,0x7e073565u,0x6cf3f5f1u,0x9f8a3a4u,0xda8ccfeu,0x60be2365u,0x7ed742f5u,0x668b8031u,0x4bb03494u,0x59019333u,0x700e2878u,0x1cc45856u,0x1d1617f7u,0x7b988da6u,0x4eb4936cu,0x78c9f87eu,0x63ce3e94u,0x7178341bu,0x45bc2f86u,0x5b775bcu,0x704b0244u,0x29eed278u,0x47f43032u,0x2127b2e5u,0x1997903fu,0x24b3ce03u,0xc32298cu,0x7d2b6f3au,0x17fcaa81u,0x72f37fefu,0x3028e7a9u,0x5edd4d96u,0x1f96583bu,0x4cd6918au,0x14880f0eu,0x69170359u,0x173cbd33u,0x969e7f4u,0x6e7f23abu,0x6182ea87u,0x4dcb1f5cu,0x585fa113u,0x729cb3b6u,0x1b3a27au,0x1ba173e7u,0x4b33bceau,0x63d93bbbu,0x6b3fbf99u,0x6f17e9d1u,0xc3dd8bau,0xbc1f9a8u,0x64d3f370u,0x465a6a18u};
static __device__ __constant__ uint32_t internal_rc[22] = {0x22776a11u,0x5fa34268u,0x1415528du,0x563fbd14u,0x34f45244u,0x120ea1b6u,0x261368a5u,0x27665ec1u,0x36be2805u,0x345c4784u,0x17efdcc1u,0x393e6530u,0x6da0b4b8u,0x31e5ded3u,0x675b27acu,0xae88c30u,0x577841ccu,0x5fe06decu,0x56b0691au,0x7242de1fu,0x3c377529u,0x339b7523u};

__device__ __forceinline__ uint32_t reduce(uint64_t a) {
  a = (a & modulus) + (a >> 31); a = (a & modulus) + (a >> 31);
  return a >= modulus ? uint32_t(a - modulus) : uint32_t(a);
}
__device__ __forceinline__ uint32_t add(uint32_t a,uint32_t b){return reduce(uint64_t(a)+b);}
__device__ __forceinline__ uint32_t mul(uint32_t a,uint32_t b){return reduce(uint64_t(a)*b);}
__device__ __forceinline__ uint32_t fifth(uint32_t a){const auto q=mul(a,a);return mul(mul(q,q),a);}
__device__ inline void external(uint32_t *s){
  for(uint32_t i=0;i<24;i+=4){
    const auto a=s[i],b=s[i+1],c=s[i+2],d=s[i+3];
    const auto ab=add(a,b),cd=add(c,d),all=add(ab,cd),all_b=add(all,b),all_d=add(all,d);
    s[i+3]=add(all_d,add(a,a));s[i+1]=add(all_b,add(c,c));s[i]=add(all_b,ab);s[i+2]=add(all_d,cd);
  }
  for(uint32_t i=0;i<4;++i){uint64_t sum=0;for(uint32_t j=i;j<24;j+=4)sum+=s[j];
    const auto v=reduce(sum);for(uint32_t j=i;j<24;j+=4)s[j]=add(s[j],v);}
}
__device__ inline void permute(uint32_t *s){
  external(s);
  for(uint32_t r=0;r<4;++r){for(uint32_t i=0;i<24;++i)s[i]=fifth(add(s[i],initial[24*r+i]));external(s);}
  for(uint32_t r=0;r<22;++r){
    s[0]=fifth(add(s[0],internal_rc[r]));uint64_t sum=0;for(uint32_t i=0;i<24;++i)sum+=s[i];
    const auto all=reduce(sum),old0=s[0];s[0]=add(all,old0?modulus-add(old0,old0):0);
    for(uint32_t i=1;i<24;++i)s[i]=add(all,mul(s[i],1u<<(i-1)));
  }
  for(uint32_t r=0;r<4;++r){for(uint32_t i=0;i<24;++i)s[i]=fifth(add(s[i],final_rc[24*r+i]));external(s);}
}
struct Sponge{
  uint32_t state[24],at;
  __device__ explicit Sponge(uint32_t domain):state{},at(0){state[22]=1;state[23]=domain;}
  __device__ void absorb(uint32_t x){state[at]=add(state[at],x);if(++at==12){permute(state);at=0;}}
  __device__ void raw32(uint32_t x){absorb(x&65535);absorb(x>>16);}
  __device__ void raw64(uint64_t x){raw32(uint32_t(x));raw32(uint32_t(x>>32));}
  __device__ void finish(uint32_t *out){state[at]=add(state[at],1);permute(state);for(uint32_t i=0;i<9;++i)out[i]=state[i];}
};
__device__ inline bool canonical(const uint32_t *data,uint64_t n,uint32_t *status){
  for(uint64_t i=0;i<n;++i)if(data[i]>=modulus){atomicOr(status,1u);return false;}return true;
}
// Explicit column-major source layout, row-major 9-word digests.
static __global__ void leaves(const uint32_t *values,uint32_t columns,uint32_t rows,uint32_t *out,uint32_t *status){
  const uint32_t row=blockIdx.x*blockDim.x+threadIdx.x;if(row>=rows)return;
  Sponge s(1);for(uint32_t col=0;col<columns;++col){const auto v=values[uint64_t(col)*rows+row];
    if(v>=modulus){atomicOr(status,1u);return;}s.absorb(v);}s.finish(out+uint64_t(row)*9);
}
static __global__ void parents(const uint32_t *children,uint32_t rows,uint32_t *out,uint32_t *status){
  const uint32_t row=blockIdx.x*blockDim.x+threadIdx.x;if(row>=rows)return;
  const auto src=children+uint64_t(row)*18;if(!canonical(src,18,status))return;
  Sponge s(2);for(uint32_t i=0;i<18;++i)s.absorb(src[i]);s.finish(out+uint64_t(row)*9);
}
// Operation domains exactly match core/channel/poseidon2_m31.zig.
// Inputs and outputs stay on device; one thread owns the ordered transcript.
static __global__ void transcript(const uint32_t *digest,uint32_t domain,const uint32_t *payload,uint32_t count,uint64_t draw,uint32_t *out,uint32_t *status){
  if(blockIdx.x||threadIdx.x)return;
  if(domain<3||domain>6||!canonical(digest,9,status)){atomicOr(status,2u);return;}
  if(domain==6&&count!=0){atomicOr(status,2u);return;}
  if(domain==5&&count!=9){atomicOr(status,2u);return;}
  if(domain!=3&&!canonical(payload,count,status))return;
  Sponge s(domain);for(uint32_t i=0;i<9;++i)s.absorb(digest[i]);
  if(domain==6)s.raw64(draw);else for(uint32_t i=0;i<count;++i){if(domain==3)s.raw32(payload[i]);else s.absorb(payload[i]);}
  s.finish(out);
}
static __global__ void permutations(const uint32_t *in,uint32_t count,uint32_t *out,uint32_t *status){
  const uint32_t row=blockIdx.x*blockDim.x+threadIdx.x;if(row>=count)return;
  const auto src=in+uint64_t(row)*24;if(!canonical(src,24,status))return;
  uint32_t s[24];for(uint32_t i=0;i<24;++i)s[i]=src[i];permute(s);for(uint32_t i=0;i<24;++i)out[uint64_t(row)*24+i]=s[i];
}
}}}
