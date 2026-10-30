// Exact word-aligned BLAKE3 and stwo.blake3.experimental.v1 framing.
// Port of the already qualified Metal implementation; no Blake2 hash alias.
#ifndef STWO_CUDA_BLAKE3_PROTOCOL_CUH
#define STWO_CUDA_BLAKE3_PROTOCOL_CUH
#include <stdint.h>
namespace stwo::cuda::blake3 {
__device__ __forceinline__ uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32u-n)); }
__device__ __forceinline__ void g(uint32_t *v,int a,int b,int c,int d,uint32_t x,uint32_t y) {
 v[a]+=v[b]+x; v[d]=rotr(v[d]^v[a],16); v[c]+=v[d]; v[b]=rotr(v[b]^v[c],12);
 v[a]+=v[b]+y; v[d]=rotr(v[d]^v[a],8); v[c]+=v[d]; v[b]=rotr(v[b]^v[c],7);
}
__device__ __forceinline__ void b3_round(uint32_t *v,const uint32_t *m) {
 g(v,0,4,8,12,m[0],m[1]); g(v,1,5,9,13,m[2],m[3]); g(v,2,6,10,14,m[4],m[5]); g(v,3,7,11,15,m[6],m[7]);
 g(v,0,5,10,15,m[8],m[9]); g(v,1,6,11,12,m[10],m[11]); g(v,2,7,8,13,m[12],m[13]); g(v,3,4,9,14,m[14],m[15]);
}
static __device__ __constant__ uint32_t STWO_BLAKE3_IV[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
__device__ __forceinline__ void stwo_blake3_compress(const uint32_t *cv, const uint32_t *block,
    uint64_t counter, uint32_t length, uint32_t flags, uint32_t *output) {
    uint32_t v[16], m[16];
    for (uint32_t i=0;i<8;++i) v[i]=cv[i];
    for (uint32_t i=0;i<4;++i) v[8+i]=STWO_BLAKE3_IV[i];
    v[12]=(uint32_t)counter; v[13]=(uint32_t)(counter>>32u); v[14]=length; v[15]=flags;
    for (uint32_t i=0;i<16;++i) m[i]=block[i];
    const uint32_t permutation[16]={2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8};
    for (uint32_t round=0;round<7;++round) {
        b3_round(v,m);
        if (round<6) {
            uint32_t next[16];
            for(uint32_t i=0;i<16;++i) next[i]=m[permutation[i]];
            for(uint32_t i=0;i<16;++i) m[i]=next[i];
        }
    }
    for(uint32_t i=0;i<8;++i) {output[i]=v[i]^v[i+8];output[i+8]=v[i+8]^cv[i];}
}
__device__ __forceinline__ void stwo_zig_blake3_parent(const uint32_t *children, uint32_t *digest) {
    // Canonical protocol ID plus node domain, encoded little endian.
    const uint32_t prefix[7]={0x6f777473u,0x616c622eu,0x2e33656bu,0x65707865u,0x656d6972u,0x6c61746eu,0x831762eu};
    uint32_t cv[8], block[16], output[16];
    for(uint32_t i=0;i<8;++i) cv[i]=STWO_BLAKE3_IV[i];
    for(uint32_t i=0;i<7;++i) block[i]=prefix[i];
    for(uint32_t i=0;i<9;++i) block[7+i]=children[i];
    stwo_blake3_compress(cv,block,0ul,64u,1u,output);
    for(uint32_t i=0;i<8;++i) cv[i]=output[i];
    for(uint32_t i=0;i<7;++i) block[i]=children[9+i];
    for(uint32_t i=7;i<16;++i) block[i]=0u;
    stwo_blake3_compress(cv,block,0ul,28u,10u,output);
    for(uint32_t i=0;i<8;++i) digest[i]=output[i];
}
// Word-aligned unkeyed BLAKE3, with delayed final-block compression.
// Binary-carry CV stack: BLAKE3 reference implementation, section 5.1.2.
// u32 column_count + seven framing words needs at most 25 subtree slots.
struct StwoBlake3WordState {
    uint32_t cv[8], block[16], stack[25][8];
    uint32_t filled, block_index, chunk_counter, stack_len;
};
__device__ __forceinline__ void stwo_blake3_words_init(StwoBlake3WordState &s) {
    for (uint32_t i=0;i<8;++i) s.cv[i]=STWO_BLAKE3_IV[i];
    for (uint32_t i=0;i<16;++i) s.block[i]=0u;
    s.filled=0u; s.block_index=0u; s.chunk_counter=0u; s.stack_len=0u;
}
// Internal BLAKE3 tree node, distinct from the protocol Merkle-node frame.
__device__ __forceinline__ void stwo_blake3_chunk_parent(const uint32_t *left,
    const uint32_t *right, uint32_t flags, uint32_t *output) {
    uint32_t cv[8], block[16];
    for (uint32_t i=0;i<8;++i) {
        cv[i]=STWO_BLAKE3_IV[i]; block[i]=left[i]; block[8+i]=right[i];
    }
    stwo_blake3_compress(cv,block,0ul,64u,4u|flags,output);
}
__device__ __forceinline__ void stwo_blake3_word(StwoBlake3WordState &s, uint32_t word) {
    if (s.filled==16u) {
        uint32_t output[16];
        uint32_t flags=(s.block_index==0u ? 1u : 0u) | (s.block_index==15u ? 2u : 0u);
        stwo_blake3_compress(s.cv,s.block,uint64_t(s.chunk_counter),64u,flags,output);
        if (s.block_index==15u) {
            uint32_t total=++s.chunk_counter;
            while ((total&1u)==0u) {
                --s.stack_len;
                stwo_blake3_chunk_parent(s.stack[s.stack_len],output,0u,output);
                total>>=1u;
            }
            for (uint32_t i=0;i<8;++i) {
                s.stack[s.stack_len][i]=output[i]; s.cv[i]=STWO_BLAKE3_IV[i];
            }
            ++s.stack_len; s.block_index=0u;
        } else {
            for (uint32_t i=0;i<8;++i) s.cv[i]=output[i];
            ++s.block_index;
        }
        s.filled=0u;
        for (uint32_t i=0;i<16;++i) s.block[i]=0u;
    }
    s.block[s.filled++]=word;
}
__device__ __forceinline__ void stwo_blake3_words_finish(StwoBlake3WordState &s,
    uint32_t *digest) {
    uint32_t output[16];
    uint32_t flags=2u | (s.block_index==0u ? 1u : 0u) | (s.stack_len==0u ? 8u : 0u);
    stwo_blake3_compress(s.cv,s.block,uint64_t(s.chunk_counter),s.filled*4u,flags,output);
    while (s.stack_len>0u) {
        --s.stack_len;
        stwo_blake3_chunk_parent(s.stack[s.stack_len],output,s.stack_len==0u ? 8u : 0u,output);
    }
    for (uint32_t i=0;i<8;++i) digest[i]=output[i];
}
__device__ __forceinline__ void stwo_blake3_frame_init(StwoBlake3WordState &s, uint32_t domain) {
    stwo_blake3_words_init(s);
    // Canonical protocol ID + leaf domain (7), followed by LE32 field words.
    const uint32_t prefix[7]={0x6f777473u,0x616c622eu,0x2e33656bu,0x65707865u,0x656d6972u,0x6c61746eu,0x0031762eu | (domain<<24u)};
    for (uint32_t i=0;i<7;++i) stwo_blake3_word(s,prefix[i]);
}
__device__ __forceinline__ void stwo_blake3_leaf_init(StwoBlake3WordState &s) {
    stwo_blake3_frame_init(s,7u);
}

struct Hash { uint32_t words[8]; };
using State = StwoBlake3WordState;
static_assert(sizeof(State)==912);
struct Channel { uint32_t digest[8], counter[2], error; };
static_assert(sizeof(Channel)==44);
} // namespace stwo::cuda::blake3
#endif
