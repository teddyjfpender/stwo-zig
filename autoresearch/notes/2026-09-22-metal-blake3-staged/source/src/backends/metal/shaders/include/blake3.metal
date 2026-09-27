#ifndef STWO_ZIG_BLAKE3_METAL
#define STWO_ZIG_BLAKE3_METAL
#ifndef STWO_ZIG_AMALGAMATED
#include "stwo_zig/blake2s.metal"
#endif
constant uint STWO_BLAKE3_IV[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
inline void stwo_blake3_compress(thread const uint *cv, thread const uint *block,
    ulong counter, uint length, uint flags, thread uint *output) {
    uint v[16], m[16];
    for (uint i=0;i<8;++i) v[i]=cv[i];
    for (uint i=0;i<4;++i) v[8+i]=STWO_BLAKE3_IV[i];
    v[12]=(uint)counter; v[13]=(uint)(counter>>32u); v[14]=length; v[15]=flags;
    for (uint i=0;i<16;++i) m[i]=block[i];
    const uint permutation[16]={2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8};
    for (uint round=0;round<7;++round) {
        STWO_ZIG_BLAKE2S_ROUND(v,m,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
        if (round<6) {
            uint next[16];
            for(uint i=0;i<16;++i) next[i]=m[permutation[i]];
            for(uint i=0;i<16;++i) m[i]=next[i];
        }
    }
    for(uint i=0;i<8;++i) {output[i]=v[i]^v[i+8];output[i+8]=v[i+8]^cv[i];}
}
inline void stwo_zig_blake3_parent(thread const uint *children, thread uint *digest) {
    // Canonical protocol ID plus node domain, encoded little endian.
    const uint prefix[7]={0x6f777473u,0x616c622eu,0x2e33656bu,0x65707865u,0x656d6972u,0x6c61746eu,0x831762eu};
    uint cv[8], block[16], output[16];
    for(uint i=0;i<8;++i) cv[i]=STWO_BLAKE3_IV[i];
    for(uint i=0;i<7;++i) block[i]=prefix[i];
    for(uint i=0;i<9;++i) block[7+i]=children[i];
    stwo_blake3_compress(cv,block,0ul,64u,1u,output);
    for(uint i=0;i<8;++i) cv[i]=output[i];
    for(uint i=0;i<7;++i) block[i]=children[9+i];
    for(uint i=7;i<16;++i) block[i]=0u;
    stwo_blake3_compress(cv,block,0ul,28u,10u,output);
    for(uint i=0;i<8;++i) digest[i]=output[i];
}
// Word-aligned unkeyed BLAKE3, with delayed final-block compression.
// Binary-carry CV stack: BLAKE3 reference implementation, section 5.1.2.
// u32 column_count + seven framing words needs at most 25 subtree slots.
struct StwoBlake3WordState {
    uint cv[8], block[16], stack[25][8];
    uint filled, block_index, chunk_counter, stack_len;
};
inline void stwo_blake3_words_init(thread StwoBlake3WordState &s) {
    for (uint i=0;i<8;++i) s.cv[i]=STWO_BLAKE3_IV[i];
    for (uint i=0;i<16;++i) s.block[i]=0u;
    s.filled=0u; s.block_index=0u; s.chunk_counter=0u; s.stack_len=0u;
}
// Internal BLAKE3 tree node, distinct from the protocol Merkle-node frame.
inline void stwo_blake3_chunk_parent(thread const uint *left,
    thread const uint *right, uint flags, thread uint *output) {
    uint cv[8], block[16];
    for (uint i=0;i<8;++i) {
        cv[i]=STWO_BLAKE3_IV[i]; block[i]=left[i]; block[8+i]=right[i];
    }
    stwo_blake3_compress(cv,block,0ul,64u,4u|flags,output);
}
inline void stwo_blake3_word(thread StwoBlake3WordState &s, uint word) {
    if (s.filled==16u) {
        uint output[16];
        uint flags=(s.block_index==0u ? 1u : 0u) | (s.block_index==15u ? 2u : 0u);
        stwo_blake3_compress(s.cv,s.block,ulong(s.chunk_counter),64u,flags,output);
        if (s.block_index==15u) {
            uint total=++s.chunk_counter;
            while ((total&1u)==0u) {
                --s.stack_len;
                stwo_blake3_chunk_parent(s.stack[s.stack_len],output,0u,output);
                total>>=1u;
            }
            for (uint i=0;i<8;++i) {
                s.stack[s.stack_len][i]=output[i]; s.cv[i]=STWO_BLAKE3_IV[i];
            }
            ++s.stack_len; s.block_index=0u;
        } else {
            for (uint i=0;i<8;++i) s.cv[i]=output[i];
            ++s.block_index;
        }
        s.filled=0u;
        for (uint i=0;i<16;++i) s.block[i]=0u;
    }
    s.block[s.filled++]=word;
}
inline void stwo_blake3_words_finish(thread StwoBlake3WordState &s,
    thread uint *digest) {
    uint output[16];
    uint flags=2u | (s.block_index==0u ? 1u : 0u) | (s.stack_len==0u ? 8u : 0u);
    stwo_blake3_compress(s.cv,s.block,ulong(s.chunk_counter),s.filled*4u,flags,output);
    while (s.stack_len>0u) {
        --s.stack_len;
        stwo_blake3_chunk_parent(s.stack[s.stack_len],output,s.stack_len==0u ? 8u : 0u,output);
    }
    for (uint i=0;i<8;++i) digest[i]=output[i];
}
inline void stwo_blake3_leaf_init(thread StwoBlake3WordState &s) {
    stwo_blake3_words_init(s);
    // Canonical protocol ID + leaf domain (7), followed by LE32 field words.
    const uint prefix[7]={0x6f777473u,0x616c622eu,0x2e33656bu,0x65707865u,0x656d6972u,0x6c61746eu,0x0731762eu};
    for (uint i=0;i<7;++i) stwo_blake3_word(s,prefix[i]);
}
#endif
