#include "blake2s.cuh"
#include "blake2s_progressive_scalar.cuh"
#include "n2b_terminal.cuh"
#include <cstdio>
#include <cstdlib>
#include "poly_utils.cuh"
#include "utils.cuh"

__device__ __constant__ uint32_t blake2s_IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

__device__ __constant__ uint8_t blake2s_sigma[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 }
};


#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#define G(r,i,a,b,c,d) \
    do { \
        a = a + b + m[blake2s_sigma[r][2*i+0]]; \
        d = ROTR32(d ^ a, 16); \
        c = c + d; \
        b = ROTR32(b ^ c, 12); \
        a = a + b + m[blake2s_sigma[r][2*i+1]]; \
        d = ROTR32(d ^ a, 8); \
        c = c + d; \
        b = ROTR32(b ^ c, 7); \
    } while(0)

typedef struct {
    uint32_t h[8];      // hash state
    uint32_t t;         // total bytes so far
    uint8_t  buf[64];   // buffer
    size_t   buflen;    // buffer usage
} Blake2sState;

__device__ void blake2s_compress(
    Blake2sState* S,
    const uint8_t block[64],
    uint32_t t,         // total bytes so far
    uint32_t lastblock  // 0 for normal, 0xFFFFFFFF for last block
) {
    uint32_t m[16];
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        m[i] =  ((uint32_t)block[4*i+0]      ) |
                ((uint32_t)block[4*i+1] << 8 ) |
                ((uint32_t)block[4*i+2] << 16) |
                ((uint32_t)block[4*i+3] << 24);
    }

    uint32_t v[16];
    #pragma unroll
    for (int i = 0; i < 8; i++) v[i] = S->h[i];
    #pragma unroll
    for (int i = 0; i < 8; i++) v[i+8] = blake2s_IV[i];

    v[12] ^= t;         // low 32 bits of offset
    v[13] ^= 0;         // high 32 bits (always 0 for <2^32 bytes)
    v[14] ^= lastblock; // 0xFFFFFFFF for last block

    // 10 rounds
    #pragma unroll
    for (int r = 0; r < 10; r++) {
        G(r,0,v[0],v[4],v[8],v[12]);
        G(r,1,v[1],v[5],v[9],v[13]);
        G(r,2,v[2],v[6],v[10],v[14]);
        G(r,3,v[3],v[7],v[11],v[15]);
        G(r,4,v[0],v[5],v[10],v[15]);
        G(r,5,v[1],v[6],v[11],v[12]);
        G(r,6,v[2],v[7],v[8],v[13]);
        G(r,7,v[3],v[4],v[9],v[14]);
    }

    #pragma unroll
    for (int i = 0; i < 8; i++)
        S->h[i] ^= v[i] ^ v[i+8];
}


__device__ void blake2s_init(Blake2sState* S) {
    const uint32_t IV[8] = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    };
    S->h[0] = IV[0] ^ 0x01010020; // digest len = 32
    S->h[1] = IV[1];
    S->h[2] = IV[2];
    S->h[3] = IV[3];
    S->h[4] = IV[4];
    S->h[5] = IV[5];
    S->h[6] = IV[6];
    S->h[7] = IV[7];
    S->t = 0;
    S->buflen = 0;
}
__device__ void blake2s_update(Blake2sState* S, const uint8_t* in, size_t inlen) {
    size_t left = S->buflen;
    size_t fill = 64 - left;

    if (inlen > fill) {
        memcpy(S->buf + left, in, fill);
        S->t += 64;
        blake2s_compress(S, S->buf, S->t, 0);
        in += fill;
        inlen -= fill;
        while (inlen > 64) {
            S->t += 64;
            blake2s_compress(S, in, S->t, 0);
            in += 64;
            inlen -= 64;
        }
        left = 0;
    }
    memcpy(S->buf + left, in, inlen);
    S->buflen = left + inlen;
}

__device__ void blake2s_finalize(Blake2sState* S, Blake2sHash* out) {
    S->t += S->buflen;
    memset(S->buf + S->buflen, 0, 64 - S->buflen); // pad
    blake2s_compress(S, S->buf, S->t, 0xFFFFFFFF); // lastblock = 0xFFFFFFFF
    for (int i = 0; i < 8; i++) {
        out->s[i] = S->h[i];
    }
}

// Clonable progressive lane. Counter and pending length are canonical-prefix
// launch scalars; only row-varying chaining and pending words persist in HBM.
__host__ __device__ constexpr uint32_t progressive_pending_words(
    uint32_t absorbed_columns) {
    return absorbed_columns == 0 ? 0 : ((absorbed_columns - 1) & 15u) + 1;
}
static_assert(progressive_pending_words(0) == 0, "empty prefix must be empty");
static_assert(progressive_pending_words(1) == 1, "one word must remain pending");
static_assert(progressive_pending_words(16) == 16, "lazy full block must remain pending");
static_assert(progressive_pending_words(17) == 1, "next block must start at one word");
static_assert(progressive_pending_words(0xffffffffu) == 15,
              "maximum canonical prefix must not overflow");

#define PROGRESSIVE_LOAD_STATE(S)       \
    uint32_t h0 = (S).h[0];             \
    uint32_t h1 = (S).h[1];             \
    uint32_t h2 = (S).h[2];             \
    uint32_t h3 = (S).h[3];             \
    uint32_t h4 = (S).h[4];             \
    uint32_t h5 = (S).h[5];             \
    uint32_t h6 = (S).h[6];             \
    uint32_t h7 = (S).h[7];             \
    uint32_t p0 = (S).pending[0];        \
    uint32_t p1 = (S).pending[1];        \
    uint32_t p2 = (S).pending[2];        \
    uint32_t p3 = (S).pending[3];        \
    uint32_t p4 = (S).pending[4];        \
    uint32_t p5 = (S).pending[5];        \
    uint32_t p6 = (S).pending[6];        \
    uint32_t p7 = (S).pending[7];        \
    uint32_t p8 = (S).pending[8];        \
    uint32_t p9 = (S).pending[9];        \
    uint32_t p10 = (S).pending[10];      \
    uint32_t p11 = (S).pending[11];      \
    uint32_t p12 = (S).pending[12];      \
    uint32_t p13 = (S).pending[13];      \
    uint32_t p14 = (S).pending[14];      \
    uint32_t p15 = (S).pending[15]

#define PROGRESSIVE_COMPRESS(COUNTER, LAST)                                  \
    progressive_blake2s_compress_scalar(                                     \
        h0,h1,h2,h3,h4,h5,h6,h7,                                             \
        p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,              \
        COUNTER, LAST)

#define PROGRESSIVE_STORE_STATE(S)    \
    (S).h[0] = h0;                    \
    (S).h[1] = h1;                    \
    (S).h[2] = h2;                    \
    (S).h[3] = h3;                    \
    (S).h[4] = h4;                    \
    (S).h[5] = h5;                    \
    (S).h[6] = h6;                    \
    (S).h[7] = h7;                    \
    (S).pending[0] = p0;              \
    (S).pending[1] = p1;              \
    (S).pending[2] = p2;              \
    (S).pending[3] = p3;              \
    (S).pending[4] = p4;              \
    (S).pending[5] = p5;              \
    (S).pending[6] = p6;              \
    (S).pending[7] = p7;              \
    (S).pending[8] = p8;              \
    (S).pending[9] = p9;              \
    (S).pending[10] = p10;            \
    (S).pending[11] = p11;            \
    (S).pending[12] = p12;            \
    (S).pending[13] = p13;            \
    (S).pending[14] = p14;            \
    (S).pending[15] = p15

__global__ void progressive_leaf_init_in_gpu(
    uint32_t size, ProgressiveBlake2sState *states) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= size) return;
    ProgressiveBlake2sState state = {};
    state.h[0] = 0x6A09E667 ^ 0x01010020;
    state.h[1] = 0xBB67AE85;
    state.h[2] = 0x3C6EF372;
    state.h[3] = 0xA54FF53A;
    state.h[4] = 0x510E527F;
    state.h[5] = 0x9B05688C;
    state.h[6] = 0x1F83D9AB;
    state.h[7] = 0x5BE0CD19;
    states[row] = state;
}

__global__ void progressive_leaf_absorb_in_gpu(
    uint32_t size,
    uint32_t number_of_columns,
    uint32_t absorbed_columns_before,
    uint32_t **columns,
    ProgressiveBlake2sState *states) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= size) return;
    ProgressiveBlake2sState &state = states[row];
    PROGRESSIVE_LOAD_STATE(state);
    uint32_t pending_words = progressive_pending_words(absorbed_columns_before);
    uint64_t compressed_bytes =
        static_cast<uint64_t>(absorbed_columns_before - pending_words) * 4;
    for (uint32_t column = 0; column < number_of_columns; ++column) {
        if (pending_words == 16) {
            compressed_bytes += 64;
            PROGRESSIVE_COMPRESS(compressed_bytes, 0);
            pending_words = 0;
        }
        uint32_t word = columns[column][row];
        switch (pending_words++) {
            case 0: p0 = word; break;
            case 1: p1 = word; break;
            case 2: p2 = word; break;
            case 3: p3 = word; break;
            case 4: p4 = word; break;
            case 5: p5 = word; break;
            case 6: p6 = word; break;
            case 7: p7 = word; break;
            case 8: p8 = word; break;
            case 9: p9 = word; break;
            case 10: p10 = word; break;
            case 11: p11 = word; break;
            case 12: p12 = word; break;
            case 13: p13 = word; break;
            case 14: p14 = word; break;
            default: p15 = word; break;
        }
    }
    PROGRESSIVE_STORE_STATE(state);
}

__global__ void progressive_leaf_expand_in_gpu(
    uint32_t to_size,
    uint32_t log_ratio,
    const ProgressiveBlake2sState *states_in,
    ProgressiveBlake2sState *states_out) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= to_size) return;
    uint32_t parent = ((row >> (log_ratio + 1)) << 1) | (row & 1);
    states_out[row] = states_in[parent];
}

__global__ void progressive_leaf_finalize_in_gpu(
    uint32_t size,
    uint32_t absorbed_columns,
    const ProgressiveBlake2sState *states,
    Blake2sHash *result) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= size) return;
    const ProgressiveBlake2sState &state = states[row];
    PROGRESSIVE_LOAD_STATE(state);
    uint32_t pending_words = progressive_pending_words(absorbed_columns);
    if (pending_words < 1) p0 = 0;
    if (pending_words < 2) p1 = 0;
    if (pending_words < 3) p2 = 0;
    if (pending_words < 4) p3 = 0;
    if (pending_words < 5) p4 = 0;
    if (pending_words < 6) p5 = 0;
    if (pending_words < 7) p6 = 0;
    if (pending_words < 8) p7 = 0;
    if (pending_words < 9) p8 = 0;
    if (pending_words < 10) p9 = 0;
    if (pending_words < 11) p10 = 0;
    if (pending_words < 12) p11 = 0;
    if (pending_words < 13) p12 = 0;
    if (pending_words < 14) p13 = 0;
    if (pending_words < 15) p14 = 0;
    if (pending_words < 16) p15 = 0;
    PROGRESSIVE_COMPRESS(
        static_cast<uint64_t>(absorbed_columns) * 4, 0xFFFFFFFFu);
    result[row].s[0] = h0;
    result[row].s[1] = h1;
    result[row].s[2] = h2;
    result[row].s[3] = h3;
    result[row].s[4] = h4;
    result[row].s[5] = h5;
    result[row].s[6] = h6;
    result[row].s[7] = h7;
}

#undef PROGRESSIVE_STORE_STATE
#undef PROGRESSIVE_COMPRESS
#undef PROGRESSIVE_LOAD_STATE

// Kept in this translation unit deliberately: transcript hashing must share
// the exact compression implementation used by the ordinary Blake2s Merkle
// channel.  Relocatable device code resolves this symbol for
// device_transcript.cu at device-link time.
__device__ void stwo_blake2s_hash2_device(
    const uint8_t *first,
    size_t first_len,
    const uint8_t *second,
    size_t second_len,
    Blake2sHash *out) {
    Blake2sState state;
    blake2s_init(&state);
    if (first_len != 0) {
        blake2s_update(&state, first, first_len);
    }
    if (second_len != 0) {
        blake2s_update(&state, second, second_len);
    }
    blake2s_finalize(&state, out);
}

// ---------------------------------------------------------------------------
// WORD-BLOCK blake2s (the commit-path fast lane). The tree hashes M31 words
// and 32-byte child digests — both are sequences of little-endian u32s, which
// ARE blake2s message words: the byte-buffered state machine above (64-byte
// local buffer, per-4-byte memcpy, byte->word re-decode every compress) is
// pure overhead for them. These helpers keep h[8] and m[16] in REGISTERS
// (callers must index m with compile-time constants — unrolled 16-word
// groups), producing BIT-IDENTICAL digests: same word stream, same byte
// counts, same lastblock flag.
// ---------------------------------------------------------------------------

__device__ __forceinline__ void blake2s_compress_words(
    uint32_t h[8],
    const uint32_t m[16],
    uint32_t t,         // total bytes so far
    uint32_t lastblock  // 0 for normal, 0xFFFFFFFF for last block
) {
    uint32_t v[16];
    #pragma unroll
    for (int i = 0; i < 8; i++) v[i] = h[i];
    #pragma unroll
    for (int i = 0; i < 8; i++) v[i+8] = blake2s_IV[i];

    v[12] ^= t;
    v[14] ^= lastblock;

    #pragma unroll
    for (int r = 0; r < 10; r++) {
        G(r,0,v[0],v[4],v[8],v[12]);
        G(r,1,v[1],v[5],v[9],v[13]);
        G(r,2,v[2],v[6],v[10],v[14]);
        G(r,3,v[3],v[7],v[11],v[15]);
        G(r,4,v[0],v[5],v[10],v[15]);
        G(r,5,v[1],v[6],v[11],v[12]);
        G(r,6,v[2],v[7],v[8],v[13]);
        G(r,7,v[3],v[4],v[9],v[14]);
    }

    #pragma unroll
    for (int i = 0; i < 8; i++)
        h[i] ^= v[i] ^ v[i+8];
}

__device__ __forceinline__ void blake2s_init_words(uint32_t h[8]) {
    #pragma unroll
    for (int i = 0; i < 8; i++) h[i] = blake2s_IV[i];
    h[0] ^= 0x01010020; // digest len = 32, fanout/depth 1 — same as blake2s_init
}

// ---------------------------------------------------------------------------
// ILP2 compression (Step 3.2 leaf-hash ILP lane): TWO independent blake2s
// streams interleaved instruction-by-instruction. Each G step's dependency
// chain is ~6 sequential ops; interleaving stream a and stream b gives the
// scheduler two independent chains so ALU latency is hidden by ILP instead of
// occupancy (the kernels sit at 255 regs / 12.5% occupancy — occupancy hints
// measured FLAT, see blake2s.cuh). Per-stream math is IDENTICAL to
// blake2s_compress_words (same sigma table, same rotation amounts — rotates
// spelled as __funnelshift_r, the SASS the ROTR32 macro also lowers to), so
// digests are bit-identical by construction. Register budget: 2x16 v + 2x16 m
// staging + 2x8 h ~= 80 u32 before scheduling.
// ---------------------------------------------------------------------------

#define ROTR32_FS(x, n) __funnelshift_r((x), (x), (n))

#define G2(r,i,va,vb,ma,mb,A,B,C,D) \
    do { \
        va[A] = va[A] + va[B] + ma[blake2s_sigma[r][2*i+0]]; \
        vb[A] = vb[A] + vb[B] + mb[blake2s_sigma[r][2*i+0]]; \
        va[D] = ROTR32_FS(va[D] ^ va[A], 16); \
        vb[D] = ROTR32_FS(vb[D] ^ vb[A], 16); \
        va[C] = va[C] + va[D]; \
        vb[C] = vb[C] + vb[D]; \
        va[B] = ROTR32_FS(va[B] ^ va[C], 12); \
        vb[B] = ROTR32_FS(vb[B] ^ vb[C], 12); \
        va[A] = va[A] + va[B] + ma[blake2s_sigma[r][2*i+1]]; \
        vb[A] = vb[A] + vb[B] + mb[blake2s_sigma[r][2*i+1]]; \
        va[D] = ROTR32_FS(va[D] ^ va[A], 8); \
        vb[D] = ROTR32_FS(vb[D] ^ vb[A], 8); \
        va[C] = va[C] + va[D]; \
        vb[C] = vb[C] + vb[D]; \
        va[B] = ROTR32_FS(va[B] ^ va[C], 7); \
        vb[B] = ROTR32_FS(vb[B] ^ vb[C], 7); \
    } while (0)

__device__ __forceinline__ void blake2s_compress_words_x2(
    uint32_t ha[8],
    uint32_t hb[8],
    const uint32_t ma[16],
    const uint32_t mb[16],
    uint32_t t,         // total bytes so far (both streams share the column stream)
    uint32_t lastblock  // 0 for normal, 0xFFFFFFFF for last block
) {
    uint32_t va[16], vb[16];
    #pragma unroll
    for (int i = 0; i < 8; i++) { va[i] = ha[i]; vb[i] = hb[i]; }
    #pragma unroll
    for (int i = 0; i < 8; i++) { va[i+8] = blake2s_IV[i]; vb[i+8] = blake2s_IV[i]; }

    va[12] ^= t;
    vb[12] ^= t;
    va[14] ^= lastblock;
    vb[14] ^= lastblock;

    #pragma unroll
    for (int r = 0; r < 10; r++) {
        G2(r,0,va,vb,ma,mb,0,4,8,12);
        G2(r,1,va,vb,ma,mb,1,5,9,13);
        G2(r,2,va,vb,ma,mb,2,6,10,14);
        G2(r,3,va,vb,ma,mb,3,7,11,15);
        G2(r,4,va,vb,ma,mb,0,5,10,15);
        G2(r,5,va,vb,ma,mb,1,6,11,12);
        G2(r,6,va,vb,ma,mb,2,7,8,13);
        G2(r,7,va,vb,ma,mb,3,4,9,14);
    }

    #pragma unroll
    for (int i = 0; i < 8; i++) {
        ha[i] ^= va[i] ^ va[i+8];
        hb[i] ^= vb[i] ^ vb[i+8];
    }
}

__device__ void stwo_blake2s_compress_leaf_block_device(
    Blake2sHash *state,
    const uint32_t message[16],
    uint32_t total_bytes,
    uint32_t lastblock
) {
    uint32_t h[8];
    #pragma unroll
    for (int i = 0; i < 8; ++i) h[i] = state->s[i];
    blake2s_compress_words(h, message, total_bytes, lastblock);
    #pragma unroll
    for (int i = 0; i < 8; ++i) state->s[i] = h[i];
}

// Hash a row's column words: unrolled 16-word groups (m stays in registers),
// zero-padded tail block with the exact byte count + lastblock flag.
__device__ __forceinline__ void blake2s_hash_column_words(
    uint32_t h[8],
    uint32_t t,                 // bytes already consumed (0, or 64 after children)
    uint32_t **data,
    uint32_t number_of_columns,
    uint32_t index,
    Blake2sHash *out
) {
    uint32_t m[16];
    uint32_t col = 0;
    // Lazy like blake2s_update (`inlen > fill`): a block is compressed with
    // last=0 only when more words follow it, so the block holding the final
    // word is the one flagged last — also when the stream is an exact
    // multiple of 16 words (rem == 16 below, never a zero-padded extra block).
    while (col + 16 < number_of_columns) {
        #pragma unroll
        for (int k = 0; k < 16; k++) m[k] = data[col + k][index];
        t += 64;
        blake2s_compress_words(h, m, t, 0);
        col += 16;
    }
    uint32_t rem = number_of_columns - col;
    #pragma unroll
    for (int k = 0; k < 16; k++) {
        m[k] = (k < rem) ? data[col + k][index] : 0;
    }
    t += 4 * rem;
    blake2s_compress_words(h, m, t, 0xFFFFFFFF);
    #pragma unroll
    for (int i = 0; i < 8; i++) out->s[i] = h[i];
}




__global__ void __launch_bounds__(BLOCK_SIZE) commit_on_first_layer_in_gpu(
    uint32_t size,
    uint32_t number_of_columns,
    uint32_t **data,
    Blake2sHash *result
) {
    uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= size) return;
    // Word-block lane: bit-identical digests, no byte buffer (see
    // blake2s_hash_column_words).
    uint32_t h[8];
    blake2s_init_words(h);
    blake2s_hash_column_words(h, 0, data, number_of_columns, index, &result[index]);
}

__device__ __forceinline__ uint32_t lifted_column_index(
    uint32_t lifted_index,
    uint32_t log_ratio
) {
    if (log_ratio == 0) {
        return lifted_index;
    }
    return ((lifted_index >> (log_ratio + 1)) << 1) + (lifted_index & 1);
}

__global__ void __launch_bounds__(BLOCK_SIZE, STWO_LEAF_MIN_BLOCKS) commit_on_first_layer_lifted_in_gpu(
    uint32_t size,
    uint32_t number_of_columns,
    uint32_t **data,
    const uint32_t *column_log_sizes,
    uint32_t lifting_log_size,
    Blake2sHash *result
) {
    uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= size) return;

    // Word-block lane with per-column lifted source indices.
    uint32_t h[8];
    blake2s_init_words(h);
    uint32_t m[16];
    uint32_t t = 0;
    uint32_t col = 0;
    // Lazy full-block loop — see blake2s_hash_column_words.
    while (col + 16 < number_of_columns) {
        #pragma unroll
        for (int k = 0; k < 16; k++) {
            uint32_t log_ratio = lifting_log_size - column_log_sizes[col + k];
            m[k] = data[col + k][lifted_column_index(index, log_ratio)];
        }
        t += 64;
        blake2s_compress_words(h, m, t, 0);
        col += 16;
    }
    uint32_t rem = number_of_columns - col;
    #pragma unroll
    for (int k = 0; k < 16; k++) {
        if (k < rem) {
            uint32_t log_ratio = lifting_log_size - column_log_sizes[col + k];
            m[k] = data[col + k][lifted_column_index(index, log_ratio)];
        } else {
            m[k] = 0;
        }
    }
    t += 4 * rem;
    blake2s_compress_words(h, m, t, 0xFFFFFFFF);
    #pragma unroll
    for (int i = 0; i < 8; i++) result[index].s[i] = h[i];
}

// ---------------------------------------------------------------------------
// STREAMING leaf commit (VRAM diet): the lifted first-layer hash split into
// init / update-group / finalize, so the caller can LDE the base columns one
// GROUP at a time — feed each group into every leaf's running blake2s state,
// then free the group — instead of holding ALL LDE'd columns resident. Peak
// drops from all-columns to one-group + the h[8]-per-leaf state.
//
// BYTE-IDENTICAL to commit_on_first_layer_lifted_in_gpu by construction: the
// word stream per leaf is the same sorted-column / lifted-index sequence, and
// the block boundaries match the lazy loop above. Non-final groups carry a
// column count that is a MULTIPLE OF 16 (whole 64-byte blocks, last=0); the
// cross-group state is exactly h[8] plus the byte count t = 4*(cols so far),
// so no partial-word carry is needed at group boundaries. The finalize step
// compresses the trailing [0,rem) block (rem in 1..=16) with the last flag —
// identical to the reference kernel's tail. `state` holds h[8] per leaf and is
// updated in place; finalize writes the digest back into the same buffer.
// ---------------------------------------------------------------------------
__global__ void __launch_bounds__(BLOCK_SIZE) stream_leaf_init_in_gpu(
    uint32_t size,
    Blake2sHash *state
) {
    uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= size) return;
    uint32_t h[8];
    blake2s_init_words(h);
    #pragma unroll
    for (int i = 0; i < 8; i++) state[index].s[i] = h[i];
}

__global__ void __launch_bounds__(BLOCK_SIZE, STWO_LEAF_MIN_BLOCKS) stream_leaf_update_in_gpu(
    uint32_t size,
    uint32_t group_n_cols,          // MULTIPLE OF 16 (whole blocks, last=0)
    uint32_t **group_data,
    const uint32_t *group_col_log_sizes,
    uint32_t lifting_log_size,
    uint32_t cols_done,             // columns compressed in prior groups
    Blake2sHash *state
) {
    uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= size) return;
    uint32_t h[8];
    #pragma unroll
    for (int i = 0; i < 8; i++) h[i] = state[index].s[i];
    uint32_t m[16];
    uint32_t t = 4u * cols_done;    // bytes hashed so far (4 per M31 word)
    uint32_t col = 0;
    while (col + 16 <= group_n_cols) {
        #pragma unroll
        for (int k = 0; k < 16; k++) {
            uint32_t log_ratio = lifting_log_size - group_col_log_sizes[col + k];
            m[k] = group_data[col + k][lifted_column_index(index, log_ratio)];
        }
        t += 64;
        blake2s_compress_words(h, m, t, 0);
        col += 16;
    }
    #pragma unroll
    for (int i = 0; i < 8; i++) state[index].s[i] = h[i];
}

// ILP2 leaf-update variant (opt-in: STWO_CUDA_BLAKE2S_LEAF_ILP=1 on the Rust
// launch sites; default OFF). One thread owns TWO ADJACENT rows (2*tid,
// 2*tid+1) and drives both blake2s streams through the interleaved
// blake2s_compress_words_x2, doubling the independent instruction chains per
// thread. The per-row word stream, block boundaries, and byte counts are
// EXACTLY stream_leaf_update_in_gpu's — byte-identical digests. Grid HALVES:
// blocks = ceil(ceil(size/2) / BLOCK_SIZE) (see number_of_ilp2_blocks_for; the
// Rust mirror + unit tests live in backend-cuda/src/backend/blake2s.rs). Odd
// row counts: the final unpaired row runs the scalar compress, byte-identical.
// The adjacent rows' lifted indices are consecutive words of every column
// (lifted_column_index maps 2p -> base, 2p+1 -> base+1), so the paired loads
// stay contiguous.
__global__ void __launch_bounds__(BLOCK_SIZE, STWO_LEAF_MIN_BLOCKS) stream_leaf_update_ilp2_in_gpu(
    uint32_t size,
    uint32_t group_n_cols,          // MULTIPLE OF 16 (whole blocks, last=0)
    uint32_t **group_data,
    const uint32_t *group_col_log_sizes,
    uint32_t lifting_log_size,
    uint32_t cols_done,             // columns compressed in prior groups
    Blake2sHash *state
) {
    const uint32_t pair = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t row0 = 2 * pair;
    if (row0 >= size) return;
    const uint32_t row1 = row0 + 1;

    if (row1 < size) {
        uint32_t ha[8], hb[8];
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            ha[i] = state[row0].s[i];
            hb[i] = state[row1].s[i];
        }
        uint32_t ma[16], mb[16];
        uint32_t t = 4u * cols_done;    // bytes hashed so far (4 per M31 word)
        uint32_t col = 0;
        while (col + 16 <= group_n_cols) {
            #pragma unroll
            for (int k = 0; k < 16; k++) {
                const uint32_t log_ratio =
                    lifting_log_size - group_col_log_sizes[col + k];
                const uint32_t *column = group_data[col + k];
                ma[k] = column[lifted_column_index(row0, log_ratio)];
                mb[k] = column[lifted_column_index(row1, log_ratio)];
            }
            t += 64;
            blake2s_compress_words_x2(ha, hb, ma, mb, t, 0);
            col += 16;
        }
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            state[row0].s[i] = ha[i];
            state[row1].s[i] = hb[i];
        }
    } else {
        // Odd row-count tail: the single remaining row takes the scalar
        // stream — the exact stream_leaf_update_in_gpu body for one index.
        uint32_t h[8];
        #pragma unroll
        for (int i = 0; i < 8; i++) h[i] = state[row0].s[i];
        uint32_t m[16];
        uint32_t t = 4u * cols_done;
        uint32_t col = 0;
        while (col + 16 <= group_n_cols) {
            #pragma unroll
            for (int k = 0; k < 16; k++) {
                const uint32_t log_ratio =
                    lifting_log_size - group_col_log_sizes[col + k];
                m[k] = group_data[col + k][lifted_column_index(row0, log_ratio)];
            }
            t += 64;
            blake2s_compress_words(h, m, t, 0);
            col += 16;
        }
        #pragma unroll
        for (int i = 0; i < 8; i++) state[row0].s[i] = h[i];
    }
}

__global__ void __launch_bounds__(BLOCK_SIZE) stream_leaf_finalize_in_gpu(
    uint32_t size,
    uint32_t rem_cols,              // final block width in 1..=16
    uint32_t **final_data,
    const uint32_t *final_col_log_sizes,
    uint32_t lifting_log_size,
    uint32_t cols_done,             // columns compressed before the final block
    Blake2sHash *result             // in/out: carries h[8], receives the digest
) {
    uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= size) return;
    uint32_t h[8];
    #pragma unroll
    for (int i = 0; i < 8; i++) h[i] = result[index].s[i];
    uint32_t m[16];
    #pragma unroll
    for (int k = 0; k < 16; k++) {
        if (k < rem_cols) {
            uint32_t log_ratio = lifting_log_size - final_col_log_sizes[k];
            m[k] = final_data[k][lifted_column_index(index, log_ratio)];
        } else {
            m[k] = 0;
        }
    }
    uint32_t t = 4u * cols_done + 4u * rem_cols;
    blake2s_compress_words(h, m, t, 0xFFFFFFFF);
    #pragma unroll
    for (int i = 0; i < 8; i++) result[index].s[i] = h[i];
}

// `prefinal` is the in-place N2B state after stage log_n-1. Reproduce exactly
// the ordinary final circle butterfly for one bit-reversed evaluation word.
__device__ __forceinline__ uint32_t n2b_final_value(
    const uint32_t *prefinal,
    uint32_t evaluation_index,
    uint32_t evaluation_log_size,
    uint32_t *twiddles,
    uint32_t twiddle_words
) {
    const uint32_t half_domain = 1u << (evaluation_log_size - 1);
    const uint32_t pair = evaluation_index >> 1;
    const StwoN2bFinalPair values = stwo_n2b_final_pair(
        prefinal, pair, half_domain, twiddles, twiddle_words);
    return (evaluation_index & 1) == 0 ? values.even : values.odd;
}

// Hash-from-tile fusion. One bounded block owns 256 lifted leaves and performs
// the producer's final butterfly immediately before Blake2s consumes each raw
// M31 word. Group boundaries and 16-word compression blocks are unchanged.
__global__ void __launch_bounds__(BLOCK_SIZE) stream_leaf_group_from_lde_in_gpu(
    uint32_t size,
    uint32_t group_n_cols,
    uint32_t **prefinal_columns,
    const uint32_t *column_log_sizes,
    uint32_t lifting_log_size,
    uint32_t cols_done,
    uint32_t is_final,
    uint32_t *twiddles,
    uint32_t twiddle_words,
    Blake2sHash *state
) {
    const uint32_t leaf_index = blockIdx.x * blockDim.x + threadIdx.x;
    if (leaf_index >= size) return;

    uint32_t h[8];
    #pragma unroll
    for (int i = 0; i < 8; ++i) h[i] = state[leaf_index].s[i];
    uint32_t m[16];
    uint32_t t = 4u * cols_done;
    uint32_t column = 0;
    if (is_final == 0) {
        while (column < group_n_cols) {
            #pragma unroll
            for (int k = 0; k < 16; ++k) {
                const uint32_t evaluation_log_size = column_log_sizes[column + k];
                const uint32_t local_index = lifted_column_index(
                    leaf_index, lifting_log_size - evaluation_log_size);
                m[k] = n2b_final_value(
                    prefinal_columns[column + k], local_index,
                    evaluation_log_size, twiddles, twiddle_words);
            }
            t += 64;
            blake2s_compress_words(h, m, t, 0);
            column += 16;
        }
    } else {
        #pragma unroll
        for (int k = 0; k < 16; ++k) {
            if ((uint32_t)k < group_n_cols) {
                const uint32_t evaluation_log_size = column_log_sizes[k];
                const uint32_t local_index = lifted_column_index(
                    leaf_index, lifting_log_size - evaluation_log_size);
                m[k] = n2b_final_value(
                    prefinal_columns[k], local_index, evaluation_log_size,
                    twiddles, twiddle_words);
            } else {
                m[k] = 0;
            }
        }
        t += 4u * group_n_cols;
        blake2s_compress_words(h, m, t, 0xFFFFFFFF);
    }
    #pragma unroll
    for (int i = 0; i < 8; ++i) state[leaf_index].s[i] = h[i];
}

__global__ void __launch_bounds__(BLOCK_SIZE) sparse_leaf_group_in_gpu(
    const uint32_t *leaf_indices,
    const uint32_t *leaf_count,
    uint32_t max_leaf_count,
    uint32_t group_n_cols,
    uint32_t **group_data,
    const uint32_t *group_col_log_sizes,
    uint32_t lifting_log_size,
    uint32_t cols_done,
    uint32_t is_final,
    Blake2sHash *states
) {
    const uint32_t sparse_index = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t count = min(*leaf_count, max_leaf_count);
    if (sparse_index >= count) return;
    const uint32_t leaf_index = leaf_indices[sparse_index];

    uint32_t h[8];
    if (cols_done == 0) {
        blake2s_init_words(h);
    } else {
        #pragma unroll
        for (int i = 0; i < 8; ++i) h[i] = states[sparse_index].s[i];
    }
    uint32_t m[16];
    uint32_t t = 4u * cols_done;
    uint32_t col = 0;
    if (!is_final) {
        while (col < group_n_cols) {
            #pragma unroll
            for (int k = 0; k < 16; ++k) {
                const uint32_t log_ratio =
                    lifting_log_size - group_col_log_sizes[col + k];
                m[k] = group_data[col + k][lifted_column_index(leaf_index, log_ratio)];
            }
            t += 64;
            blake2s_compress_words(h, m, t, 0);
            col += 16;
        }
    } else {
        #pragma unroll
        for (int k = 0; k < 16; ++k) {
            if ((uint32_t)k < group_n_cols) {
                const uint32_t log_ratio =
                    lifting_log_size - group_col_log_sizes[k];
                m[k] = group_data[k][lifted_column_index(leaf_index, log_ratio)];
            } else {
                m[k] = 0;
            }
        }
        t += 4u * group_n_cols;
        blake2s_compress_words(h, m, t, 0xFFFFFFFF);
    }
    #pragma unroll
    for (int i = 0; i < 8; ++i) states[sparse_index].s[i] = h[i];
}

// FRI's packed-leaf transform is purely a byte-layout transform:
// packed[coord + 4*offset][row] = coords[coord][4*row + offset]. Hash that
// exact 16-word stream directly so no second full-size evaluation is needed.
extern "C" __global__ void __launch_bounds__(BLOCK_SIZE) stwo_gpu_lab_blake2s_fri_leaf(
    uint32_t evaluation_size,
    m31 **coordinates,
    uint32_t log_rows_per_leaf,
    Blake2sHash *result
) {
    const uint32_t leaf_index = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t leaf_count = evaluation_size >> log_rows_per_leaf;
    if (leaf_index >= leaf_count) return;

    uint32_t h[8];
    blake2s_init_words(h);
    uint32_t m[16] = {0};
    if (log_rows_per_leaf == 0) {
        #pragma unroll
        for (int coord = 0; coord < 4; ++coord) {
            m[coord] = coordinates[coord][leaf_index];
        }
        blake2s_compress_words(h, m, 16, 0xFFFFFFFF);
    } else {
        #pragma unroll
        for (int offset = 0; offset < 4; ++offset) {
            #pragma unroll
            for (int coord = 0; coord < 4; ++coord) {
                m[coord + 4 * offset] =
                    coordinates[coord][4 * leaf_index + offset];
            }
        }
        blake2s_compress_words(h, m, 64, 0xFFFFFFFF);
    }
    #pragma unroll
    for (int i = 0; i < 8; ++i) result[leaf_index].s[i] = h[i];
}

extern "C" __global__ void __launch_bounds__(BLOCK_SIZE, STWO_LEAF_MIN_BLOCKS) stwo_gpu_lab_blake2s_layer(
    uint32_t size,
    uint32_t number_of_columns,
    uint32_t **data,
    Blake2sHash *prev_layer,
    Blake2sHash *result
) {
    uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= size) return;
    // Word-block lane: children = exactly one full block (t = 64), then the
    // optional layer columns continue block-wise. Bit-identical digests.
    uint32_t h[8];
    blake2s_init_words(h);
    uint32_t m[16];
    Blake2sHash left = prev_layer[2*index];
    Blake2sHash right = prev_layer[2*index+1];
    #pragma unroll
    for (int i = 0; i < 8; ++i) m[i] = left.s[i];
    #pragma unroll
    for (int i = 0; i < 8; ++i) m[8 + i] = right.s[i];
    if (number_of_columns == 0) {
        blake2s_compress_words(h, m, 64, 0xFFFFFFFF);
        #pragma unroll
        for (int i = 0; i < 8; i++) result[index].s[i] = h[i];
        return;
    }
    blake2s_compress_words(h, m, 64, 0);
    blake2s_hash_column_words(h, 64, data, number_of_columns, index, &result[index]);
}

// ---------------------------------------------------------------------------
// Commit-path fusion (Workstream D) — layer-pair Merkle hashing.
//
// Additive: the kernels above are untouched. This hashes TWO internal tree levels
// per launch. For output index i it produces
//     out[i] = H( H(prev[4i], prev[4i+1]), H(prev[4i+2], prev[4i+3]) )
// which is *exactly* two sequential applications of
// `stwo_gpu_lab_blake2s_layer` with number_of_columns == 0 — i.e.
// byte-identical to the reference by construction, no hash-function or ordering
// change. It is only valid where BOTH fused levels inject zero columns (the common
// internal-tree case in the lifted Merkle tree); the caller must not use it across
// a level that injects columns. Gated OFF behind STWO_CUDA_FUSED_COMMIT +
// STWO_CUDA_FUSED_COMMIT_LAYER_PAIR (default OFF) until the pod gates pass.
// ---------------------------------------------------------------------------

// Hash a pair of child digests into one, matching the column-free byte stream of
// `stwo_gpu_lab_blake2s_layer` (left.s[0..8] then right.s[0..8], each
// word little-endian) exactly.
__device__ __forceinline__ Blake2sHash blake2s_hash_children_device(
    const Blake2sHash& left,
    const Blake2sHash& right
) {
    // Word-block lane: one full block (t = 64) with the lastblock flag.
    uint32_t h[8];
    blake2s_init_words(h);
    uint32_t m[16];
    #pragma unroll
    for (int i = 0; i < 8; ++i) m[i] = left.s[i];
    #pragma unroll
    for (int i = 0; i < 8; ++i) m[8 + i] = right.s[i];
    blake2s_compress_words(h, m, 64, 0xFFFFFFFF);
    Blake2sHash out;
    #pragma unroll
    for (int i = 0; i < 8; ++i) out.s[i] = h[i];
    return out;
}

__global__ void __launch_bounds__(BLOCK_SIZE) commit_on_two_layers_using_previous_in_gpu(
    uint32_t size,                 // number of OUTPUT (grandparent) hashes
    Blake2sHash *prev_layer,       // size == 4 * `size`
    Blake2sHash *result
) {
    uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= size) return;
    Blake2sHash left_mid =
        blake2s_hash_children_device(prev_layer[4 * index + 0], prev_layer[4 * index + 1]);
    Blake2sHash right_mid =
        blake2s_hash_children_device(prev_layer[4 * index + 2], prev_layer[4 * index + 3]);
    result[index] = blake2s_hash_children_device(left_mid, right_mid);
}

uint32_t number_of_blocks_for(uint32_t size) {
    return (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
}

// ILP2 grid: one thread per ROW PAIR; an odd row count adds one single-row
// thread. Keep this formula in LOCKSTEP with `leaf_ilp2_grid_blocks` in
// crates/backend-cuda/src/backend/blake2s.rs (pure-Rust mirror + unit tests).
static uint32_t number_of_ilp2_blocks_for(uint32_t size) {
    const uint32_t row_pairs = size / 2 + (size & 1);
    return number_of_blocks_for(row_pairs);
}
void commit_on_first_layer(
    uint32_t size,
    uint32_t number_of_columns,
    uint32_t **device_columns,
    Blake2sHash* result
) {
    commit_on_first_layer_in_gpu<<<number_of_blocks_for(size), BLOCK_SIZE>>>(
        size, number_of_columns, device_columns, result);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

void commit_on_first_layer_lifted(
    uint32_t size,
    uint32_t number_of_columns,
    uint32_t **device_columns,
    const uint32_t *column_log_sizes,
    uint32_t lifting_log_size,
    Blake2sHash* result
) {
    commit_on_first_layer_lifted_in_gpu<<<number_of_blocks_for(size), BLOCK_SIZE>>>(
        size, number_of_columns, device_columns, column_log_sizes, lifting_log_size, result);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

// Streaming leaf commit (VRAM diet) — init / update-group / finalize.
// Decisive bandwidth-vs-occupancy probe for the fused-commit keystone (design §19,
// component #2). Prints, once per process when STWO_COMMIT_PROBE is set, each commit
// kernel's static register/shared footprint and the resulting theoretical occupancy
// (achieved active-warps / SM max). Low occupancy => the leaf-hash kernel is
// register/occupancy-bound (the ledger's evidence-based finding, now measured), so
// the lever is register-pressure reduction / cooperative hashing, NOT eliminating the
// LDE HBM round-trip (which is only ~5ms of bandwidth). Zero cost when the env is unset.
static void stwo_maybe_probe_commit_occupancy() {
    static bool done = false;
    if (done) {
        return;
    }
    done = true;
    if (getenv("STWO_COMMIT_PROBE") == nullptr) {
        return;
    }
    struct KernelInfo {
        const char *name;
        const void *fn;
        int block;
    };
    const KernelInfo kernels[] = {
        {"stream_leaf_update", reinterpret_cast<const void *>(stream_leaf_update_in_gpu), BLOCK_SIZE},
        {"stream_leaf_update_ilp2",
         reinterpret_cast<const void *>(stream_leaf_update_ilp2_in_gpu), BLOCK_SIZE},
        {"stream_leaf_finalize", reinterpret_cast<const void *>(stream_leaf_finalize_in_gpu),
         BLOCK_SIZE},
        {"commit_on_first_layer_lifted",
         reinterpret_cast<const void *>(commit_on_first_layer_lifted_in_gpu), BLOCK_SIZE},
        {"commit_on_layer_using_previous",
         reinterpret_cast<const void *>(stwo_gpu_lab_blake2s_layer), BLOCK_SIZE},
    };
    int dev = 0;
    cudaGetDevice(&dev);
    cudaDeviceProp prop;
    cudaGetDeviceProperties(&prop, dev);
    for (const KernelInfo &k : kernels) {
        cudaFuncAttributes attr;
        if (cudaFuncGetAttributes(&attr, k.fn) != cudaSuccess) {
            continue;
        }
        int max_blocks = 0;
        cudaOccupancyMaxActiveBlocksPerMultiprocessor(&max_blocks, k.fn, k.block, 0);
        double occ = static_cast<double>(max_blocks * k.block) / prop.maxThreadsPerMultiProcessor;
        fprintf(stderr,
                "COMMIT_PROBE %s: regs=%d smem_bytes=%zu localmem_bytes=%zu "
                "block=%d maxBlocksPerSM=%d occupancy=%.3f\n",
                k.name, attr.numRegs, attr.sharedSizeBytes, attr.localSizeBytes, k.block,
                max_blocks, occ);
    }
}

void stream_leaf_init(uint32_t size, Blake2sHash *state) {
    stwo_maybe_probe_commit_occupancy();
    stream_leaf_init_in_gpu<<<number_of_blocks_for(size), BLOCK_SIZE>>>(size, state);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

void stream_leaf_update(
    uint32_t size,
    uint32_t group_n_cols,
    uint32_t **device_columns,
    const uint32_t *column_log_sizes,
    uint32_t lifting_log_size,
    uint32_t cols_done,
    Blake2sHash *state
) {
    stream_leaf_update_in_gpu<<<number_of_blocks_for(size), BLOCK_SIZE>>>(
        size, group_n_cols, device_columns, column_log_sizes, lifting_log_size, cols_done, state);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

// ILP2 leaf-update lane (opt-in; see stream_leaf_update_ilp2_in_gpu).
// Byte-identical to stream_leaf_update with half the grid.
void stream_leaf_update_ilp2(
    uint32_t size,
    uint32_t group_n_cols,
    uint32_t **device_columns,
    const uint32_t *column_log_sizes,
    uint32_t lifting_log_size,
    uint32_t cols_done,
    Blake2sHash *state
) {
    stream_leaf_update_ilp2_in_gpu<<<number_of_ilp2_blocks_for(size), BLOCK_SIZE>>>(
        size, group_n_cols, device_columns, column_log_sizes, lifting_log_size, cols_done, state);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

void stream_leaf_finalize(
    uint32_t size,
    uint32_t rem_cols,
    uint32_t **device_columns,
    const uint32_t *column_log_sizes,
    uint32_t lifting_log_size,
    uint32_t cols_done,
    Blake2sHash *result
) {
    stream_leaf_finalize_in_gpu<<<number_of_blocks_for(size), BLOCK_SIZE>>>(
        size, rem_cols, device_columns, column_log_sizes, lifting_log_size, cols_done, result);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

// Graph-capturable streaming-leaf entry points. Pointer/log tables and output
// state are caller-owned DEVICE buffers; every launch uses the supplied stream.
// These functions intentionally skip the optional occupancy probe and all debug
// synchronization so capture contains only the actual kernels.
extern "C" int stwo_blake2s_leaf_init_on(
    uint32_t size, Blake2sHash *state, void *stream
) {
    if (size == 0 || state == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    stream_leaf_init_in_gpu<<<number_of_blocks_for(size), BLOCK_SIZE, 0,
                              reinterpret_cast<cudaStream_t>(stream)>>>(size, state);
    return cudaGetLastError();
}

extern "C" int stwo_blake2s_progressive_init_on(
    uint32_t size, ProgressiveBlake2sState *states, void *stream
) {
    if (size == 0 || states == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    progressive_leaf_init_in_gpu<<<number_of_blocks_for(size), BLOCK_SIZE, 0,
                                   reinterpret_cast<cudaStream_t>(stream)>>>(size, states);
    return cudaGetLastError();
}

extern "C" int stwo_blake2s_progressive_absorb_on(
    uint32_t size,
    uint32_t number_of_columns,
    uint32_t absorbed_columns_before,
    uint32_t **columns,
    ProgressiveBlake2sState *states,
    void *stream
) {
    if (size == 0 || number_of_columns == 0 || columns == nullptr ||
        absorbed_columns_before > 0xffffffffu - number_of_columns ||
        states == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    progressive_leaf_absorb_in_gpu<<<number_of_blocks_for(size), BLOCK_SIZE, 0,
                                     reinterpret_cast<cudaStream_t>(stream)>>>(
        size, number_of_columns, absorbed_columns_before, columns, states);
    return cudaGetLastError();
}

extern "C" int stwo_blake2s_progressive_expand_on(
    uint32_t from_log_size,
    uint32_t to_log_size,
    const ProgressiveBlake2sState *states_in,
    ProgressiveBlake2sState *states_out,
    void *stream
) {
    if (from_log_size >= to_log_size || to_log_size >= 31 ||
        states_in == nullptr || states_out == nullptr || states_in == states_out ||
        stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    uint32_t to_size = 1u << to_log_size;
    progressive_leaf_expand_in_gpu<<<number_of_blocks_for(to_size), BLOCK_SIZE, 0,
                                     reinterpret_cast<cudaStream_t>(stream)>>>(
        to_size, to_log_size - from_log_size, states_in, states_out);
    return cudaGetLastError();
}

extern "C" int stwo_blake2s_progressive_finalize_on(
    uint32_t size,
    uint32_t absorbed_columns,
    const ProgressiveBlake2sState *states,
    Blake2sHash *result,
    void *stream
) {
    if (size == 0 || states == nullptr || result == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    progressive_leaf_finalize_in_gpu<<<number_of_blocks_for(size), BLOCK_SIZE, 0,
                                       reinterpret_cast<cudaStream_t>(stream)>>>(
        size, absorbed_columns, states, result);
    return cudaGetLastError();
}

extern "C" int stwo_blake2s_leaf_update_on(
    uint32_t size,
    uint32_t group_n_cols,
    uint32_t **device_columns,
    const uint32_t *column_log_sizes,
    uint32_t lifting_log_size,
    uint32_t cols_done,
    Blake2sHash *state,
    void *stream
) {
    if (size == 0 || group_n_cols == 0 || (group_n_cols % 16) != 0 ||
        device_columns == nullptr || column_log_sizes == nullptr ||
        lifting_log_size >= 31 || size != (1u << lifting_log_size) ||
        (cols_done % 16) != 0 || state == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    stream_leaf_update_in_gpu<<<number_of_blocks_for(size), BLOCK_SIZE, 0,
                                reinterpret_cast<cudaStream_t>(stream)>>>(
        size, group_n_cols, device_columns, column_log_sizes, lifting_log_size,
        cols_done, state);
    return cudaGetLastError();
}

// ILP2 explicit-stream leaf update (opt-in via STWO_CUDA_BLAKE2S_LEAF_ILP=1 at
// the Rust launch sites). Same validation contract as
// stwo_blake2s_leaf_update_on; only the grid (halved) and the kernel differ.
extern "C" int stwo_blake2s_leaf_update_ilp2_on(
    uint32_t size,
    uint32_t group_n_cols,
    uint32_t **device_columns,
    const uint32_t *column_log_sizes,
    uint32_t lifting_log_size,
    uint32_t cols_done,
    Blake2sHash *state,
    void *stream
) {
    if (size == 0 || group_n_cols == 0 || (group_n_cols % 16) != 0 ||
        device_columns == nullptr || column_log_sizes == nullptr ||
        lifting_log_size >= 31 || size != (1u << lifting_log_size) ||
        (cols_done % 16) != 0 || state == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    stream_leaf_update_ilp2_in_gpu<<<number_of_ilp2_blocks_for(size), BLOCK_SIZE, 0,
                                     reinterpret_cast<cudaStream_t>(stream)>>>(
        size, group_n_cols, device_columns, column_log_sizes, lifting_log_size,
        cols_done, state);
    return cudaGetLastError();
}

extern "C" int stwo_blake2s_leaf_finalize_on(
    uint32_t size,
    uint32_t rem_cols,
    uint32_t **device_columns,
    const uint32_t *column_log_sizes,
    uint32_t lifting_log_size,
    uint32_t cols_done,
    Blake2sHash *result,
    void *stream
) {
    if (size == 0 || rem_cols == 0 || rem_cols > 16 || device_columns == nullptr ||
        column_log_sizes == nullptr || lifting_log_size >= 31 ||
        size != (1u << lifting_log_size) || (cols_done % 16) != 0 ||
        result == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    stream_leaf_finalize_in_gpu<<<number_of_blocks_for(size), BLOCK_SIZE, 0,
                                  reinterpret_cast<cudaStream_t>(stream)>>>(
        size, rem_cols, device_columns, column_log_sizes, lifting_log_size,
        cols_done, result);
    return cudaGetLastError();
}

extern "C" int stwo_blake2s_leaf_group_from_lde_on(
    uint32_t size,
    uint32_t group_n_cols,
    uint32_t **prefinal_columns,
    const uint32_t *column_log_sizes,
    uint32_t lifting_log_size,
    uint32_t cols_done,
    uint32_t is_final,
    uint32_t *twiddles,
    uint32_t twiddle_words,
    Blake2sHash *state,
    void *stream
) {
    const bool valid_width = is_final != 0
        ? group_n_cols > 0 && group_n_cols <= 16
        : group_n_cols > 0 && (group_n_cols % 16) == 0;
    if (size == 0 || !valid_width || prefinal_columns == nullptr ||
        column_log_sizes == nullptr || lifting_log_size >= 31 ||
        size != (1u << lifting_log_size) || (cols_done % 16) != 0 ||
        twiddles == nullptr || twiddle_words == 0 || state == nullptr ||
        stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    stream_leaf_group_from_lde_in_gpu<<<number_of_blocks_for(size), BLOCK_SIZE, 0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
        size, group_n_cols, prefinal_columns, column_log_sizes,
        lifting_log_size, cols_done, is_final, twiddles, twiddle_words, state);
    return cudaGetLastError();
}

// One column-free interior Merkle level: result[i] = H(prev[2i], prev[2i+1]).
extern "C" int stwo_blake2s_layer_on(
    const Blake2sHash *previous_layer,
    uint32_t output_size,
    Blake2sHash *result,
    void *stream
) {
    if (previous_layer == nullptr || output_size == 0 ||
        (output_size & (output_size - 1)) != 0 || result == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    stwo_gpu_lab_blake2s_layer<<<number_of_blocks_for(output_size), BLOCK_SIZE, 0,
                                 reinterpret_cast<cudaStream_t>(stream)>>>(
        output_size, 0, nullptr, const_cast<Blake2sHash *>(previous_layer), result);
    return cudaGetLastError();
}

extern "C" int stwo_blake2s_fri_leaf_on(
    uint32_t evaluation_size,
    uint32_t **coordinate_columns,
    uint32_t log_rows_per_leaf,
    Blake2sHash *result,
    void *stream
) {
    if (evaluation_size == 0 ||
        (evaluation_size & (evaluation_size - 1)) != 0 ||
        coordinate_columns == nullptr ||
        (log_rows_per_leaf != 0 && log_rows_per_leaf != 2) ||
        evaluation_size < (1u << log_rows_per_leaf) ||
        result == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    const uint32_t leaf_count = evaluation_size >> log_rows_per_leaf;
    stwo_gpu_lab_blake2s_fri_leaf<<<number_of_blocks_for(leaf_count), BLOCK_SIZE, 0,
                                    reinterpret_cast<cudaStream_t>(stream)>>>(
        evaluation_size,
        reinterpret_cast<m31 **>(coordinate_columns),
        log_rows_per_leaf,
        result);
    return cudaGetLastError();
}

extern "C" int stwo_blake2s_sparse_leaf_group_on(
    const uint32_t *leaf_indices,
    const uint32_t *leaf_count,
    uint32_t max_leaf_count,
    uint32_t group_n_cols,
    uint32_t **columns,
    const uint32_t *column_log_sizes,
    uint32_t lifting_log_size,
    uint32_t cols_done,
    uint32_t is_final,
    Blake2sHash *states,
    void *stream
) {
    const bool valid_width = is_final != 0
        ? group_n_cols > 0 && group_n_cols <= 16
        : group_n_cols > 0 && (group_n_cols % 16) == 0;
    if (leaf_indices == nullptr || leaf_count == nullptr || max_leaf_count == 0 ||
        !valid_width || columns == nullptr || column_log_sizes == nullptr ||
        lifting_log_size >= 31 || (cols_done % 16) != 0 || states == nullptr ||
        stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    sparse_leaf_group_in_gpu<<<number_of_blocks_for(max_leaf_count), BLOCK_SIZE, 0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
        leaf_indices, leaf_count, max_leaf_count, group_n_cols, columns,
        column_log_sizes, lifting_log_size, cols_done, is_final, states);
    return cudaGetLastError();
}

void commit_on_layer_with_previous(
    uint32_t size,
    uint32_t number_of_columns,
    uint32_t **device_columns,
    Blake2sHash* previous_layer,
    Blake2sHash* result
) {
    stwo_gpu_lab_blake2s_layer<<<number_of_blocks_for(size), BLOCK_SIZE>>>(
        size, number_of_columns, device_columns, previous_layer, result);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

// Layer-pair fusion (Workstream D). `size` is the number of grandparent hashes to
// produce; `previous_layer` must hold `4 * size` child hashes. Column-free only.
void commit_on_two_layers_with_previous(
    uint32_t size,
    Blake2sHash* previous_layer,
    Blake2sHash* result
) {
    commit_on_two_layers_using_previous_in_gpu<<<number_of_blocks_for(size), BLOCK_SIZE>>>(
        size, previous_layer, result);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

// ---------------------------------------------------------------------------
// Merkle TAIL fusion (commit fusion, C2): the top K levels in ONE launch. The
// per-level launches this replaces are tiny (<= 4096 nodes) — their cost is
// the launch gap, not the hashing — so a single block with __syncthreads
// between levels replaces ~K launches. Levels write into caller-provided
// per-level buffers (the same layout the per-layer path produces, so tree
// readers are unchanged). Hashing delegates to blake2s_hash_children_device —
// the SAME routine the per-layer kernel uses: a scheduling change, not a new
// hash.
// 256 threads, bounded: the inlined children hash is register-fat and a
// 1024-thread block exceeds the SM register file (launch fails with
// out-of-resources on H100). Width is irrelevant here — the whole tail is
// <= 2^12 hashes and the per-level grid-stride loop covers any level width.
#define STWO_TAIL_BLOCK 256u
__global__ void __launch_bounds__(STWO_TAIL_BLOCK) blake2s_tail_kernel(
    const Blake2sHash *first,
    uint32_t first_size,
    Blake2sHash *const *out_levels,
    uint32_t n_levels
) {
    const Blake2sHash *prev = first;
    uint32_t size = first_size;
    for (uint32_t l = 0; l < n_levels; ++l) {
        uint32_t next = size / 2;
        for (uint32_t i = threadIdx.x; i < next; i += blockDim.x) {
            out_levels[l][i] =
                blake2s_hash_children_device(prev[2 * i], prev[2 * i + 1]);
        }
        __syncthreads();
        prev = out_levels[l];
        size = next;
    }
}

// Returns 0 on success. `out_levels_dev` is a DEVICE array of n_levels device
// pointers; level l holds first_size >> (l+1) hashes. first_size must be a
// power of two with first_size >> n_levels >= 1.
extern "C" int stwo_blake2s_tail(
    const Blake2sHash *first_dev,
    uint32_t first_size,
    Blake2sHash *const *out_levels_dev,
    uint32_t n_levels
) {
    if (n_levels == 0) {
        return 0;
    }
    if (n_levels >= 32 || first_size == 0 || (first_size & (first_size - 1)) != 0 ||
        (first_size >> n_levels) == 0) {
        fprintf(stderr, "stwo_blake2s_tail: bad sizes (first=%u levels=%u)\n",
                first_size, n_levels);
        return 1;
    }
    blake2s_tail_kernel<<<1, STWO_TAIL_BLOCK>>>(first_dev, first_size, out_levels_dev, n_levels);
    if (cudaGetLastError() != cudaSuccess) {
        fprintf(stderr, "stwo_blake2s_tail: launch failed\n");
        return 1;
    }
    return 0;
}

// Explicit-stream tail variant for graph capture. All level buffers and the
// device pointer table are caller-owned and address-stable for the graph epoch.
extern "C" int stwo_blake2s_tail_on(
    const Blake2sHash *first_dev,
    uint32_t first_size,
    Blake2sHash *const *out_levels_dev,
    uint32_t n_levels,
    void *stream
) {
    if (stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    if (n_levels == 0) {
        return cudaSuccess;
    }
    if (first_dev == nullptr || out_levels_dev == nullptr || n_levels >= 32 ||
        first_size == 0 || (first_size & (first_size - 1)) != 0 ||
        (first_size >> n_levels) == 0) {
        return cudaErrorInvalidValue;
    }
    blake2s_tail_kernel<<<1, STWO_TAIL_BLOCK, 0,
                          reinterpret_cast<cudaStream_t>(stream)>>>(
        first_dev, first_size, out_levels_dev, n_levels);
    return cudaGetLastError();
}

// ---------------------------------------------------------------------------
// Interior FOUR-level fusion (Step 3.2 second half; opt-in via
// STWO_CUDA_BLAKE2S_INTERIOR_FUSED=1 on the Rust planning side, default OFF).
//
// One launch builds FOUR column-free interior Merkle levels: for each output
// index i it consumes the 16 consecutive child digests prev[16i .. 16i+16)
// and produces the level-4 ancestor. The three intermediate levels live only
// in SHARED memory — they are never written to (or reread from) HBM, so the
// interior traffic for the window drops from (1/2 + 1/4 + 1/8 + 1/16) reads +
// writes per child to one read of the children plus a 1/16th-size output
// write. The Rust planner only selects this kernel for windows whose three
// intermediate levels are UNRETAINED (prune-depth scratch); any window that
// must materialize an intermediate retained layer falls back to the per-level
// kernel (see commit_graph.rs).
//
// BYTE IDENTITY: every parent is blake2s_hash_children_device — the SAME
// routine the per-level kernel (stwo_gpu_lab_blake2s_layer with
// number_of_columns == 0), the layer-pair kernel, and the fused tail use —
// and at each of the four local levels parent[j] = H(child[2j], child[2j+1]),
// exactly the per-level index mapping. By induction over the four levels the
// output level is bit-identical to four sequential stwo_blake2s_layer_on
// launches; this is a scheduling/traffic change, not a new hash or ordering.
// The pure-Rust spec test `interior4_spec_tests` in
// crates/backend-cuda/src/backend/blake2s.rs locks this composition against
// the CPU reference hasher.
//
// Geometry: 256 threads/block; each block produces 32 outputs from 512
// children. Level 1 reads children straight from global (each thread hashes
// one adjacent pair — no need to stage raw children in shared) and parks the
// 256 parents in shared; levels 2..4 reduce within shared; level 4 writes the
// 32 outputs to global. Shared footprint: (256 + 128 + 64) * 32 B = 14 KiB.
// Keep the grid math in LOCKSTEP with `interior4_grid_blocks` in
// crates/backend-cuda/src/backend/blake2s.rs (pure-Rust mirror + unit tests).
#define STWO_INTERIOR4_BLOCK 256u
#define STWO_INTERIOR4_OUT_PER_BLOCK (STWO_INTERIOR4_BLOCK / 8u)

__global__ void __launch_bounds__(STWO_INTERIOR4_BLOCK) blake2s_interior4_kernel(
    const Blake2sHash *prev,    // 16 * out_size child digests
    uint32_t out_size,          // number of level-4 output hashes
    Blake2sHash *out
) {
    __shared__ Blake2sHash l1[STWO_INTERIOR4_BLOCK];        // level-1 parents
    __shared__ Blake2sHash l2[STWO_INTERIOR4_BLOCK / 2];    // level-2 parents
    __shared__ Blake2sHash l3[STWO_INTERIOR4_BLOCK / 4];    // level-3 parents

    const uint32_t out0 = blockIdx.x * STWO_INTERIOR4_OUT_PER_BLOCK;
    // Outputs owned by this block. out_size is a power of two, so the window
    // is only partial when out_size < 32 (then the grid is a single block).
    const uint32_t window = min(out_size - out0, STWO_INTERIOR4_OUT_PER_BLOCK);
    const uint32_t tid = threadIdx.x;
    const Blake2sHash *children = prev + 16u * out0;

    if (tid < 8u * window) {
        l1[tid] = blake2s_hash_children_device(children[2u * tid], children[2u * tid + 1]);
    }
    __syncthreads();
    if (tid < 4u * window) {
        l2[tid] = blake2s_hash_children_device(l1[2u * tid], l1[2u * tid + 1]);
    }
    __syncthreads();
    if (tid < 2u * window) {
        l3[tid] = blake2s_hash_children_device(l2[2u * tid], l2[2u * tid + 1]);
    }
    __syncthreads();
    if (tid < window) {
        out[out0 + tid] = blake2s_hash_children_device(l3[2u * tid], l3[2u * tid + 1]);
    }
}

// Grid: one block per 32 outputs. Mirror of `interior4_grid_blocks` (Rust).
static uint32_t number_of_interior4_blocks_for(uint32_t out_size) {
    return (out_size + STWO_INTERIOR4_OUT_PER_BLOCK - 1) / STWO_INTERIOR4_OUT_PER_BLOCK;
}

// Four column-free interior levels in one launch: result[i] is the level-4
// ancestor of previous_layer[16i .. 16i+16). `previous_layer` must hold
// 16 * output_size hashes. In-place operation is FORBIDDEN (blocks write
// low output indices other blocks may still be reading as children), hence
// the aliasing reject; the Rust planner additionally falls back to per-level
// kernels for any window whose buffers alias.
extern "C" int stwo_blake2s_interior4_on(
    const Blake2sHash *previous_layer,
    uint32_t output_size,
    Blake2sHash *result,
    void *stream
) {
    if (previous_layer == nullptr || output_size == 0 ||
        (output_size & (output_size - 1)) != 0 || result == nullptr ||
        previous_layer == result || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    blake2s_interior4_kernel<<<number_of_interior4_blocks_for(output_size),
                               STWO_INTERIOR4_BLOCK, 0,
                               reinterpret_cast<cudaStream_t>(stream)>>>(
        previous_layer, output_size, result);
    return cudaGetLastError();
}
