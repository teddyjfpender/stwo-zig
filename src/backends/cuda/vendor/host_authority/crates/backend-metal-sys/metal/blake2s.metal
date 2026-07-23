#include <metal_stdlib>
using namespace metal;

constant uint STWO_METAL_BLAKE2S_IV[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
};

constant uchar STWO_METAL_BLAKE2S_SIGMA[10][16] = {
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

struct StwoMetalBlake2sState {
    uint h[8];
    uint t;
    uchar buf[64];
    uint buflen;
};

static inline uint stwo_metal_rotr32(uint value, uint shift) {
    return (value >> shift) | (value << (32u - shift));
}

static inline void stwo_metal_blake2s_g(
    thread uint *v,
    thread const uint *m,
    uint round,
    uint index,
    thread uint &a,
    thread uint &b,
    thread uint &c,
    thread uint &d
) {
    a = a + b + m[STWO_METAL_BLAKE2S_SIGMA[round][2u * index + 0u]];
    d = stwo_metal_rotr32(d ^ a, 16u);
    c = c + d;
    b = stwo_metal_rotr32(b ^ c, 12u);
    a = a + b + m[STWO_METAL_BLAKE2S_SIGMA[round][2u * index + 1u]];
    d = stwo_metal_rotr32(d ^ a, 8u);
    c = c + d;
    b = stwo_metal_rotr32(b ^ c, 7u);
    (void)v;
}

static inline void stwo_metal_blake2s_compress(
    thread StwoMetalBlake2sState &state,
    thread const uchar *block,
    uint total_bytes,
    uint last_block
) {
    uint m[16];
    for (uint i = 0; i < 16u; ++i) {
        uint base = 4u * i;
        m[i] =
            ((uint)block[base + 0u]) |
            (((uint)block[base + 1u]) << 8u) |
            (((uint)block[base + 2u]) << 16u) |
            (((uint)block[base + 3u]) << 24u);
    }

    uint v[16];
    for (uint i = 0; i < 8u; ++i) {
        v[i] = state.h[i];
        v[i + 8u] = STWO_METAL_BLAKE2S_IV[i];
    }
    v[12] ^= total_bytes;
    v[14] ^= last_block;

    for (uint round = 0; round < 10u; ++round) {
        stwo_metal_blake2s_g(v, m, round, 0u, v[0], v[4], v[8], v[12]);
        stwo_metal_blake2s_g(v, m, round, 1u, v[1], v[5], v[9], v[13]);
        stwo_metal_blake2s_g(v, m, round, 2u, v[2], v[6], v[10], v[14]);
        stwo_metal_blake2s_g(v, m, round, 3u, v[3], v[7], v[11], v[15]);
        stwo_metal_blake2s_g(v, m, round, 4u, v[0], v[5], v[10], v[15]);
        stwo_metal_blake2s_g(v, m, round, 5u, v[1], v[6], v[11], v[12]);
        stwo_metal_blake2s_g(v, m, round, 6u, v[2], v[7], v[8], v[13]);
        stwo_metal_blake2s_g(v, m, round, 7u, v[3], v[4], v[9], v[14]);
    }

    for (uint i = 0; i < 8u; ++i) {
        state.h[i] ^= v[i] ^ v[i + 8u];
    }
}

static inline void stwo_metal_blake2s_init(thread StwoMetalBlake2sState &state) {
    state.h[0] = STWO_METAL_BLAKE2S_IV[0] ^ 0x01010020u;
    state.h[1] = STWO_METAL_BLAKE2S_IV[1];
    state.h[2] = STWO_METAL_BLAKE2S_IV[2];
    state.h[3] = STWO_METAL_BLAKE2S_IV[3];
    state.h[4] = STWO_METAL_BLAKE2S_IV[4];
    state.h[5] = STWO_METAL_BLAKE2S_IV[5];
    state.h[6] = STWO_METAL_BLAKE2S_IV[6];
    state.h[7] = STWO_METAL_BLAKE2S_IV[7];
    state.t = 0u;
    state.buflen = 0u;
}

static inline void stwo_metal_blake2s_update(
    thread StwoMetalBlake2sState &state,
    thread const uchar *input,
    uint input_len
) {
    uint left = state.buflen;
    uint fill = 64u - left;
    uint offset = 0u;

    if (input_len > fill) {
        for (uint i = 0; i < fill; ++i) {
            state.buf[left + i] = input[i];
        }
        state.t += 64u;
        stwo_metal_blake2s_compress(state, state.buf, state.t, 0u);
        offset += fill;
        input_len -= fill;
        while (input_len > 64u) {
            state.t += 64u;
            stwo_metal_blake2s_compress(state, input + offset, state.t, 0u);
            offset += 64u;
            input_len -= 64u;
        }
        left = 0u;
    }

    for (uint i = 0; i < input_len; ++i) {
        state.buf[left + i] = input[offset + i];
    }
    state.buflen = left + input_len;
}

static inline void stwo_metal_blake2s_finalize(
    thread StwoMetalBlake2sState &state,
    device uint *dst_words,
    uint dst_index
) {
    state.t += state.buflen;
    for (uint i = state.buflen; i < 64u; ++i) {
        state.buf[i] = 0u;
    }
    stwo_metal_blake2s_compress(state, state.buf, state.t, 0xFFFFFFFFu);
    for (uint i = 0; i < 8u; ++i) {
        dst_words[dst_index * 8u + i] = state.h[i];
    }
}

static inline void stwo_metal_blake2s_init_words(thread uint *state_words) {
    state_words[0] = STWO_METAL_BLAKE2S_IV[0] ^ 0x01010020u;
    state_words[1] = STWO_METAL_BLAKE2S_IV[1];
    state_words[2] = STWO_METAL_BLAKE2S_IV[2];
    state_words[3] = STWO_METAL_BLAKE2S_IV[3];
    state_words[4] = STWO_METAL_BLAKE2S_IV[4];
    state_words[5] = STWO_METAL_BLAKE2S_IV[5];
    state_words[6] = STWO_METAL_BLAKE2S_IV[6];
    state_words[7] = STWO_METAL_BLAKE2S_IV[7];
}

static inline void stwo_metal_blake2s_compress_words(
    thread uint *state_words,
    thread const uchar *block,
    uint total_bytes,
    uint last_block
) {
    uint m[16];
    for (uint i = 0; i < 16u; ++i) {
        uint base = 4u * i;
        m[i] =
            ((uint)block[base + 0u]) |
            (((uint)block[base + 1u]) << 8u) |
            (((uint)block[base + 2u]) << 16u) |
            (((uint)block[base + 3u]) << 24u);
    }

    uint v[16];
    for (uint i = 0; i < 8u; ++i) {
        v[i] = state_words[i];
        v[i + 8u] = STWO_METAL_BLAKE2S_IV[i];
    }
    v[12] ^= total_bytes;
    v[14] ^= last_block;

    for (uint round = 0; round < 10u; ++round) {
        stwo_metal_blake2s_g(v, m, round, 0u, v[0], v[4], v[8], v[12]);
        stwo_metal_blake2s_g(v, m, round, 1u, v[1], v[5], v[9], v[13]);
        stwo_metal_blake2s_g(v, m, round, 2u, v[2], v[6], v[10], v[14]);
        stwo_metal_blake2s_g(v, m, round, 3u, v[3], v[7], v[11], v[15]);
        stwo_metal_blake2s_g(v, m, round, 4u, v[0], v[5], v[10], v[15]);
        stwo_metal_blake2s_g(v, m, round, 5u, v[1], v[6], v[11], v[12]);
        stwo_metal_blake2s_g(v, m, round, 6u, v[2], v[7], v[8], v[13]);
        stwo_metal_blake2s_g(v, m, round, 7u, v[3], v[4], v[9], v[14]);
    }

    for (uint i = 0; i < 8u; ++i) {
        state_words[i] ^= v[i] ^ v[i + 8u];
    }
}

// Like compress_words but takes message words directly (no byte unpacking).
static inline void stwo_metal_blake2s_compress_uint_words(
    thread uint *state_words,
    thread const uint *m,
    uint total_bytes,
    uint last_block
) {
    uint v[16];
    for (uint i = 0; i < 8u; ++i) {
        v[i] = state_words[i];
        v[i + 8u] = STWO_METAL_BLAKE2S_IV[i];
    }
    v[12] ^= total_bytes;
    v[14] ^= last_block;

    for (uint round = 0; round < 10u; ++round) {
        stwo_metal_blake2s_g(v, m, round, 0u, v[0], v[4], v[8], v[12]);
        stwo_metal_blake2s_g(v, m, round, 1u, v[1], v[5], v[9], v[13]);
        stwo_metal_blake2s_g(v, m, round, 2u, v[2], v[6], v[10], v[14]);
        stwo_metal_blake2s_g(v, m, round, 3u, v[3], v[7], v[11], v[15]);
        stwo_metal_blake2s_g(v, m, round, 4u, v[0], v[5], v[10], v[15]);
        stwo_metal_blake2s_g(v, m, round, 5u, v[1], v[6], v[11], v[12]);
        stwo_metal_blake2s_g(v, m, round, 6u, v[2], v[7], v[8], v[13]);
        stwo_metal_blake2s_g(v, m, round, 7u, v[3], v[4], v[9], v[14]);
    }

    for (uint i = 0; i < 8u; ++i) {
        state_words[i] ^= v[i] ^ v[i + 8u];
    }
}

static inline uint stwo_metal_lifted_column_index(uint lifted_index, uint log_ratio) {
    if (log_ratio == 0u) {
        return lifted_index;
    }
    return ((lifted_index >> (log_ratio + 1u)) << 1u) + (lifted_index & 1u);
}

static inline device const uint *stwo_metal_select_leaf_column(
    uint column_index,
    device const uint *column0,
    device const uint *column1,
    device const uint *column2,
    device const uint *column3,
    device const uint *column4,
    device const uint *column5,
    device const uint *column6,
    device const uint *column7,
    device const uint *column8,
    device const uint *column9,
    device const uint *column10,
    device const uint *column11,
    device const uint *column12,
    device const uint *column13,
    device const uint *column14,
    device const uint *column15
) {
    switch (column_index) {
        case 0u: return column0;
        case 1u: return column1;
        case 2u: return column2;
        case 3u: return column3;
        case 4u: return column4;
        case 5u: return column5;
        case 6u: return column6;
        case 7u: return column7;
        case 8u: return column8;
        case 9u: return column9;
        case 10u: return column10;
        case 11u: return column11;
        case 12u: return column12;
        case 13u: return column13;
        case 14u: return column14;
        default: return column15;
    }
}

kernel void blake2s_build_leaves_lifted_u32(
    device const uint *flat_columns [[buffer(0)]],
    device const uint *column_offsets [[buffer(1)]],
    device const uint *column_log_sizes [[buffer(2)]],
    device uint *dst [[buffer(3)]],
    constant uint &n_columns [[buffer(4)]],
    constant uint &lifting_log_size [[buffer(5)]],
    uint row_index [[thread_position_in_grid]]
) {
    uint row_count = 1u << lifting_log_size;
    if (row_index >= row_count) {
        return;
    }

    StwoMetalBlake2sState state;
    stwo_metal_blake2s_init(state);
    uchar bytes[4];

    for (uint column_index = 0u; column_index < n_columns; ++column_index) {
        uint column_log_size = column_log_sizes[column_index];
        uint source_index =
            stwo_metal_lifted_column_index(row_index, lifting_log_size - column_log_size);
        uint value = flat_columns[column_offsets[column_index] + source_index];
        bytes[0] = (uchar)(value & 0xFFu);
        bytes[1] = (uchar)((value >> 8u) & 0xFFu);
        bytes[2] = (uchar)((value >> 16u) & 0xFFu);
        bytes[3] = (uchar)((value >> 24u) & 0xFFu);
        stwo_metal_blake2s_update(state, bytes, 4u);
    }

    stwo_metal_blake2s_finalize(state, dst, row_index);
}

// Fast single-pass leaf builder: processes ALL columns per thread with state in
// registers.  Uses Metal GPU virtual addresses (gpuAddress) to read directly
// from original column buffers — zero copy.  Direct word-level compression
// skips byte packing round-trip.  Eliminates the inter-chunk state buffer.
kernel void blake2s_build_leaves_lifted_fast_u32(
    device const uint64_t *column_addrs [[buffer(0)]],
    device const uint *column_log_sizes [[buffer(1)]],
    device uint *dst [[buffer(2)]],
    constant uint &n_columns [[buffer(3)]],
    constant uint &lifting_log_size [[buffer(4)]],
    uint row_index [[thread_position_in_grid]]
) {
    uint row_count = 1u << lifting_log_size;
    if (row_index >= row_count) {
        return;
    }

    thread uint state[8];
    stwo_metal_blake2s_init_words(state);

    // Process columns in groups of 16 (= 64 bytes = one Blake2s block).
    uint m[16];
    uint col_in_block = 0u;
    uint total_bytes = 0u;

    for (uint c = 0u; c < n_columns; ++c) {
        device const uint *col = (device const uint *)column_addrs[c];
        uint log_ratio = lifting_log_size - column_log_sizes[c];
        uint source_index = stwo_metal_lifted_column_index(row_index, log_ratio);
        m[col_in_block] = col[source_index];
        col_in_block++;
        total_bytes += 4u;

        if (col_in_block == 16u) {
            uint is_last = (c + 1u == n_columns) ? 0xFFFFFFFFu : 0u;
            stwo_metal_blake2s_compress_uint_words(state, m, total_bytes, is_last);
            col_in_block = 0u;
        }
    }

    // Remainder: partially filled block (pad with zeros).
    if (col_in_block > 0u) {
        for (uint i = col_in_block; i < 16u; ++i) {
            m[i] = 0u;
        }
        stwo_metal_blake2s_compress_uint_words(state, m, total_bytes, 0xFFFFFFFFu);
    }

    // Write leaf hash.
    uint dst_base = row_index * 8u;
    for (uint i = 0u; i < 8u; ++i) {
        dst[dst_base + i] = state[i];
    }
}

kernel void blake2s_build_leaves_lifted_wide_chunk_u32(
    device const uint *column0 [[buffer(0)]],
    device const uint *column1 [[buffer(1)]],
    device const uint *column2 [[buffer(2)]],
    device const uint *column3 [[buffer(3)]],
    device const uint *column4 [[buffer(4)]],
    device const uint *column5 [[buffer(5)]],
    device const uint *column6 [[buffer(6)]],
    device const uint *column7 [[buffer(7)]],
    device const uint *column8 [[buffer(8)]],
    device const uint *column9 [[buffer(9)]],
    device const uint *column10 [[buffer(10)]],
    device const uint *column11 [[buffer(11)]],
    device const uint *column12 [[buffer(12)]],
    device const uint *column13 [[buffer(13)]],
    device const uint *column14 [[buffer(14)]],
    device const uint *column15 [[buffer(15)]],
    device uint *state_words [[buffer(16)]],
    device uint *dst [[buffer(17)]],
    constant uint *column_log_sizes [[buffer(18)]],
    constant uint &n_columns [[buffer(19)]],
    constant uint &lifting_log_size [[buffer(20)]],
    constant uint &processed_bytes_before [[buffer(21)]],
    constant uint &is_first_chunk [[buffer(22)]],
    constant uint &is_final_chunk [[buffer(23)]],
    uint row_index [[thread_position_in_grid]]
) {
    uint row_count = 1u << lifting_log_size;
    if (row_index >= row_count) {
        return;
    }

    thread uint state[8];
    if (is_first_chunk != 0u) {
        stwo_metal_blake2s_init_words(state);
    } else {
        for (uint i = 0; i < 8u; ++i) {
            state[i] = state_words[row_index * 8u + i];
        }
    }

    uchar block[64];
    for (uint i = 0; i < 64u; ++i) {
        block[i] = 0u;
    }

    for (uint column_index = 0u; column_index < n_columns; ++column_index) {
        device const uint *column = stwo_metal_select_leaf_column(
            column_index,
            column0,
            column1,
            column2,
            column3,
            column4,
            column5,
            column6,
            column7,
            column8,
            column9,
            column10,
            column11,
            column12,
            column13,
            column14,
            column15
        );
        uint column_log_size = column_log_sizes[column_index];
        uint source_index =
            stwo_metal_lifted_column_index(row_index, lifting_log_size - column_log_size);
        uint value = column[source_index];
        uint byte_offset = column_index * 4u;
        block[byte_offset + 0u] = (uchar)(value & 0xFFu);
        block[byte_offset + 1u] = (uchar)((value >> 8u) & 0xFFu);
        block[byte_offset + 2u] = (uchar)((value >> 16u) & 0xFFu);
        block[byte_offset + 3u] = (uchar)((value >> 24u) & 0xFFu);
    }

    uint total_bytes = processed_bytes_before + n_columns * 4u;
    uint last_block = is_final_chunk != 0u ? 0xFFFFFFFFu : 0u;
    stwo_metal_blake2s_compress_words(state, block, total_bytes, last_block);

    for (uint i = 0; i < 8u; ++i) {
        state_words[row_index * 8u + i] = state[i];
        if (is_final_chunk != 0u) {
            dst[row_index * 8u + i] = state[i];
        }
    }
}

kernel void blake2s_build_next_layer_u32(
    device const uint *prev_layer [[buffer(0)]],
    device uint *dst [[buffer(1)]],
    constant uint &next_len [[buffer(2)]],
    uint row_index [[thread_position_in_grid]]
) {
    if (row_index >= next_len) {
        return;
    }

    // Read 16 message words directly — skip byte unpack/repack overhead.
    uint m[16];
    uint child_base = row_index * 16u;
    for (uint i = 0u; i < 16u; ++i) {
        m[i] = prev_layer[child_base + i];
    }

    thread uint state[8];
    stwo_metal_blake2s_init_words(state);
    stwo_metal_blake2s_compress_uint_words(state, m, 64u, 0xFFFFFFFFu);

    uint dst_base = row_index * 8u;
    for (uint i = 0u; i < 8u; ++i) {
        dst[dst_base + i] = state[i];
    }
}
