#include "blake2s.cuh"
#include "n2b_terminal.cuh"

#include <stdint.h>

// Low-register streaming Blake2s leaf update. The scalar implementation keeps
// h[8], m[16], and v[16] in one thread and reaches the SM90 255-register
// ceiling. Here one four-lane subgroup owns one leaf. Lane q owns v[q],
// v[q+4], v[q+8], and v[q+12]; column G functions are local, while the
// diagonal half-round is a fixed shuffle permutation inside the quad.

namespace {

constexpr uint32_t kBlockThreads = 256;
constexpr uint32_t kQuadWidth = 4;
constexpr uint32_t kTerminalPairWidth = 8;
constexpr uint32_t kLeavesPerBlock = kBlockThreads / kQuadWidth;
constexpr uint32_t kTerminalPairsPerBlock =
    kBlockThreads / kTerminalPairWidth;
constexpr uint32_t kMaxQuadRows = 1u << 30;
#ifndef STWO_BLAKE2S_QUAD_MIN_BLOCKS
#define STWO_BLAKE2S_QUAD_MIN_BLOCKS 6
#endif
#ifndef STWO_BLAKE2S_PROGRESSIVE_QUAD_MIN_BLOCKS
#define STWO_BLAKE2S_PROGRESSIVE_QUAD_MIN_BLOCKS 5
#endif
static_assert(kBlockThreads % 32 == 0, "quad block must contain complete warps");
static_assert(32 % kQuadWidth == 0, "quad width must partition a warp");
static_assert(STWO_BLAKE2S_QUAD_MIN_BLOCKS >= 1, "invalid occupancy target");
static_assert(STWO_BLAKE2S_PROGRESSIVE_QUAD_MIN_BLOCKS >= 1,
              "invalid progressive occupancy target");

__device__ __constant__ uint32_t kIv[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

__device__ __forceinline__ uint32_t rotate_right(uint32_t value, uint32_t bits) {
    return __funnelshift_r(value, value, bits);
}

__device__ __forceinline__ void mix(
    uint32_t &a,
    uint32_t &b,
    uint32_t &c,
    uint32_t &d,
    uint32_t first,
    uint32_t second) {
    a = a + b + first;
    d = rotate_right(d ^ a, 16);
    c += d;
    b = rotate_right(b ^ c, 12);
    a = a + b + second;
    d = rotate_right(d ^ a, 8);
    c += d;
    b = rotate_right(b ^ c, 7);
}

__device__ __forceinline__ uint32_t quad_shuffle(
    uint32_t mask, uint32_t value, uint32_t source_lane) {
    return __shfl_sync(mask, value, source_lane, kQuadWidth);
}

// The 16 message words are staged once in shared memory so every lane can
// consume the round permutation without retaining the full block in registers.
__device__ __forceinline__ void compress_quad(
    uint32_t mask,
    uint32_t quad_lane,
    uint32_t &h_low,
    uint32_t &h_high,
    const uint32_t *message,
    uint32_t total_bytes,
    uint32_t last_block) {
    const uint32_t original_low = h_low;
    const uint32_t original_high = h_high;
    uint32_t a = h_low;
    uint32_t b = h_high;
    uint32_t c = kIv[quad_lane];
    uint32_t d = kIv[quad_lane + 4];
    if (quad_lane == 0) d ^= total_bytes;  // v[12]
    if (quad_lane == 2) d ^= last_block;   // v[14]

    // Spell sigma indices as immediates. Dynamic constant-memory indexing
    // serializes the four distinct lane addresses; the select below becomes
    // ordinary predicates followed by one shared-memory message load.
#define QUAD_PICK(i0, i1, i2, i3)                                           \
    message[quad_lane == 0 ? (i0) : quad_lane == 1 ? (i1)                   \
                                  : quad_lane == 2 ? (i2) : (i3)]
#define QUAD_ROUND(s0, s1, s2, s3, s4, s5, s6, s7,                         \
                   s8, s9, s10, s11, s12, s13, s14, s15) do {              \
    mix(a, b, c, d, QUAD_PICK(s0, s2, s4, s6),                             \
         QUAD_PICK(s1, s3, s5, s7));                                        \
    uint32_t diagonal_b = quad_shuffle(mask, b, (quad_lane + 1) & 3u);      \
    uint32_t diagonal_c = quad_shuffle(mask, c, (quad_lane + 2) & 3u);      \
    uint32_t diagonal_d = quad_shuffle(mask, d, (quad_lane + 3) & 3u);      \
    mix(a, diagonal_b, diagonal_c, diagonal_d,                              \
         QUAD_PICK(s8, s10, s12, s14), QUAD_PICK(s9, s11, s13, s15));      \
    b = quad_shuffle(mask, diagonal_b, (quad_lane + 3) & 3u);               \
    c = quad_shuffle(mask, diagonal_c, (quad_lane + 2) & 3u);               \
    d = quad_shuffle(mask, diagonal_d, (quad_lane + 1) & 3u);               \
} while (0)

    QUAD_ROUND(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    QUAD_ROUND(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);
    QUAD_ROUND(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4);
    QUAD_ROUND(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8);
    QUAD_ROUND(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13);
    QUAD_ROUND(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9);
    QUAD_ROUND(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11);
    QUAD_ROUND(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10);
    QUAD_ROUND(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5);
    QUAD_ROUND(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0);

#undef QUAD_ROUND
#undef QUAD_PICK

    h_low = original_low ^ a ^ c;
    h_high = original_high ^ b ^ d;
}

__device__ __forceinline__ uint32_t lifted_index(
    uint32_t leaf, uint32_t log_ratio) {
    if (log_ratio == 0) return leaf;
    return ((leaf >> (log_ratio + 1)) << 1) + (leaf & 1);
}

__global__ __launch_bounds__(kBlockThreads, STWO_BLAKE2S_QUAD_MIN_BLOCKS)
void stream_leaf_update_quad(
    uint32_t size,
    uint32_t group_columns,
    uint32_t **columns,
    const uint32_t *column_log_sizes,
    uint32_t lifting_log_size,
    uint32_t columns_done,
    Blake2sHash *states) {
    const uint32_t thread = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t leaf = thread / kQuadWidth;
    const uint32_t quad_lane = threadIdx.x & 3u;
    if (leaf >= size) return;

    const uint32_t lane_in_warp = threadIdx.x & 31u;
    const uint32_t mask = 0xFu << (lane_in_warp & ~3u);
    const uint32_t local_leaf = threadIdx.x / kQuadWidth;
    __shared__ uint32_t messages[kLeavesPerBlock][16];
    uint32_t h_low = states[leaf].s[quad_lane];
    uint32_t h_high = states[leaf].s[quad_lane + 4];
    uint32_t total_bytes = 4u * columns_done;

    for (uint32_t first = 0; first < group_columns; first += 16) {
        const uint32_t i0 = first + quad_lane;
        const uint32_t i1 = i0 + 4;
        const uint32_t i2 = i0 + 8;
        const uint32_t i3 = i0 + 12;
        const uint32_t r0 = lifting_log_size - column_log_sizes[i0];
        const uint32_t r1 = lifting_log_size - column_log_sizes[i1];
        const uint32_t r2 = lifting_log_size - column_log_sizes[i2];
        const uint32_t r3 = lifting_log_size - column_log_sizes[i3];
        const uint32_t m0 = columns[i0][lifted_index(leaf, r0)];
        const uint32_t m1 = columns[i1][lifted_index(leaf, r1)];
        const uint32_t m2 = columns[i2][lifted_index(leaf, r2)];
        const uint32_t m3 = columns[i3][lifted_index(leaf, r3)];
        messages[local_leaf][quad_lane] = m0;
        messages[local_leaf][quad_lane + 4] = m1;
        messages[local_leaf][quad_lane + 8] = m2;
        messages[local_leaf][quad_lane + 12] = m3;
        __syncwarp(mask);
        total_bytes += 64;
        compress_quad(mask, quad_lane, h_low, h_high, messages[local_leaf],
                      total_bytes, 0);
    }

    states[leaf].s[quad_lane] = h_low;
    states[leaf].s[quad_lane + 4] = h_high;
}

// One quad owns one native-domain row. The chaining value and lazy pending
// block remain distributed across its four lanes for the complete canonical
// batch; HBM sees one state read and one state write, irrespective of width.
__global__ __launch_bounds__(kBlockThreads,
                             STWO_BLAKE2S_PROGRESSIVE_QUAD_MIN_BLOCKS)
void progressive_leaf_absorb_quad(
    uint32_t size,
    uint32_t number_of_columns,
    uint32_t absorbed_columns_before,
    uint32_t **columns,
    uint32_t initializes_state,
    ProgressiveBlake2sState *states) {
    const uint32_t thread = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t row = thread / kQuadWidth;
    const uint32_t quad_lane = threadIdx.x & 3u;
    if (row >= size) return;

    const uint32_t lane_in_warp = threadIdx.x & 31u;
    const uint32_t mask = 0xFu << (lane_in_warp & ~3u);
    const uint32_t local_row = threadIdx.x / kQuadWidth;
    __shared__ uint32_t messages[kLeavesPerBlock][16];

    uint32_t h_low = initializes_state != 0
        ? kIv[quad_lane] ^ (quad_lane == 0 ? 0x01010020u : 0u)
        : states[row].h[quad_lane];
    uint32_t h_high = initializes_state != 0
        ? kIv[quad_lane + 4]
        : states[row].h[quad_lane + 4];
    #pragma unroll
    for (uint32_t word = quad_lane; word < 16; word += kQuadWidth) {
        messages[local_row][word] = initializes_state != 0
            ? 0u
            : states[row].pending[word];
    }
    __syncwarp(mask);

    uint32_t pending_words = stwo_compact_pending_words(absorbed_columns_before);
    uint32_t compressed_bytes = 4u * (absorbed_columns_before - pending_words);
    uint32_t consumed = 0;
    while (consumed < number_of_columns) {
        if (pending_words == 16) {
            compressed_bytes += 64;
            compress_quad(mask, quad_lane, h_low, h_high,
                          messages[local_row], compressed_bytes, 0);
            pending_words = 0;
            __syncwarp(mask);
        }
        const uint32_t available = 16 - pending_words;
        const uint32_t remaining = number_of_columns - consumed;
        const uint32_t fill = available < remaining ? available : remaining;
        for (uint32_t local = quad_lane; local < fill; local += kQuadWidth) {
            messages[local_row][pending_words + local] =
                columns[consumed + local][row];
        }
        __syncwarp(mask);
        pending_words += fill;
        consumed += fill;
    }

    states[row].h[quad_lane] = h_low;
    states[row].h[quad_lane + 4] = h_high;
    #pragma unroll
    for (uint32_t word = quad_lane; word < 16; word += kQuadWidth) {
        states[row].pending[word] = messages[local_row][word];
    }
}

// Compact successor to progressive_leaf_absorb_quad. The lazy block is
// reconstructed from retained evaluation columns, so only h[8] crosses an
// HBM boundary. `tail` is a by-value kernel parameter owned by the graph.
__global__ __launch_bounds__(kBlockThreads,
                             STWO_BLAKE2S_PROGRESSIVE_QUAD_MIN_BLOCKS)
void compact_leaf_absorb_quad(
    uint32_t size,
    uint32_t number_of_columns,
    uint32_t absorbed_columns_before,
    uint32_t **columns,
    uint32_t initializes_state,
    CompactBlake2sTailDescriptor tail,
    Blake2sHash *states) {
    const uint32_t thread = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t row = thread / kQuadWidth;
    const uint32_t quad_lane = threadIdx.x & 3u;
    if (row >= size) return;

    const uint32_t lane_in_warp = threadIdx.x & 31u;
    const uint32_t mask = 0xFu << (lane_in_warp & ~3u);
    const uint32_t local_row = threadIdx.x / kQuadWidth;
    __shared__ uint32_t messages[kLeavesPerBlock][16];

    uint32_t h_low = initializes_state != 0
        ? kIv[quad_lane] ^ (quad_lane == 0 ? 0x01010020u : 0u)
        : states[row].s[quad_lane];
    uint32_t h_high = initializes_state != 0
        ? kIv[quad_lane + 4]
        : states[row].s[quad_lane + 4];
    uint32_t pending_words = stwo_compact_pending_words(absorbed_columns_before);
    for (uint32_t word = quad_lane; word < pending_words;
         word += kQuadWidth) {
        const uint32_t *column = reinterpret_cast<const uint32_t *>(
            tail.column_addresses[word]);
        messages[local_row][word] =
            column[lifted_index(row, tail.log_ratios[word])];
    }
    __syncwarp(mask);

    uint32_t compressed_bytes =
        4u * (absorbed_columns_before - pending_words);
    uint32_t consumed = 0;
    while (consumed < number_of_columns) {
        if (pending_words == 16) {
            compressed_bytes += 64;
            compress_quad(mask, quad_lane, h_low, h_high,
                          messages[local_row], compressed_bytes, 0);
            pending_words = 0;
            __syncwarp(mask);
        }
        const uint32_t available = 16 - pending_words;
        const uint32_t remaining = number_of_columns - consumed;
        const uint32_t fill = available < remaining ? available : remaining;
        for (uint32_t local = quad_lane; local < fill;
             local += kQuadWidth) {
            messages[local_row][pending_words + local] =
                columns[consumed + local][row];
        }
        __syncwarp(mask);
        pending_words += fill;
        consumed += fill;
    }

    states[row].s[quad_lane] = h_low;
    states[row].s[quad_lane + 4] = h_high;
}

// Source-major expansion successor. One quad loads one source h8 exactly once,
// then emits every circle-ordered child after reconstructing its lazy tail and
// absorbing the new native-domain batch. Source and destination are disjoint.
__global__ __launch_bounds__(kBlockThreads,
                             STWO_BLAKE2S_PROGRESSIVE_QUAD_MIN_BLOCKS)
void compact_leaf_expand_absorb_quad(
    uint32_t source_size,
    uint32_t expansion,
    uint32_t number_of_columns,
    uint32_t absorbed_columns_before,
    uint32_t **columns,
    CompactBlake2sTailDescriptor tail,
    const Blake2sHash *source_states,
    Blake2sHash *destination_states) {
    const uint32_t thread = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t source_row = thread / kQuadWidth;
    const uint32_t quad_lane = threadIdx.x & 3u;
    if (source_row >= source_size) return;

    const uint32_t lane_in_warp = threadIdx.x & 31u;
    const uint32_t mask = 0xFu << (lane_in_warp & ~3u);
    const uint32_t local_row = threadIdx.x / kQuadWidth;
    __shared__ uint32_t messages[kLeavesPerBlock][16];
    const uint32_t original_low = source_states[source_row].s[quad_lane];
    const uint32_t original_high = source_states[source_row].s[quad_lane + 4];
    const uint32_t source_pair = source_row >> 1;
    const uint32_t parity = source_row & 1u;

    for (uint32_t child = 0; child < expansion; ++child) {
        // This is the inverse of lifted_index(target, log2(expansion)).
        const uint32_t target_row =
            2u * (expansion * source_pair + child) + parity;
        uint32_t h_low = original_low;
        uint32_t h_high = original_high;
        uint32_t pending_words =
            stwo_compact_pending_words(absorbed_columns_before);
        for (uint32_t word = quad_lane; word < pending_words;
             word += kQuadWidth) {
            const uint32_t *column = reinterpret_cast<const uint32_t *>(
                tail.column_addresses[word]);
            messages[local_row][word] =
                column[lifted_index(target_row, tail.log_ratios[word])];
        }
        __syncwarp(mask);

        uint32_t compressed_bytes =
            4u * (absorbed_columns_before - pending_words);
        uint32_t consumed = 0;
        while (consumed < number_of_columns) {
            if (pending_words == 16) {
                compressed_bytes += 64;
                compress_quad(mask, quad_lane, h_low, h_high,
                              messages[local_row], compressed_bytes, 0);
                pending_words = 0;
                __syncwarp(mask);
            }
            const uint32_t available = 16 - pending_words;
            const uint32_t remaining = number_of_columns - consumed;
            const uint32_t fill = available < remaining ? available : remaining;
            for (uint32_t local = quad_lane; local < fill;
                 local += kQuadWidth) {
                messages[local_row][pending_words + local] =
                    columns[consumed + local][target_row];
            }
            __syncwarp(mask);
            pending_words += fill;
            consumed += fill;
        }
        destination_states[target_row].s[quad_lane] = h_low;
        destination_states[target_row].s[quad_lane + 4] = h_high;
        __syncwarp(mask);
    }
}

// Direct retained N2B stops before the final circle butterfly. One eight-lane
// owner covers an adjacent row pair: its lower quad loads each pre-final pair
// once and stages both results, all eight lanes rendezvous, then and only then
// are the canonical retained words written. The two quads subsequently run
// the exact compact absorb stream for their respective rows.
__global__ __launch_bounds__(kBlockThreads,
                             STWO_BLAKE2S_PROGRESSIVE_QUAD_MIN_BLOCKS)
void compact_leaf_absorb_n2b_terminal_pair(
    uint32_t size,
    uint32_t number_of_columns,
    uint32_t absorbed_columns_before,
    uint32_t **prefinal_columns,
    uint32_t initializes_state,
    CompactBlake2sTailDescriptor tail,
    uint32_t *twiddles,
    uint32_t twiddle_words,
    Blake2sHash *states) {
    const uint32_t thread = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t pair = thread / kTerminalPairWidth;
    if (pair >= size / 2) return;

    const uint32_t lane_in_pair = threadIdx.x & 7u;
    const uint32_t row_in_pair = lane_in_pair / kQuadWidth;
    const uint32_t quad_lane = lane_in_pair & 3u;
    const uint32_t row = 2 * pair + row_in_pair;
    const uint32_t lane_in_warp = threadIdx.x & 31u;
    const uint32_t pair_mask = 0xffu << (lane_in_warp & ~7u);
    const uint32_t quad_mask = 0xfu << (lane_in_warp & ~3u);
    const uint32_t local_pair = threadIdx.x / kTerminalPairWidth;
    __shared__ uint32_t messages[kTerminalPairsPerBlock][2][16];

    uint32_t h_low = initializes_state != 0
        ? kIv[quad_lane] ^ (quad_lane == 0 ? 0x01010020u : 0u)
        : states[row].s[quad_lane];
    uint32_t h_high = initializes_state != 0
        ? kIv[quad_lane + 4]
        : states[row].s[quad_lane + 4];
    uint32_t pending_words = stwo_compact_pending_words(absorbed_columns_before);
    for (uint32_t word = quad_lane; word < pending_words;
         word += kQuadWidth) {
        const uint32_t *column = reinterpret_cast<const uint32_t *>(
            tail.column_addresses[word]);
        messages[local_pair][row_in_pair][word] =
            column[lifted_index(row, tail.log_ratios[word])];
    }
    __syncwarp(pair_mask);

    uint32_t compressed_bytes =
        4u * (absorbed_columns_before - pending_words);
    uint32_t consumed = 0;
    const uint32_t half_domain = size / 2;
    while (consumed < number_of_columns) {
        if (pending_words == 16) {
            compressed_bytes += 64;
            compress_quad(quad_mask, quad_lane, h_low, h_high,
                          messages[local_pair][row_in_pair], compressed_bytes, 0);
            pending_words = 0;
            __syncwarp(pair_mask);
        }
        const uint32_t available = 16 - pending_words;
        const uint32_t remaining = number_of_columns - consumed;
        const uint32_t fill = available < remaining ? available : remaining;
        for (uint32_t first = 0; first < fill; first += kQuadWidth) {
            const uint32_t local = first + quad_lane;
            if (row_in_pair == 0 && local < fill) {
                const uint32_t column_index = consumed + local;
                const StwoN2bFinalPair values = stwo_n2b_final_pair(
                    prefinal_columns[column_index], pair, half_domain,
                    twiddles, twiddle_words);
                messages[local_pair][0][pending_words + local] = values.even;
                messages[local_pair][1][pending_words + local] = values.odd;
            }
            // Ordering proof: every sibling load in this four-column tranche
            // completes before either half of the pair reaches the write.
            __syncwarp(pair_mask);
            if (local < fill) {
                prefinal_columns[consumed + local][row] =
                    messages[local_pair][row_in_pair][pending_words + local];
            }
            __syncwarp(pair_mask);
        }
        pending_words += fill;
        consumed += fill;
    }

    states[row].s[quad_lane] = h_low;
    states[row].s[quad_lane + 4] = h_high;
}

__global__ __launch_bounds__(kBlockThreads,
                             STWO_BLAKE2S_PROGRESSIVE_QUAD_MIN_BLOCKS)
void compact_leaf_finalize_quad_in_place(
    uint32_t size,
    uint32_t absorbed_columns,
    CompactBlake2sTailDescriptor tail,
    Blake2sHash *states_and_hashes) {
    const uint32_t thread = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t row = thread / kQuadWidth;
    const uint32_t quad_lane = threadIdx.x & 3u;
    if (row >= size) return;

    const uint32_t lane_in_warp = threadIdx.x & 31u;
    const uint32_t mask = 0xFu << (lane_in_warp & ~3u);
    const uint32_t local_row = threadIdx.x / kQuadWidth;
    __shared__ uint32_t messages[kLeavesPerBlock][16];
    const uint32_t pending_words = stwo_compact_pending_words(absorbed_columns);
    for (uint32_t word = quad_lane; word < 16; word += kQuadWidth) {
        if (word < pending_words) {
            const uint32_t *column = reinterpret_cast<const uint32_t *>(
                tail.column_addresses[word]);
            messages[local_row][word] =
                column[lifted_index(row, tail.log_ratios[word])];
        } else {
            messages[local_row][word] = 0;
        }
    }
    __syncwarp(mask);

    uint32_t h_low = states_and_hashes[row].s[quad_lane];
    uint32_t h_high = states_and_hashes[row].s[quad_lane + 4];
    compress_quad(mask, quad_lane, h_low, h_high, messages[local_row],
                  4u * absorbed_columns, 0xffffffffu);
    states_and_hashes[row].s[quad_lane] = h_low;
    states_and_hashes[row].s[quad_lane + 4] = h_high;
}

}  // namespace

__device__ void stwo_blake2s_init_leaf_state_quad_device(Blake2sHash *state) {
    const uint32_t quad_lane = threadIdx.x & 3u;
    state->s[quad_lane] = kIv[quad_lane]
        ^ (quad_lane == 0 ? 0x01010020u : 0u);
    state->s[quad_lane + 4] = kIv[quad_lane + 4];
}

__device__ void stwo_blake2s_compress_leaf_block_quad_device(
    Blake2sHash *state,
    const uint32_t message[16],
    uint32_t total_bytes,
    uint32_t lastblock) {
    const uint32_t quad_lane = threadIdx.x & 3u;
    const uint32_t lane_in_warp = threadIdx.x & 31u;
    const uint32_t mask = 0xFu << (lane_in_warp & ~3u);
    uint32_t h_low = state->s[quad_lane];
    uint32_t h_high = state->s[quad_lane + 4];
    compress_quad(mask, quad_lane, h_low, h_high, message,
                  total_bytes, lastblock);
    state->s[quad_lane] = h_low;
    state->s[quad_lane + 4] = h_high;
}

extern "C" int stwo_blake2s_leaf_update_quad_on(
    uint32_t size,
    uint32_t group_columns,
    uint32_t **columns,
    const uint32_t *column_log_sizes,
    uint32_t lifting_log_size,
    uint32_t columns_done,
    Blake2sHash *states,
    void *stream) {
    if (size == 0 || group_columns == 0 || (group_columns % 16) != 0 ||
        columns == nullptr || column_log_sizes == nullptr ||
        lifting_log_size >= 31 || size != (1u << lifting_log_size) ||
        (columns_done % 16) != 0 || states == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    const uint32_t blocks = (size + kLeavesPerBlock - 1) / kLeavesPerBlock;
    stream_leaf_update_quad<<<blocks, kBlockThreads, 0,
                              reinterpret_cast<cudaStream_t>(stream)>>>(
        size, group_columns, columns, column_log_sizes, lifting_log_size,
        columns_done, states);
    return cudaGetLastError();
}

extern "C" int stwo_blake2s_progressive_absorb_quad_on(
    uint32_t size,
    uint32_t number_of_columns,
    uint32_t absorbed_columns_before,
    uint32_t **columns,
    uint32_t initializes_state,
    ProgressiveBlake2sState *states,
    void *stream) {
    constexpr uint32_t kMaxCounterColumns = 0x3fffffffu;
    if (size == 0 || size > kMaxQuadRows || (size & (size - 1)) != 0 ||
        number_of_columns == 0 ||
        columns == nullptr || initializes_state > 1 ||
        (initializes_state != 0 && absorbed_columns_before != 0) ||
        number_of_columns > kMaxCounterColumns ||
        absorbed_columns_before > kMaxCounterColumns - number_of_columns ||
        states == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    const uint32_t blocks = 1 + (size - 1) / kLeavesPerBlock;
    progressive_leaf_absorb_quad<<<blocks, kBlockThreads, 0,
                                   reinterpret_cast<cudaStream_t>(stream)>>>(
        size, number_of_columns, absorbed_columns_before, columns,
        initializes_state, states);
    return cudaGetLastError();
}

extern "C" int stwo_blake2s_compact_absorb_quad_on(
    uint32_t size,
    uint32_t number_of_columns,
    uint32_t absorbed_columns_before,
    uint32_t **columns,
    uint32_t initializes_state,
    const CompactBlake2sTailDescriptor *tail,
    Blake2sHash *states,
    void *stream) {
    constexpr uint32_t kMaxCounterColumns = 0x3fffffffu;
    if (size == 0 || size > kMaxQuadRows || (size & (size - 1)) != 0 ||
        number_of_columns == 0 || columns == nullptr ||
        initializes_state > 1 ||
        ((initializes_state != 0) != (absorbed_columns_before == 0)) ||
        number_of_columns > kMaxCounterColumns ||
        absorbed_columns_before > kMaxCounterColumns - number_of_columns ||
        tail == nullptr || states == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    const CompactBlake2sTailDescriptor descriptor = *tail;
    if (!stwo_compact_tail_descriptor_valid(
            size, absorbed_columns_before, descriptor)) {
        return cudaErrorInvalidValue;
    }
    const uint32_t blocks = 1 + (size - 1) / kLeavesPerBlock;
    compact_leaf_absorb_quad<<<blocks, kBlockThreads, 0,
                               reinterpret_cast<cudaStream_t>(stream)>>>(
        size, number_of_columns, absorbed_columns_before, columns,
        initializes_state, descriptor, states);
    return cudaGetLastError();
}

extern "C" int stwo_blake2s_compact_expand_absorb_quad_on(
    uint32_t from_log_size,
    uint32_t to_log_size,
    uint32_t number_of_columns,
    uint32_t absorbed_columns_before,
    uint32_t **columns,
    const CompactBlake2sTailDescriptor *tail,
    const Blake2sHash *source_states,
    Blake2sHash *destination_states,
    void *stream) {
    constexpr uint32_t kMaxCounterColumns = 0x3fffffffu;
    if (from_log_size == 0 || from_log_size >= to_log_size ||
        to_log_size >= 31 || number_of_columns == 0 ||
        absorbed_columns_before == 0 || columns == nullptr || tail == nullptr ||
        source_states == nullptr || destination_states == nullptr ||
        stream == nullptr || number_of_columns > kMaxCounterColumns ||
        absorbed_columns_before > kMaxCounterColumns - number_of_columns) {
        return cudaErrorInvalidValue;
    }
    const uint32_t source_size = 1u << from_log_size;
    const uint32_t target_size = 1u << to_log_size;
    const uintptr_t source_begin = reinterpret_cast<uintptr_t>(source_states);
    const uintptr_t destination_begin =
        reinterpret_cast<uintptr_t>(destination_states);
    const uintptr_t source_bytes =
        static_cast<uintptr_t>(source_size) * sizeof(Blake2sHash);
    const uintptr_t destination_bytes =
        static_cast<uintptr_t>(target_size) * sizeof(Blake2sHash);
    if ((source_begin & (alignof(Blake2sHash) - 1)) != 0 ||
        (destination_begin & (alignof(Blake2sHash) - 1)) != 0 ||
        source_begin > UINTPTR_MAX - source_bytes ||
        destination_begin > UINTPTR_MAX - destination_bytes) {
        return cudaErrorInvalidValue;
    }
    const uintptr_t source_end = source_begin + source_bytes;
    const uintptr_t destination_end = destination_begin + destination_bytes;
    if (source_begin < destination_end && destination_begin < source_end) {
        return cudaErrorInvalidValue;
    }
    const CompactBlake2sTailDescriptor descriptor = *tail;
    if (!stwo_compact_tail_descriptor_valid(
            target_size, absorbed_columns_before, descriptor)) {
        return cudaErrorInvalidValue;
    }
    const uint32_t blocks = 1 + (source_size - 1) / kLeavesPerBlock;
    compact_leaf_expand_absorb_quad<<<
        blocks, kBlockThreads, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
        source_size, 1u << (to_log_size - from_log_size), number_of_columns,
        absorbed_columns_before, columns, descriptor, source_states,
        destination_states);
    return cudaGetLastError();
}

extern "C" int stwo_blake2s_compact_absorb_n2b_terminal_pair_on(
    uint32_t size,
    uint32_t number_of_columns,
    uint32_t absorbed_columns_before,
    uint32_t **prefinal_columns,
    uint32_t initializes_state,
    const CompactBlake2sTailDescriptor *tail,
    uint32_t *twiddles,
    uint32_t twiddle_words,
    Blake2sHash *states,
    void *stream) {
    constexpr uint32_t kMaxCounterColumns = 0x3fffffffu;
    if (size < 8 || size > kMaxQuadRows || (size & (size - 1)) != 0 ||
        number_of_columns == 0 || prefinal_columns == nullptr ||
        initializes_state > 1 ||
        ((initializes_state != 0) != (absorbed_columns_before == 0)) ||
        number_of_columns > kMaxCounterColumns ||
        absorbed_columns_before > kMaxCounterColumns - number_of_columns ||
        tail == nullptr || twiddles == nullptr || twiddle_words < size / 2 ||
        states == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    const CompactBlake2sTailDescriptor descriptor = *tail;
    if (!stwo_compact_tail_descriptor_valid(
            size, absorbed_columns_before, descriptor)) {
        return cudaErrorInvalidValue;
    }
    const uint32_t pairs = size / 2;
    const uint32_t blocks =
        1 + (pairs - 1) / kTerminalPairsPerBlock;
    compact_leaf_absorb_n2b_terminal_pair<<<
        blocks, kBlockThreads, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
        size, number_of_columns, absorbed_columns_before, prefinal_columns,
        initializes_state, descriptor, twiddles, twiddle_words, states);
    return cudaGetLastError();
}

extern "C" int stwo_blake2s_compact_finalize_quad_in_place_on(
    uint32_t size,
    uint32_t absorbed_columns,
    const CompactBlake2sTailDescriptor *tail,
    Blake2sHash *states_and_hashes,
    void *stream) {
    constexpr uint32_t kMaxCounterColumns = 0x3fffffffu;
    if (size == 0 || size > kMaxQuadRows || (size & (size - 1)) != 0 ||
        absorbed_columns == 0 || absorbed_columns > kMaxCounterColumns ||
        tail == nullptr || states_and_hashes == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    const CompactBlake2sTailDescriptor descriptor = *tail;
    if (!stwo_compact_tail_descriptor_valid(size, absorbed_columns, descriptor)) {
        return cudaErrorInvalidValue;
    }
    const uint32_t blocks = 1 + (size - 1) / kLeavesPerBlock;
    compact_leaf_finalize_quad_in_place<<<
        blocks, kBlockThreads, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
        size, absorbed_columns, descriptor, states_and_hashes);
    return cudaGetLastError();
}
