#ifndef STWO_NTT_COMPACT_LEAF_H
#define STWO_NTT_COMPACT_LEAF_H

#include "blake2s.cuh"

DEVICE_FORCEINLINE unsigned stwo_compact_lifted_index(
    unsigned row, unsigned log_ratio) {
    return log_ratio == 0
        ? row
        : ((row >> (log_ratio + 1)) << 1) + (row & 1);
}

// One aligned quad owns one row. `message` is the current register-produced
// canonical 16-column tile; `scratch` is a quad-private shared-memory block.
// The lazy prefix is read only at a boundary where no register copy exists.
DEVICE_FORCEINLINE void stwo_compact_consume_final16_quad(
    Blake2sHash *states,
    unsigned row,
    const uint32_t message[16],
    m31 **values,
    uint32_t tile,
    uint32_t cols_done,
    CompactBlake2sTailDescriptor initial_tail,
    uint32_t scratch[16]
) {
    const uint32_t quad_lane = threadIdx.x & 3u;
    const uint32_t lane_in_warp = threadIdx.x & 31u;
    const uint32_t mask = 0xFu << (lane_in_warp & ~3u);
    const uint32_t prior_columns = cols_done + 16u * tile;
    uint32_t pending = stwo_compact_pending_words(prior_columns);
    for (uint32_t word = quad_lane; word < pending; word += 4) {
        if (tile == 0) {
            const uint32_t *column = reinterpret_cast<const uint32_t *>(
                initial_tail.column_addresses[word]);
            scratch[word] = column[stwo_compact_lifted_index(
                row, initial_tail.log_ratios[word])];
        } else {
            const uint32_t first = 16u - pending;
            scratch[word] = values[(tile - 1) * 16 + first + word][row];
        }
    }
    __syncwarp(mask);
    if (prior_columns == 0) {
        stwo_blake2s_init_leaf_state_quad_device(&states[row]);
    }

    uint32_t compressed_bytes = 4u * (prior_columns - pending);
    uint32_t consumed = 0;
    while (consumed < 16) {
        if (pending == 16) {
            compressed_bytes += 64;
            stwo_blake2s_compress_leaf_block_quad_device(
                &states[row], scratch, compressed_bytes, 0u);
            pending = 0;
            __syncwarp(mask);
        }
        const uint32_t available = 16u - pending;
        const uint32_t remaining = 16u - consumed;
        const uint32_t fill = available < remaining ? available : remaining;
        for (uint32_t local = quad_lane; local < fill; local += 4) {
            scratch[pending + local] = message[consumed + local];
        }
        __syncwarp(mask);
        pending += fill;
        consumed += fill;
    }
}

#endif
