#ifndef STWO_ZIG_AMALGAMATED
#include "stwo_zig/base.metal"
#include "stwo_zig/blake2s.metal"
#include "stwo_zig/merkle.metal"
#include "stwo_zig/poseidon2_m31.metal"
#include "stwo_zig/extension_fields.metal"
#endif

inline Qm31Value fri_fused_fold_pair(
    Qm31Value left, Qm31Value right, uint inverse, Qm31Value alpha
) {
    return qm_add(qm_add(left, right), qm_mul(alpha, qm_mul_m31(qm_sub(left, right), inverse)));
}

inline void fri_store_coordinates_and_leaf(
    device uint *coordinates, device uint *leaves, uint value_count, uint index,
    Qm31Value value, constant uint *leaf_seed, uint prefix_bytes
) {
    coordinates[index] = value.a;
    coordinates[value_count + index] = value.b;
    coordinates[2u * value_count + index] = value.c;
    coordinates[3u * value_count + index] = value.d;

    uint state[8], message[16];
    if (prefix_bytes == 0u) blake2s_init_hash(state);
    else blake2s_init_seeded(state, leaf_seed);
    message[0] = value.a;
    message[1] = value.b;
    message[2] = value.c;
    message[3] = value.d;
    for (uint word = 4u; word < 16u; ++word) message[word] = 0u;
    blake2s_compress(state, message, prefix_bytes + 16u, true);
    for (uint word = 0u; word < 8u; ++word) leaves[index * 8u + word] = state[word];
}

// Exhaustively checks one host-selected nonce interval. The host advances to
// the next interval only after this dispatch completes with no match, so the
// result is the protocol's exact lowest nonce rather than merely any nonce.
kernel void stwo_zig_blake2s_pow_search(
    constant uint *prefix [[buffer(0)]],
    constant uint *round_zero_columns [[buffer(1)]],
    constant ulong &nonce_base [[buffer(2)]],
    constant uint &nonce_count [[buffer(3)]],
    constant uint &pow_bits [[buffer(4)]],
    device atomic_uint &first_match [[buffer(5)]],
    uint local_nonce [[thread_position_in_grid]]
) {
    if (local_nonce >= nonce_count) return;

    ulong nonce = nonce_base + (ulong)local_nonce;
    uint state[8], message[16], compression_state[16];
    for (uint word = 0u; word < 8u; ++word) message[word] = prefix[word];
    message[8] = (uint)nonce;
    message[9] = (uint)(nonce >> 32u);
    for (uint word = 10u; word < 16u; ++word) message[word] = 0u;

    // Round zero's column half consumes only prefix words 0..7. The host
    // computes it once per proof instead of every candidate thread.
    for (uint word = 0u; word < 16u; ++word)
        compression_state[word] = round_zero_columns[word];
    blake2s_g_words(message[8], message[9], compression_state[0], compression_state[5], compression_state[10], compression_state[15]);
    blake2s_g_words(message[10], message[11], compression_state[1], compression_state[6], compression_state[11], compression_state[12]);
    blake2s_g_words(message[12], message[13], compression_state[2], compression_state[7], compression_state[8], compression_state[13]);
    blake2s_g_words(message[14], message[15], compression_state[3], compression_state[4], compression_state[9], compression_state[14]);
    STWO_ZIG_BLAKE2S_ROUND(compression_state, message, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);
    STWO_ZIG_BLAKE2S_ROUND(compression_state, message, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4);
    STWO_ZIG_BLAKE2S_ROUND(compression_state, message, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8);
    STWO_ZIG_BLAKE2S_ROUND(compression_state, message, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13);
    STWO_ZIG_BLAKE2S_ROUND(compression_state, message, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9);
    STWO_ZIG_BLAKE2S_ROUND(compression_state, message, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11);
    STWO_ZIG_BLAKE2S_ROUND(compression_state, message, 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10);
    STWO_ZIG_BLAKE2S_ROUND(compression_state, message, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5);
    STWO_ZIG_BLAKE2S_ROUND(compression_state, message, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0);
    blake2s_init_hash(state);
    for (uint word = 0u; word < 8u; ++word)
        state[word] ^= compression_state[word] ^ compression_state[word + 8u];

    uint zero_bits = 0u;
    for (uint word = 0u; word < 8u; ++word) {
        if (state[word] == 0u) {
            zero_bits += 32u;
            continue;
        }
        zero_bits += ctz(state[word]);
        break;
    }
    if (zero_bits >= pow_bits)
        atomic_fetch_min_explicit(&first_match, local_nonce, memory_order_relaxed);
}

kernel void stwo_zig_qm31_to_coordinates(
    device const Qm31Value *source [[buffer(0)]],
    device uint *coordinates [[buffer(1)]],
    constant uint &value_count [[buffer(2)]],
    device uint *leaves [[buffer(3)]],
    constant uint *leaf_seed [[buffer(4)]],
    constant uint &prefix_bytes [[buffer(5)]],
    constant uint &write_leaf [[buffer(6)]],
    uint index [[thread_position_in_grid]]
) {
    if (index >= value_count) return;
    Qm31Value value = source[index];
    if (write_leaf != 0u)
        fri_store_coordinates_and_leaf(
            coordinates, leaves, value_count, index, value, leaf_seed, prefix_bytes
        );
    else {
        coordinates[index] = value.a;
        coordinates[value_count + index] = value.b;
        coordinates[2u * value_count + index] = value.c;
        coordinates[3u * value_count + index] = value.d;
    }
}

kernel void stwo_zig_fri_fold_line(
    device const Qm31Value *source [[buffer(0)]],
    device const uint *inverse_x [[buffer(1)]],
    constant Qm31Value &alpha [[buffer(2)]],
    device Qm31Value *destination [[buffer(3)]],
    constant uint &destination_count [[buffer(4)]],
    device uint *coordinates [[buffer(5)]],
    device uint *leaves [[buffer(6)]],
    constant uint *leaf_seed [[buffer(7)]],
    constant uint &prefix_bytes [[buffer(8)]],
    constant uint &prepare_next [[buffer(9)]],
    uint index [[thread_position_in_grid]]
) {
    if (index >= destination_count) return;
    Qm31Value value = fri_fused_fold_pair(
        source[index << 1u], source[(index << 1u) + 1u], inverse_x[index], alpha
    );
    destination[index] = value;
    if (prepare_next != 0u)
        fri_store_coordinates_and_leaf(
            coordinates, leaves, destination_count, index, value, leaf_seed, prefix_bytes
        );
}

kernel void stwo_zig_blake2s_leaves(
    device const uint *flat_columns [[buffer(0)]],
    device const uint *column_offsets [[buffer(1)]],
    device const uint *column_log_sizes [[buffer(2)]],
    device uint *destination [[buffer(3)]],
    constant uint &column_count [[buffer(4)]],
    constant uint &lifting_log_size [[buffer(5)]],
    constant uint *leaf_seed [[buffer(6)]],
    constant uint &prefix_bytes [[buffer(7)]],
    uint row [[thread_position_in_grid]]
) {
    uint row_count = 1u << lifting_log_size;
    if (row >= row_count) return;

    uint state[8];
    if (prefix_bytes == 0u) blake2s_init_hash(state);
    else blake2s_init_seeded(state, leaf_seed);

    uint message[16];
    uint full_blocks = column_count >> 4u;
    uint remainder = column_count & 15u;
    for (uint block = 0u; block < full_blocks; ++block) {
        uint first_column = block << 4u;
        for (uint word = 0u; word < 16u; ++word) {
            uint column = first_column + word;
            uint log_size = column_log_sizes[column];
            uint source = lifted_index(row, lifting_log_size - log_size);
            message[word] = flat_columns[column_offsets[column] + source];
        }
        bool last = remainder == 0u && block + 1u == full_blocks;
        blake2s_compress(state, message, prefix_bytes + (first_column + 16u) * 4u, last);
    }
    if (remainder != 0u) {
        uint first_column = full_blocks << 4u;
        for (uint word = 0u; word < remainder; ++word) {
            uint column = first_column + word;
            uint log_size = column_log_sizes[column];
            uint source = lifted_index(row, lifting_log_size - log_size);
            message[word] = flat_columns[column_offsets[column] + source];
        }
        for (uint word = remainder; word < 16u; ++word) message[word] = 0u;
        blake2s_compress(state, message, prefix_bytes + column_count * 4u, true);
    }
    uint base = row * 8u;
    for (uint i = 0; i < 8u; ++i) destination[base + i] = state[i];
}

kernel void stwo_zig_blake2s_leaf_absorb_resident(
    device uint *arena [[buffer(0)]], constant uint *column_offsets [[buffer(1)]],
    constant uint *column_logs [[buffer(2)]], constant uint &column_count [[buffer(3)]],
    constant uint &state_offset [[buffer(4)]], constant uint &lifting_log [[buffer(5)]],
    constant uint &first_column [[buffer(6)]], constant uint &is_final [[buffer(7)]],
    constant uint &prefix_bytes [[buffer(8)]], constant uint *leaf_seed [[buffer(9)]],
    uint row [[thread_position_in_grid]]
) {
    uint row_count = 1u << lifting_log;
    if (row >= row_count || column_count == 0u || column_count > 16u) return;
    uint state[8], message[16];
    if (first_column == 0u) {
        if (prefix_bytes == 0u) blake2s_init_hash(state);
        else blake2s_init_seeded(state, leaf_seed);
    }
    else for (uint i = 0u; i < 8u; ++i) state[i] = arena[state_offset + row * 8u + i];
    for (uint i = 0u; i < column_count; ++i)
        message[i] = arena[column_offsets[i] + lifted_index(row, lifting_log - column_logs[i])];
    for (uint i = column_count; i < 16u; ++i) message[i] = 0u;
    blake2s_compress(state, message, prefix_bytes + (first_column + column_count) * 4u, is_final != 0u);
    for (uint i = 0u; i < 8u; ++i) arena[state_offset + row * 8u + i] = state[i];
}

kernel void stwo_zig_blake2s_leaf_absorb_compact_resident(
    device uint *arena [[buffer(0)]], constant uint *column_offsets [[buffer(1)]],
    constant uint *column_logs [[buffer(2)]], constant uint &column_count [[buffer(3)]],
    constant uint &source_state_offset [[buffer(4)]], constant uint &source_state_log [[buffer(5)]],
    constant uint &destination_state_offset [[buffer(6)]], constant uint &destination_log [[buffer(7)]],
    constant uint &first_column [[buffer(8)]], constant uint &is_final [[buffer(9)]],
    constant uint &prefix_bytes [[buffer(10)]], constant uint *leaf_seed [[buffer(11)]],
    uint row [[thread_position_in_grid]]
) {
    uint row_count = 1u << destination_log;
    if (row >= row_count || column_count == 0u || column_count > 16u) return;
    uint state[8], message[16];
    if (first_column == 0u) {
        if (prefix_bytes == 0u) blake2s_init_hash(state);
        else blake2s_init_seeded(state, leaf_seed);
    } else {
        uint source_row = lifted_index(row, destination_log - source_state_log);
        for (uint i = 0u; i < 8u; ++i)
            state[i] = arena[source_state_offset + source_row * 8u + i];
    }
    for (uint i = 0u; i < column_count; ++i)
        message[i] = arena[column_offsets[i] + lifted_index(row, destination_log - column_logs[i])];
    for (uint i = column_count; i < 16u; ++i) message[i] = 0u;
    blake2s_compress(state, message, prefix_bytes + (first_column + column_count) * 4u, is_final != 0u);
    for (uint i = 0u; i < 8u; ++i)
        arena[destination_state_offset + row * 8u + i] = state[i];
}

kernel void stwo_zig_blake2s_parents(
    device const uint *children [[buffer(0)]],
    device uint *destination [[buffer(1)]],
    constant uint &parent_count [[buffer(2)]],
    constant uint *node_seed [[buffer(3)]],
    constant uint &prefix_bytes [[buffer(4)]],
    uint parent [[thread_position_in_grid]]
) {
    if (parent >= parent_count) return;
    uint state[8];
    uint message[16];
    if (prefix_bytes == 0u) blake2s_init_hash(state);
    else blake2s_init_seeded(state, node_seed);
    for (uint i = 0; i < 16u; ++i) message[i] = children[parent * 16u + i];
    blake2s_compress(state, message, prefix_bytes + 64u, true);
    for (uint i = 0; i < 8u; ++i) destination[parent * 8u + i] = state[i];
}

kernel void stwo_zig_blake2s_parents_sparse(
    device uint *arena [[buffer(0)]], constant uint &child_offset [[buffer(1)]],
    constant uint &destination_offset [[buffer(2)]], constant uint &parent_count [[buffer(3)]],
    constant uint *node_seed [[buffer(4)]], constant uint &prefix_bytes [[buffer(5)]],
    uint parent [[thread_position_in_grid]]
) {
    if (parent >= parent_count) return;
    uint state[8], message[16];
    if (prefix_bytes == 0u) blake2s_init_hash(state);
    else blake2s_init_seeded(state, node_seed);
    for (uint i = 0; i < 16u; ++i) message[i] = arena[child_offset + parent * 16u + i];
    blake2s_compress(state, message, prefix_bytes + 64u, true);
    for (uint i = 0; i < 8u; ++i) arena[destination_offset + parent * 8u + i] = state[i];
}

kernel void stwo_zig_poseidon2_m31_leaves(
    device const uint *flat_columns [[buffer(0)]],
    device const uint *column_offsets [[buffer(1)]],
    device const uint *column_log_sizes [[buffer(2)]],
    device uint *destination [[buffer(3)]],
    constant uint &column_count [[buffer(4)]],
    constant uint &lifting_log_size [[buffer(5)]],
    constant uint *unused_leaf_seed [[buffer(6)]],
    constant uint &unused_prefix_bytes [[buffer(7)]],
    uint row [[thread_position_in_grid]]
) {
    (void)unused_leaf_seed;
    (void)unused_prefix_bytes;
    uint row_count = 1u << lifting_log_size;
    if (row >= row_count) return;
    uint state[16];
    uint filled = 0u;
    stwo_zig_poseidon2_leaf_init(state);
    for (uint column = 0u; column < column_count; ++column) {
        uint log_size = column_log_sizes[column];
        uint source = lifted_index(row, lifting_log_size - log_size);
        stwo_zig_poseidon2_leaf_absorb(
            state, filled, flat_columns[column_offsets[column] + source]
        );
    }
    stwo_zig_poseidon2_leaf_finish(state, filled);
    uint base = row * 8u;
    for (uint lane = 0u; lane < 8u; ++lane) destination[base + lane] = state[lane];
}

// Direct commitments may alias a proof-owned heterogeneous column arena whose
// total span is larger than 2^32 M31 words.  Keep the established u32 kernel
// for compact resident arenas, and widen only the immutable column offsets for
// this direct path.  Row, log-size, and hash-layer indices remain u32 because
// every individual column and Merkle layer is still protocol-bounded below
// log 31.
kernel void stwo_zig_poseidon2_m31_leaves_wide(
    device const uint *flat_columns [[buffer(0)]],
    device const ulong *column_offsets [[buffer(1)]],
    device const uint *column_log_sizes [[buffer(2)]],
    device uint *destination [[buffer(3)]],
    constant uint &column_count [[buffer(4)]],
    constant uint &lifting_log_size [[buffer(5)]],
    constant uint *unused_leaf_seed [[buffer(6)]],
    constant uint &unused_prefix_bytes [[buffer(7)]],
    uint row [[thread_position_in_grid]]
) {
    (void)unused_leaf_seed;
    (void)unused_prefix_bytes;
    uint row_count = 1u << lifting_log_size;
    if (row >= row_count) return;
    uint state[16];
    uint filled = 0u;
    stwo_zig_poseidon2_leaf_init(state);
    for (uint column = 0u; column < column_count; ++column) {
        uint log_size = column_log_sizes[column];
        uint source = lifted_index(row, lifting_log_size - log_size);
        stwo_zig_poseidon2_leaf_absorb(
            state, filled, flat_columns[column_offsets[column] + ulong(source)]
        );
    }
    stwo_zig_poseidon2_leaf_finish(state, filled);
    uint base = row * 8u;
    for (uint lane = 0u; lane < 8u; ++lane) destination[base + lane] = state[lane];
}

kernel void stwo_zig_poseidon2_m31_leaf_absorb_resident(
    device uint *arena [[buffer(0)]], constant uint *column_offsets [[buffer(1)]],
    constant uint *column_logs [[buffer(2)]], constant uint &column_count [[buffer(3)]],
    constant uint &state_offset [[buffer(4)]], constant uint &lifting_log [[buffer(5)]],
    constant uint &first_column [[buffer(6)]], constant uint &is_final [[buffer(7)]],
    constant uint &unused_prefix_bytes [[buffer(8)]], constant uint *unused_leaf_seed [[buffer(9)]],
    uint row [[thread_position_in_grid]]
) {
    (void)unused_prefix_bytes;
    (void)unused_leaf_seed;
    uint row_count = 1u << lifting_log;
    if (row >= row_count || column_count == 0u || column_count > 16u) return;
    uint state[16];
    uint filled = first_column & 7u;
    if (first_column == 0u) stwo_zig_poseidon2_leaf_init(state);
    else for (uint lane = 0u; lane < 16u; ++lane)
        state[lane] = arena[state_offset + row * 16u + lane];
    for (uint column = 0u; column < column_count; ++column) {
        uint source = lifted_index(row, lifting_log - column_logs[column]);
        stwo_zig_poseidon2_leaf_absorb(
            state, filled, arena[column_offsets[column] + source]
        );
    }
    if (is_final != 0u) stwo_zig_poseidon2_leaf_finish(state, filled);
    for (uint lane = 0u; lane < 16u; ++lane)
        arena[state_offset + row * 16u + lane] = state[lane];
}

kernel void stwo_zig_poseidon2_m31_leaf_absorb_compact_resident(
    device uint *arena [[buffer(0)]], constant uint *column_offsets [[buffer(1)]],
    constant uint *column_logs [[buffer(2)]], constant uint &column_count [[buffer(3)]],
    constant uint &source_state_offset [[buffer(4)]], constant uint &source_state_log [[buffer(5)]],
    constant uint &destination_state_offset [[buffer(6)]], constant uint &destination_log [[buffer(7)]],
    constant uint &first_column [[buffer(8)]], constant uint &is_final [[buffer(9)]],
    constant uint &unused_prefix_bytes [[buffer(10)]], constant uint *unused_leaf_seed [[buffer(11)]],
    uint row [[thread_position_in_grid]]
) {
    (void)unused_prefix_bytes;
    (void)unused_leaf_seed;
    uint row_count = 1u << destination_log;
    if (row >= row_count || column_count == 0u || column_count > 16u) return;
    uint state[16];
    uint filled = first_column & 7u;
    if (first_column == 0u) stwo_zig_poseidon2_leaf_init(state);
    else {
        uint source_row = lifted_index(row, destination_log - source_state_log);
        for (uint lane = 0u; lane < 16u; ++lane)
            state[lane] = arena[source_state_offset + source_row * 16u + lane];
    }
    for (uint column = 0u; column < column_count; ++column) {
        uint source = lifted_index(row, destination_log - column_logs[column]);
        stwo_zig_poseidon2_leaf_absorb(
            state, filled, arena[column_offsets[column] + source]
        );
    }
    if (is_final != 0u) stwo_zig_poseidon2_leaf_finish(state, filled);
    for (uint lane = 0u; lane < 16u; ++lane)
        arena[destination_state_offset + row * 16u + lane] = state[lane];
}

// ABI22 terminal for staged Poseidon leaf hashing.  The absorb kernels retain
// the complete 16-word permutation state so a later, larger-log group can lift
// it without rereading earlier columns.  Only a final state (the last absorb
// was encoded with is_final=1) may be packed into the canonical 8-word leaf
// digest consumed by the unchanged parent kernels.
kernel void stwo_zig_poseidon2_m31_leaf_state_digest_resident_v1(
    device uint *arena [[buffer(0)]],
    constant uint &state_offset [[buffer(1)]],
    constant uint &destination_offset [[buffer(2)]],
    constant uint &lifting_log [[buffer(3)]],
    uint row [[thread_position_in_grid]]
) {
    uint row_count = 1u << lifting_log;
    if (row >= row_count) return;
    for (uint lane = 0u; lane < 8u; ++lane)
        arena[destination_offset + row * 8u + lane] =
            arena[state_offset + row * 16u + lane];
}

kernel void stwo_zig_poseidon2_m31_parents(
    device const uint *children [[buffer(0)]],
    device uint *destination [[buffer(1)]],
    constant uint &parent_count [[buffer(2)]],
    constant uint *unused_node_seed [[buffer(3)]],
    constant uint &unused_prefix_bytes [[buffer(4)]],
    uint parent [[thread_position_in_grid]]
) {
    (void)unused_node_seed;
    (void)unused_prefix_bytes;
    if (parent >= parent_count) return;
    uint child_words[16], digest[8];
    for (uint lane = 0u; lane < 16u; ++lane)
        child_words[lane] = children[parent * 16u + lane];
    stwo_zig_poseidon2_parent(child_words, digest);
    for (uint lane = 0u; lane < 8u; ++lane)
        destination[parent * 8u + lane] = digest[lane];
}

kernel void stwo_zig_poseidon2_m31_parents_sparse(
    device uint *arena [[buffer(0)]], constant uint &child_offset [[buffer(1)]],
    constant uint &destination_offset [[buffer(2)]], constant uint &parent_count [[buffer(3)]],
    constant uint *unused_node_seed [[buffer(4)]], constant uint &unused_prefix_bytes [[buffer(5)]],
    uint parent [[thread_position_in_grid]]
) {
    (void)unused_node_seed;
    (void)unused_prefix_bytes;
    if (parent >= parent_count) return;
    uint child_words[16], digest[8];
    for (uint lane = 0u; lane < 16u; ++lane)
        child_words[lane] = arena[child_offset + parent * 16u + lane];
    stwo_zig_poseidon2_parent(child_words, digest);
    for (uint lane = 0u; lane < 8u; ++lane)
        arena[destination_offset + parent * 8u + lane] = digest[lane];
}

kernel void stwo_zig_blake2s_parents_plain_sparse(
    device uint *arena [[buffer(0)]], constant uint &child_offset [[buffer(1)]],
    constant uint &destination_offset [[buffer(2)]], constant uint &parent_count [[buffer(3)]],
    uint parent [[thread_position_in_grid]]
) {
    if (parent >= parent_count) return;
    uint state[8], message[16]; blake2s_init_hash(state);
    for (uint i = 0u; i < 16u; ++i) message[i] = arena[child_offset + parent * 16u + i];
    blake2s_compress(state, message, 64u, true);
    for (uint i = 0u; i < 8u; ++i) arena[destination_offset + parent * 8u + i] = state[i];
}
