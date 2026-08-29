#ifndef STWO_ZIG_AMALGAMATED
#include "stwo_zig/base.metal"
#include "stwo_zig/blake2s.metal"
#include "stwo_zig/merkle.metal"
#include "stwo_zig/decommit.metal"
#endif

/// Canonicalizes the transcript's raw query positions once. Query counts are
/// protocol constants, so a serial insertion sort is faster than allocating a
/// device radix-sort workspace and keeps the prepared graph pointer-stable.
kernel void stwo_zig_decommit_normalize_queries_resident(
    device uint *arena [[buffer(0)]],
    constant ulong &raw_base [[buffer(1)]],
    constant uint &raw_count [[buffer(2)]],
    constant uint &log_domain_size [[buffer(3)]],
    constant ulong &unique_base [[buffer(4)]],
    constant ulong &unique_count_base [[buffer(5)]],
    constant uint &tree_count [[buffer(6)]],
    constant ulong &assembly_base [[buffer(7)]],
    constant uint &assembly_capacity [[buffer(8)]],
    uint lane [[thread_position_in_grid]]
) {
    if (lane != 0u) return;
    uint mask = (1u << log_domain_size) - 1u;
    for (uint i = 0u; i < raw_count; ++i) arena[unique_base + i] = arena[raw_base + i] & mask;
    uint unique_count = decommit_sort_unique(arena + unique_base, raw_count);
    arena[unique_count_base] = unique_count;
    uint raw_offset = 8u + tree_count * 16u;
    uint unique_offset = raw_offset + raw_count;
    uint used = unique_offset + unique_count;
    if (used > assembly_capacity) {
        arena[assembly_base + 7u] = 0u;
        return;
    }
    arena[assembly_base] = 0x44575453u;
    arena[assembly_base + 1u] = 1u;
    arena[assembly_base + 2u] = tree_count;
    arena[assembly_base + 3u] = raw_count;
    arena[assembly_base + 4u] = unique_count;
    arena[assembly_base + 5u] = raw_offset;
    arena[assembly_base + 6u] = unique_offset;
    arena[assembly_base + 7u] = used;
    for (uint i = 0u; i < tree_count * 16u; ++i) arena[assembly_base + 8u + i] = 0u;
    for (uint i = 0u; i < raw_count; ++i) arena[assembly_base + raw_offset + i] = arena[raw_base + i] & mask;
    for (uint i = 0u; i < unique_count; ++i) arena[assembly_base + unique_offset + i] = arena[unique_base + i];
}

kernel void stwo_zig_decommit_prepare_fri_queries_resident(
    device uint *arena [[buffer(0)]],
    constant ulong &unique_base [[buffer(1)]],
    constant ulong &unique_count_base [[buffer(2)]],
    constant uint &max_queries [[buffer(3)]],
    constant uint &cumulative_fold [[buffer(4)]],
    constant uint &fold_step [[buffer(5)]],
    constant uint &packed_log [[buffer(6)]],
    constant ulong &tree_queries_base [[buffer(7)]],
    constant ulong &tree_count_base [[buffer(8)]],
    constant ulong &expanded_base [[buffer(9)]],
    constant ulong &expanded_count_base [[buffer(10)]],
    constant ulong &walk_base [[buffer(11)]],
    constant ulong &walk_count_base [[buffer(12)]],
    uint lane [[thread_position_in_grid]]
) {
    if (lane != 0u) return;
    uint count = min(arena[unique_count_base], max_queries);
    for (uint i = 0u; i < count; ++i) arena[tree_queries_base + i] = arena[unique_base + i] >> cumulative_fold;
    uint queries = decommit_sort_unique(arena + tree_queries_base, count);
    arena[tree_count_base] = queries;
    uint out = 0u, previous_coset = 0xffffffffu, coset_size = 1u << fold_step;
    for (uint i = 0u; i < queries; ++i) {
        uint coset = arena[tree_queries_base + i] >> fold_step;
        if (coset == previous_coset) continue;
        previous_coset = coset;
        uint start = coset << fold_step;
        for (uint j = 0u; j < coset_size; ++j) arena[expanded_base + out++] = start + j;
    }
    arena[expanded_count_base] = out;
    for (uint i = 0u; i < out; ++i) arena[walk_base + i] = arena[expanded_base + i] >> packed_log;
    arena[walk_count_base] = decommit_sort_unique(arena + walk_base, out);
}

kernel void stwo_zig_decommit_prepare_trace_queries_resident(
    device uint *arena [[buffer(0)]],
    constant ulong &unique_base [[buffer(1)]],
    constant ulong &unique_count_base [[buffer(2)]],
    constant uint &max_queries [[buffer(3)]],
    constant uint &source_log [[buffer(4)]],
    constant uint &tree_log [[buffer(5)]],
    constant uint &leaf_log [[buffer(6)]],
    constant uint &unretained [[buffer(7)]],
    constant ulong &mapped_base [[buffer(8)]],
    constant ulong &mapped_count_base [[buffer(9)]],
    constant ulong &walk_base [[buffer(10)]],
    constant ulong &walk_count_base [[buffer(11)]],
    constant ulong &leaf_indices_base [[buffer(12)]],
    constant ulong &leaf_count_base [[buffer(13)]],
    uint lane [[thread_position_in_grid]]
) {
    if (lane != 0u) return;
    uint count = min(arena[unique_count_base], max_queries);
    for (uint i = 0u; i < count; ++i) {
        arena[mapped_base + i] = decommit_map_query_log(arena[unique_base + i], source_log, tree_log);
        arena[walk_base + i] = arena[mapped_base + i];
    }
    arena[mapped_count_base] = count;
    uint dedup = decommit_sort_unique(arena + walk_base, count);
    arena[walk_count_base] = dedup;
    if (unretained == 0u) { arena[leaf_count_base] = 0u; return; }
    uint span = 1u << unretained, leaves = 0u;
    for (uint i = 0u; i < dedup; ++i) {
        uint base = (arena[walk_base + i] >> unretained) << unretained;
        for (uint j = 0u; j < span; ++j) arena[leaf_indices_base + leaves++] = base + j;
    }
    arena[leaf_count_base] = decommit_sort_unique(arena + leaf_indices_base, leaves);
    (void)leaf_log;
}

kernel void stwo_zig_decommit_gather_trace_values_resident(
    device uint *arena [[buffer(0)]],
    constant ulong &column_offsets_base [[buffer(1)]],
    constant ulong &column_logs_base [[buffer(2)]],
    constant uint &column_count [[buffer(3)]],
    constant uint &lifting_log [[buffer(4)]],
    constant ulong &queries_base [[buffer(5)]],
    constant ulong &query_count_base [[buffer(6)]],
    constant uint &max_queries [[buffer(7)]],
    constant uint &first_column [[buffer(8)]],
    constant uint &stride [[buffer(9)]],
    constant ulong &output_base [[buffer(10)]],
    uint3 grid_position [[thread_position_in_grid]]
) {
    uint query = grid_position.x, column = grid_position.y;
    if (column >= column_count || query >= min(arena[query_count_base], max_queries)) return;
    uint row = decommit_lifted_index(arena[queries_base + query], lifting_log, arena[column_logs_base + column]);
    ulong source = decommit_wide_word_offset(arena, column_offsets_base, column);
    uint value = arena[source + ulong(row)];
    arena[output_base + (first_column + column) * stride + query] = value < 0x7fffffffu ? value : value % 0x7fffffffu;
}

/// Gathers lifted trace openings directly from an immutable resident Merkle
/// column arena. Unlike the proof-assembly kernel above, metadata and output
/// have independent buffers so an already-published tree needs no writable
/// tail or copy solely to expose its queried values to the host proof object.
kernel void stwo_zig_decommit_gather_tree_values_resident(
    device const uint *columns [[buffer(0)]],
    constant uint *column_offsets [[buffer(1)]],
    constant uint *column_logs [[buffer(2)]],
    constant uint &column_count [[buffer(3)]],
    constant uint &lifting_log [[buffer(4)]],
    constant uint *queries [[buffer(5)]],
    constant uint &query_count [[buffer(6)]],
    device uint *output [[buffer(7)]],
    uint3 grid_position [[thread_position_in_grid]]
) {
    uint query = grid_position.x, column = grid_position.y;
    if (column >= column_count || query >= query_count) return;
    uint row = decommit_lifted_index(queries[query], lifting_log, column_logs[column]);
    output[column * query_count + query] = columns[column_offsets[column] + row];
}

kernel void stwo_zig_decommit_gather_fri_values_resident(
    device uint *arena [[buffer(0)]],
    constant uint *coordinate_bases [[buffer(1)]],
    constant ulong &positions_base [[buffer(2)]],
    constant ulong &count_base [[buffer(3)]],
    constant uint &max_positions [[buffer(4)]],
    constant ulong &values_base [[buffer(5)]],
    uint index [[thread_position_in_grid]]
) {
    if (index >= min(arena[count_base], max_positions)) return;
    uint position = arena[positions_base + index];
    for (uint coordinate = 0u; coordinate < 4u; ++coordinate) {
        ulong source = decommit_join_word_offset(
            coordinate_bases[2u * coordinate],
            coordinate_bases[2u * coordinate + 1u]
        );
        uint value = arena[source + ulong(position)];
        arena[values_base + 4u * index + coordinate] = value < 0x7fffffffu ? value : value % 0x7fffffffu;
    }
}

kernel void stwo_zig_decommit_sparse_parent_resident(
    device uint *arena [[buffer(0)]], constant ulong &child_indices [[buffer(1)]],
    constant ulong &child_hashes [[buffer(2)]], constant ulong &child_count_at [[buffer(3)]],
    constant uint &max_child_count [[buffer(4)]], constant ulong &parent_indices [[buffer(5)]],
    constant ulong &parent_hashes [[buffer(6)]], constant ulong &parent_count_at [[buffer(7)]],
    constant uint *node_seed [[buffer(8)]], constant uint &prefix_bytes [[buffer(9)]],
    uint parent [[thread_position_in_grid]]
) {
    uint count = min(arena[child_count_at], max_child_count), parents = count >> 1u;
    if (parent == 0u) arena[parent_count_at] = parents;
    if (parent >= parents) return;
    uint left = 2u * parent;
    arena[parent_indices + parent] = arena[child_indices + left] >> 1u;
    uint state[8], message[16];
    if (prefix_bytes == 0u) blake2s_init_hash(state);
    else blake2s_init_seeded(state, node_seed);
    for (uint i = 0u; i < 16u; ++i) message[i] = arena[child_hashes + left * 8u + i];
    blake2s_compress(state, message, prefix_bytes + 64u, true);
    for (uint i = 0u; i < 8u; ++i) arena[parent_hashes + parent * 8u + i] = state[i];
}

kernel void stwo_zig_decommit_sparse_leaves_resident(
    device uint *arena [[buffer(0)]], constant ulong &column_offsets [[buffer(1)]],
    constant ulong &column_logs [[buffer(2)]], constant uint &column_count [[buffer(3)]],
    constant uint &lifting_log [[buffer(4)]], constant ulong &leaf_indices [[buffer(5)]],
    constant ulong &leaf_count_at [[buffer(6)]], constant uint &max_leaf_count [[buffer(7)]],
    constant ulong &output_hashes [[buffer(8)]], constant uint *leaf_seed [[buffer(9)]],
    constant uint &prefix_bytes [[buffer(10)]],
    uint sparse_index [[thread_position_in_grid]]
) {
    uint count = min(arena[leaf_count_at], max_leaf_count);
    if (sparse_index >= count) return;
    uint position = arena[leaf_indices + sparse_index];
    uint state[8], message[16], in_block = 0u, total_bytes = prefix_bytes;
    if (prefix_bytes == 0u) blake2s_init_hash(state);
    else blake2s_init_seeded(state, leaf_seed);
    for (uint column = 0u; column < column_count; ++column) {
        uint log_size = arena[column_logs + column];
        uint row = decommit_lifted_index(position, lifting_log, log_size);
        ulong source = decommit_wide_word_offset(arena, column_offsets, column);
        message[in_block++] = arena[source + ulong(row)];
        total_bytes += 4u;
        if (in_block == 16u) {
            blake2s_compress(state, message, total_bytes, column + 1u == column_count);
            in_block = 0u;
        }
    }
    if (in_block != 0u) {
        for (uint i = in_block; i < 16u; ++i) message[i] = 0u;
        blake2s_compress(state, message, total_bytes, true);
    }
    for (uint i = 0u; i < 8u; ++i) arena[output_hashes + sparse_index * 8u + i] = state[i];
}

/// Streams one block-aligned trace-column group into each sparse leaf hash.
/// Full groups contain 16 columns; only the final group may be shorter. The
/// Blake2s counter is global across groups, so this is byte-for-byte identical
/// to hashing all trace columns in one invocation.
kernel void stwo_zig_decommit_sparse_leaf_group_resident(
    device uint *arena [[buffer(0)]], constant ulong &column_offsets [[buffer(1)]],
    constant ulong &column_logs [[buffer(2)]], constant uint &column_count [[buffer(3)]],
    constant uint &first_column [[buffer(4)]], constant uint &total_columns [[buffer(5)]],
    constant uint &lifting_log [[buffer(6)]], constant ulong &leaf_indices [[buffer(7)]],
    constant ulong &leaf_count_at [[buffer(8)]], constant uint &max_leaf_count [[buffer(9)]],
    constant ulong &output_hashes [[buffer(10)]], constant uint *leaf_seed [[buffer(11)]],
    constant uint &prefix_bytes [[buffer(12)]],
    uint sparse_index [[thread_position_in_grid]]
) {
    uint count = min(arena[leaf_count_at], max_leaf_count);
    if (sparse_index >= count) return;
    uint position = arena[leaf_indices + sparse_index];
    uint state[8], message[16], in_block = 0u;
    if (first_column == 0u) {
        if (prefix_bytes == 0u) blake2s_init_hash(state);
        else blake2s_init_seeded(state, leaf_seed);
    } else {
        for (uint i = 0u; i < 8u; ++i) state[i] = arena[output_hashes + sparse_index * 8u + i];
    }
    uint total_bytes = prefix_bytes + first_column * 4u;
    for (uint column = 0u; column < column_count; ++column) {
        uint log_size = arena[column_logs + column];
        uint row = decommit_lifted_index(position, lifting_log, log_size);
        ulong source = decommit_wide_word_offset(arena, column_offsets, column);
        message[in_block++] = arena[source + ulong(row)];
        total_bytes += 4u;
        if (in_block == 16u) {
            blake2s_compress(state, message, total_bytes, first_column + column + 1u == total_columns);
            in_block = 0u;
        }
    }
    if (in_block != 0u) {
        for (uint i = in_block; i < 16u; ++i) message[i] = 0u;
        blake2s_compress(state, message, total_bytes, true);
    }
    for (uint i = 0u; i < 8u; ++i) arena[output_hashes + sparse_index * 8u + i] = state[i];
}

kernel void stwo_zig_decommit_assemble_trace_resident(
    device uint *arena [[buffer(0)]], constant uint &tree_index [[buffer(1)]],
    constant uint &role [[buffer(2)]], constant uint &leaf_log [[buffer(3)]],
    constant uint &first_retained_log [[buffer(4)]], constant uint &column_count [[buffer(5)]],
    constant ulong &mapped [[buffer(6)]], constant ulong &mapped_count_at [[buffer(7)]],
    constant uint &max_queries [[buffer(8)]], constant ulong &walk [[buffer(9)]],
    constant ulong &scratch [[buffer(10)]], constant ulong &walk_count_at [[buffer(11)]],
    constant ulong &values [[buffer(12)]], constant ulong &retained_offsets [[buffer(13)]],
    constant ulong &sparse_indices [[buffer(14)]], constant ulong &sparse_hashes [[buffer(15)]],
    constant ulong &sparse_offsets [[buffer(16)]], constant ulong &sparse_counts [[buffer(17)]],
    constant uint &sparse_level_count [[buffer(18)]], constant ulong &assembly [[buffer(19)]],
    constant uint &capacity [[buffer(20)]], uint lane [[thread_position_in_grid]]
) {
    if (lane != 0u || arena[assembly + 7u] == 0u) return;
    ulong meta = assembly + 8ul + ulong(tree_index) * 16ul;
    uint tree_start = arena[assembly + 7u], mapped_count = min(arena[mapped_count_at], max_queries), offset = 0u;
    if (!decommit_reserve(arena, assembly, capacity, mapped_count, offset)) return;
    arena[meta + 2u] = offset; arena[meta + 3u] = mapped_count;
    for (uint i = 0u; i < mapped_count; ++i) arena[assembly + offset + i] = arena[mapped + i];

    uint value_words = column_count * mapped_count;
    if (!decommit_reserve(arena, assembly, capacity, value_words, offset)) return;
    arena[meta + 4u] = offset; arena[meta + 5u] = value_words;
    for (uint c = 0u; c < column_count; ++c)
        for (uint q = 0u; q < mapped_count; ++q)
            arena[assembly + offset + c * mapped_count + q] = arena[values + c * max_queries + q];

    uint current_count = min(arena[walk_count_at], max_queries);
    bool current_is_walk = true;
    uint hash_offset = arena[assembly + 7u], hash_count = 0u;
    uint aux_offset = hash_offset + leaf_log * current_count * 8u;
    uint reserve = leaf_log * current_count * 28u;
    if (!decommit_reserve(arena, assembly, capacity, reserve, offset)) return;
    uint aux_count = 0u;
    for (int layer = int(leaf_log) - 1; layer >= 0; --layer) {
        uint previous_level = uint(layer) + 1u, next_count = 0u;
        ulong current = current_is_walk ? walk : scratch, next = current_is_walk ? scratch : walk;
        for (uint i = 0u; i < current_count;) {
            uint first = arena[current + i];
            bool pair = i + 1u < current_count && arena[current + i + 1u] == (first ^ 1u);
            if (!pair) {
                ulong source = decommit_trace_node_hash(arena, previous_level, first ^ 1u, leaf_log,
                    first_retained_log, retained_offsets, sparse_indices, sparse_hashes,
                    sparse_offsets, sparse_counts, sparse_level_count);
                if (source == 0xfffffffffffffffful) { arena[assembly + 7u] = 0u; return; }
                decommit_copy_hash(arena, assembly + hash_offset + hash_count * 8u, source);
                ++hash_count;
            }
            uint parent = first >> 1u;
            arena[next + next_count++] = parent;
            for (uint child = 2u * parent; child <= 2u * parent + 1u; ++child) {
                ulong source = decommit_trace_node_hash(arena, previous_level, child, leaf_log,
                    first_retained_log, retained_offsets, sparse_indices, sparse_hashes,
                    sparse_offsets, sparse_counts, sparse_level_count);
                if (source == 0xfffffffffffffffful) { arena[assembly + 7u] = 0u; return; }
                ulong entry = assembly + ulong(aux_offset + aux_count * 10u);
                arena[entry] = previous_level; arena[entry + 1u] = child;
                decommit_copy_hash(arena, entry + 2u, source);
                ++aux_count;
            }
            i += pair ? 2u : 1u;
        }
        current_is_walk = !current_is_walk;
        current_count = next_count;
    }
    uint compact_aux = hash_offset + hash_count * 8u;
    for (uint i = 0u; i < aux_count * 10u; ++i) arena[assembly + compact_aux + i] = arena[assembly + aux_offset + i];
    arena[assembly + 7u] = compact_aux + aux_count * 10u;
    arena[meta] = 0u; arena[meta + 1u] = role;
    arena[meta + 6u] = 0u; arena[meta + 7u] = 0u;
    arena[meta + 8u] = hash_offset; arena[meta + 9u] = hash_count;
    arena[meta + 10u] = compact_aux; arena[meta + 11u] = aux_count;
    arena[meta + 12u] = 0u; arena[meta + 13u] = 0u;
    arena[meta + 14u] = leaf_log; arena[meta + 15u] = arena[assembly + 7u] - tree_start;
}

kernel void stwo_zig_decommit_assemble_fri_resident(
    device uint *arena [[buffer(0)]],
    constant uint &tree_index [[buffer(1)]], constant uint &leaf_log [[buffer(2)]],
    constant ulong &tree_queries [[buffer(3)]], constant ulong &tree_count_at [[buffer(4)]],
    constant ulong &expanded [[buffer(5)]], constant ulong &expanded_count_at [[buffer(6)]],
    constant ulong &values [[buffer(7)]], constant ulong &walk [[buffer(8)]],
    constant ulong &scratch [[buffer(9)]], constant ulong &walk_count_at [[buffer(10)]],
    constant ulong &retained_offsets [[buffer(11)]], constant ulong &assembly [[buffer(12)]],
    constant uint &capacity [[buffer(13)]], uint lane [[thread_position_in_grid]]
) {
    if (lane != 0u || arena[assembly + 7u] == 0u) return;
    ulong meta = assembly + 8ul + ulong(tree_index) * 16ul;
    uint tree_start = arena[assembly + 7u];
    uint query_count = arena[tree_count_at], expanded_count = arena[expanded_count_at], offset = 0u;
    if (!decommit_reserve(arena, assembly, capacity, query_count, offset)) return;
    arena[meta + 2u] = offset; arena[meta + 3u] = query_count;
    for (uint i = 0u; i < query_count; ++i) arena[assembly + offset + i] = arena[tree_queries + i];

    uint witness_count = 0u;
    for (uint i = 0u; i < expanded_count; ++i)
        witness_count += decommit_contains_sorted(arena, tree_queries, query_count, arena[expanded + i]) ? 0u : 1u;
    if (!decommit_reserve(arena, assembly, capacity, 4u * witness_count, offset)) return;
    arena[meta + 6u] = offset; arena[meta + 7u] = witness_count;
    uint witness = 0u;
    for (uint i = 0u; i < expanded_count; ++i) {
        if (decommit_contains_sorted(arena, tree_queries, query_count, arena[expanded + i])) continue;
        for (uint c = 0u; c < 4u; ++c) arena[assembly + offset + 4u * witness + c] = arena[values + 4u * i + c];
        ++witness;
    }

    uint current_count = arena[walk_count_at];
    bool current_is_walk = true;
    uint hash_offset = arena[assembly + 7u];
    uint aux_offset = hash_offset + leaf_log * current_count * 8u;
    uint reserve = leaf_log * current_count * 28u;
    if (!decommit_reserve(arena, assembly, capacity, reserve, offset)) return;
    uint hash_count = 0u, aux_count = 0u;
    for (int layer = int(leaf_log) - 1; layer >= 0; --layer) {
        uint previous_level = uint(layer) + 1u, next_count = 0u;
        ulong current = current_is_walk ? walk : scratch;
        ulong next = current_is_walk ? scratch : walk;
        for (uint i = 0u; i < current_count;) {
            uint first = arena[current + i];
            bool pair = i + 1u < current_count && arena[current + i + 1u] == (first ^ 1u);
            if (!pair) {
                ulong source = decommit_wide_word_offset(arena, retained_offsets, previous_level) +
                    ulong(first ^ 1u) * 8ul;
                decommit_copy_hash(arena, assembly + hash_offset + hash_count * 8u, source);
                ++hash_count;
            }
            uint parent = first >> 1u;
            arena[next + next_count++] = parent;
            for (uint child = 2u * parent; child <= 2u * parent + 1u; ++child) {
                ulong entry = assembly + ulong(aux_offset + aux_count * 10u);
                arena[entry] = previous_level; arena[entry + 1u] = child;
                ulong source = decommit_wide_word_offset(arena, retained_offsets, previous_level) +
                    ulong(child) * 8ul;
                decommit_copy_hash(arena, entry + 2u, source);
                ++aux_count;
            }
            i += pair ? 2u : 1u;
        }
        current_is_walk = !current_is_walk;
        current_count = next_count;
    }
    uint compact_aux = hash_offset + hash_count * 8u;
    for (uint i = 0u; i < aux_count * 10u; ++i) arena[assembly + compact_aux + i] = arena[assembly + aux_offset + i];
    arena[assembly + 7u] = compact_aux + aux_count * 10u;

    if (!decommit_reserve(arena, assembly, capacity, expanded_count * 5u, offset)) return;
    arena[meta + 12u] = offset; arena[meta + 13u] = expanded_count;
    for (uint i = 0u; i < expanded_count; ++i) {
        arena[assembly + offset + 5u * i] = arena[expanded + i];
        for (uint c = 0u; c < 4u; ++c) arena[assembly + offset + 5u * i + 1u + c] = arena[values + 4u * i + c];
    }
    arena[meta] = 1u; arena[meta + 1u] = tree_index;
    arena[meta + 4u] = 0u; arena[meta + 5u] = 0u;
    arena[meta + 8u] = hash_offset; arena[meta + 9u] = hash_count;
    arena[meta + 10u] = compact_aux; arena[meta + 11u] = aux_count;
    arena[meta + 14u] = leaf_log; arena[meta + 15u] = arena[assembly + 7u] - tree_start;
}
