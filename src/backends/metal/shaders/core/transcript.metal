#ifndef STWO_ZIG_AMALGAMATED
#include "stwo_zig/base.metal"
#include "stwo_zig/blake2s.metal"
#include "stwo_zig/poseidon2_m31.metal"
#endif

inline void transcript_hash_digest_words(
    device uint *arena, uint state_base, uint source_base, uint source_words
) {
    uint hash[8], block[16];
    blake2s_init_hash(hash);
    uint total_words = 8u + source_words;
    uint total_bytes = total_words * 4u;
    uint consumed = 0u;
    while (consumed < total_words) {
        uint count = min(16u, total_words - consumed);
        for (uint i = 0u; i < 16u; ++i) block[i] = 0u;
        for (uint i = 0u; i < count; ++i) {
            uint at = consumed + i;
            block[i] = at < 8u ? arena[state_base + at] : arena[source_base + at - 8u];
        }
        consumed += count;
        blake2s_compress(hash, block, min(consumed * 4u, total_bytes), consumed == total_words);
    }
    for (uint i = 0u; i < 8u; ++i) arena[state_base + i] = hash[i];
    arena[state_base + 8u] = 0u;
}

inline void transcript_draw_words(device uint *arena, uint state_base, uint counter, thread uint *output) {
    uint hash[8], block[16];
    blake2s_init_hash(hash);
    for (uint i = 0u; i < 16u; ++i) block[i] = 0u;
    for (uint i = 0u; i < 8u; ++i) block[i] = arena[state_base + i];
    block[8] = counter;
    blake2s_compress(hash, block, 37u, true);
    for (uint i = 0u; i < 8u; ++i) output[i] = hash[i];
}

inline void transcript_draw_secure_felts(
    device uint *arena, uint state_base, uint destination_base, uint felt_count
) {
    uint produced = 0u, target = felt_count * 4u;
    uint counter = arena[state_base + 8u];
    while (produced < target) {
        uint words[8];
        bool accepted = false;
        for (uint attempt = 0u; attempt < 64u; ++attempt) {
            transcript_draw_words(arena, state_base, counter++, words);
            accepted = true;
            for (uint i = 0u; i < 8u; ++i) accepted = accepted && words[i] < 0xfffffffeu;
            if (accepted) break;
        }
        if (!accepted) {
            arena[state_base + 9u] = 1u;
            arena[state_base + 8u] = counter;
            return;
        }
        for (uint i = 0u; i < 8u && produced < target; ++i) {
            arena[destination_base + produced] = words[i] >= 0x7fffffffu ? words[i] - 0x7fffffffu : words[i];
            ++produced;
        }
    }
    arena[state_base + 8u] = counter;
}

kernel void stwo_zig_transcript_init_resident(
    device uint *arena [[buffer(0)]], constant uint &state_base [[buffer(1)]],
    uint lane [[thread_position_in_grid]]
) {
    if (lane != 0u) return;
    for (uint i = 0u; i < 9u; ++i) arena[state_base + i] = 0u;
}

kernel void stwo_zig_transcript_mix_resident(
    device uint *arena [[buffer(0)]], constant uint &state_base [[buffer(1)]],
    constant uint &source_base [[buffer(2)]], constant uint &source_words [[buffer(3)]],
    uint lane [[thread_position_in_grid]]
) {
    if (lane != 0u) return;
    transcript_hash_digest_words(arena, state_base, source_base, source_words);
}

kernel void stwo_zig_transcript_draw_secure_resident(
    device uint *arena [[buffer(0)]], constant uint &state_base [[buffer(1)]],
    constant uint &destination_base [[buffer(2)]], constant uint &felt_count [[buffer(3)]],
    uint lane [[thread_position_in_grid]]
) {
    if (lane != 0u) return;
    transcript_draw_secure_felts(arena, state_base, destination_base, felt_count);
}

// Maps one BLAKE2s compression across a four-lane quad. Each lane owns one
// column of the 4x4 state; shuffle rotations expose the diagonal G schedule
// without moving the 16-word child message out of threadgroup memory.
inline uint2 blake2s_compress_parent_cooperative4(
    threadgroup const uint *message, constant uint *node_seed,
    uint prefix_bytes, uint quad_lane, uint simd_lane
) {
    uint initial_a = prefix_bytes == 0u ? blake2s_iv[quad_lane] : node_seed[quad_lane];
    uint initial_b = prefix_bytes == 0u ? blake2s_iv[quad_lane + 4u] : node_seed[quad_lane + 4u];
    if (prefix_bytes == 0u && quad_lane == 0u) initial_a ^= 0x01010020u;
    uint a = initial_a;
    uint b = initial_b;
    uint c = blake2s_iv[quad_lane];
    uint d = blake2s_iv[quad_lane + 4u];
    if (quad_lane == 0u) d ^= prefix_bytes + 64u;
    if (quad_lane == 2u) d ^= 0xffffffffu;
    uint quad_base = simd_lane & ~3u;

    for (uint round = 0u; round < 10u; ++round) {
        a = a + b + message[blake2s_sigma[round][quad_lane * 2u]];
        d = rotr32(d ^ a, 16u);
        c += d;
        b = rotr32(b ^ c, 12u);
        a = a + b + message[blake2s_sigma[round][quad_lane * 2u + 1u]];
        d = rotr32(d ^ a, 8u);
        c += d;
        b = rotr32(b ^ c, 7u);

        uint diagonal_b = simd_shuffle(b, quad_base + ((quad_lane + 1u) & 3u));
        uint diagonal_c = simd_shuffle(c, quad_base + ((quad_lane + 2u) & 3u));
        uint diagonal_d = simd_shuffle(d, quad_base + ((quad_lane + 3u) & 3u));
        a = a + diagonal_b + message[blake2s_sigma[round][8u + quad_lane * 2u]];
        diagonal_d = rotr32(diagonal_d ^ a, 16u);
        diagonal_c += diagonal_d;
        diagonal_b = rotr32(diagonal_b ^ diagonal_c, 12u);
        a = a + diagonal_b + message[blake2s_sigma[round][9u + quad_lane * 2u]];
        diagonal_d = rotr32(diagonal_d ^ a, 8u);
        diagonal_c += diagonal_d;
        diagonal_b = rotr32(diagonal_b ^ diagonal_c, 7u);

        b = simd_shuffle(diagonal_b, quad_base + ((quad_lane + 3u) & 3u));
        c = simd_shuffle(diagonal_c, quad_base + ((quad_lane + 2u) & 3u));
        d = simd_shuffle(diagonal_d, quad_base + ((quad_lane + 1u) & 3u));
    }
    return uint2(
        initial_a ^ a ^ c,
        initial_b ^ b ^ d
    );
}

kernel void stwo_zig_blake2s_parent_tail_sparse(
    device uint *arena [[buffer(0)]], constant uint *child_offsets [[buffer(1)]],
    constant uint *destination_offsets [[buffer(2)]], constant uint *parent_counts [[buffer(3)]],
    constant uint &level_count [[buffer(4)]], constant uint *node_seed [[buffer(5)]],
    constant uint &prefix_bytes [[buffer(6)]], constant uint *transcript_config [[buffer(7)]],
    threadgroup uint *hashes [[threadgroup(0)]], uint thread_index [[thread_index_in_threadgroup]],
    uint simd_lane [[thread_index_in_simdgroup]],
    uint3 threads_in_group [[threads_per_threadgroup]],
    uint3 group [[threadgroup_position_in_grid]]
) {
    if (level_count == 0u) return;
    for (uint level = 0u; level < level_count; ++level) {
        uint parent_count = parent_counts[level];
        if (level != 0u && parent_count * 4u <= threads_in_group.x) {
            // Every available four-lane quad owns one parent. Keep the result
            // in registers until all SIMDgroups have consumed the compacted
            // child layer: early writes would otherwise alias later messages.
            uint hash_index = thread_index >> 2u;
            uint quad_lane = thread_index & 3u;
            uint2 state(0u);
            if (hash_index < parent_count) {
                state = blake2s_compress_parent_cooperative4(
                    hashes + hash_index * 16u, node_seed, prefix_bytes,
                    quad_lane, simd_lane
                );
            }
            threadgroup_barrier(mem_flags::mem_threadgroup);
            if (hash_index < parent_count) {
                hashes[hash_index * 8u + quad_lane] = state.x;
                hashes[hash_index * 8u + quad_lane + 4u] = state.y;
                uint destination = destination_offsets[level] +
                    (group.x * parent_count + hash_index) * 8u;
                arena[destination + quad_lane] = state.x;
                arena[destination + quad_lane + 4u] = state.y;
            }
        } else {
            uint message[16];
            if (thread_index < parent_count) {
                if (level == 0u) {
                    // Each threadgroup owns one contiguous bottom subtree.
                    uint source = child_offsets[0] +
                        (group.x * parent_count + thread_index) * 16u;
                    for (uint i = 0u; i < 16u; ++i) message[i] = arena[source + i];
                } else {
                    uint source = thread_index * 16u;
                    for (uint i = 0u; i < 16u; ++i) message[i] = hashes[source + i];
                }
            }
            threadgroup_barrier(mem_flags::mem_threadgroup);
            if (thread_index < parent_count) {
                uint state[8];
                if (prefix_bytes == 0u) blake2s_init_hash(state);
                else blake2s_init_seeded(state, node_seed);
                blake2s_compress(state, message, prefix_bytes + 64u, true);
                uint destination = destination_offsets[level] +
                    (group.x * parent_count + thread_index) * 8u;
                for (uint i = 0u; i < 8u; ++i) {
                    hashes[thread_index * 8u + i] = state[i];
                    arena[destination + i] = state[i];
                }
            }
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    if (transcript_config[2] == 0u || group.x != 0u ||
        parent_counts[level_count - 1u] != 1u || thread_index != 0u) return;
    uint state_base = transcript_config[0], alpha_base = transcript_config[1];
    uint digest[8], block[16];
    blake2s_init_hash(digest);
    for (uint i = 0u; i < 8u; ++i) {
        block[i] = arena[state_base + i];
        block[i + 8u] = hashes[i];
    }
    blake2s_compress(digest, block, 64u, true);
    for (uint i = 0u; i < 8u; ++i) arena[state_base + i] = digest[i];
    arena[state_base + 8u] = 0u;
    transcript_draw_secure_felts(arena, state_base, alpha_base, 1u);
}

// Poseidon2 parent tails never mutate a Fiat-Shamir transcript.  The generic
// Poseidon recursion channel performs its transcript on the typed host side;
// this kernel is solely the exact Merkle parent compression used by prepared
// resident commitment plans.  The runtime admits it only when the existing
// transcript configuration is disabled.
kernel void stwo_zig_poseidon2_m31_parent_tail_sparse(
    device uint *arena [[buffer(0)]], constant uint *child_offsets [[buffer(1)]],
    constant uint *destination_offsets [[buffer(2)]], constant uint *parent_counts [[buffer(3)]],
    constant uint &level_count [[buffer(4)]], constant uint *unused_node_seed [[buffer(5)]],
    constant uint &unused_prefix_bytes [[buffer(6)]], constant uint *transcript_config [[buffer(7)]],
    threadgroup uint *hashes [[threadgroup(0)]], uint thread_index [[thread_index_in_threadgroup]],
    uint3 threads_in_group [[threads_per_threadgroup]],
    uint3 group [[threadgroup_position_in_grid]]
) {
    (void)unused_node_seed;
    (void)unused_prefix_bytes;
    if (level_count == 0u || transcript_config[2] != 0u) return;
    for (uint level = 0u; level < level_count; ++level) {
        uint parent_count = parent_counts[level];
        uint child_words[16], digest[8];
        if (thread_index < parent_count) {
            if (level == 0u) {
                uint source = child_offsets[0] +
                    (group.x * parent_count + thread_index) * 16u;
                for (uint lane = 0u; lane < 16u; ++lane)
                    child_words[lane] = arena[source + lane];
            } else {
                for (uint lane = 0u; lane < 16u; ++lane)
                    child_words[lane] = hashes[thread_index * 16u + lane];
            }
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
        if (thread_index < parent_count) {
            stwo_zig_poseidon2_parent(child_words, digest);
            uint destination = destination_offsets[level] +
                (group.x * parent_count + thread_index) * 8u;
            for (uint lane = 0u; lane < 8u; ++lane) {
                hashes[thread_index * 8u + lane] = digest[lane];
                arena[destination + lane] = digest[lane];
            }
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }
    (void)threads_in_group;
}

kernel void stwo_zig_transcript_draw_queries_resident(
    device uint *arena [[buffer(0)]], constant uint &state_base [[buffer(1)]],
    constant uint &destination_base [[buffer(2)]], constant uint &log_domain_size [[buffer(3)]],
    constant uint &query_count [[buffer(4)]], uint lane [[thread_position_in_grid]]
) {
    if (lane != 0u) return;
    uint mask = log_domain_size == 0u ? 0u : ((1u << log_domain_size) - 1u);
    uint produced = 0u;
    uint counter = arena[state_base + 8u];
    while (produced < query_count) {
        uint words[8];
        transcript_draw_words(arena, state_base, counter++, words);
        for (uint i = 0u; i < 8u && produced < query_count; ++i)
            arena[destination_base + produced++] = words[i] & mask;
    }
    arena[state_base + 8u] = counter;
}
