#include "poly_support.h"

kernel void rfft_circle_part_u32(
    device uint *values [[buffer(0)]],
    device const uint *twiddles [[buffer(1)]],
    constant uint &values_len [[buffer(2)]],
    uint index [[thread_position_in_grid]]
) {
    uint pair_count = values_len >> 1u;
    if (index >= pair_count) {
        return;
    }

    uint idx0 = index << 1u;
    uint idx1 = idx0 + 1u;
    uint val0 = values[idx0];
    uint val1 = values[idx1];
    uint twiddle = stwo_metal_get_circle_twiddle(twiddles, index);
    uint temp = stwo_metal_m31_mul(val1, twiddle);

    values[idx0] = stwo_metal_m31_add(val0, temp);
    values[idx1] = stwo_metal_m31_sub(val0, temp);
}

kernel void rfft_line_part_u32(
    device uint *values [[buffer(0)]],
    device const uint *twiddles [[buffer(1)]],
    constant uint &values_log_len [[buffer(2)]],
    constant uint &layer [[buffer(3)]],
    constant uint &layer_domain_offset [[buffer(4)]],
    uint index [[thread_position_in_grid]]
) {
    uint values_len = 1u << values_log_len;
    uint pair_count = values_len >> 1u;
    if (index >= pair_count) {
        return;
    }

    uint number_polynomials = 1u << layer;
    uint h = index / number_polynomials;
    uint l = index % number_polynomials;
    uint idx0 = (h << (layer + 1u)) + l;
    uint idx1 = idx0 + number_polynomials;

    uint val0 = values[idx0];
    uint val1 = values[idx1];
    uint twiddle = twiddles[layer_domain_offset + h];
    uint temp = stwo_metal_m31_mul(val1, twiddle);

    values[idx0] = stwo_metal_m31_add(val0, temp);
    values[idx1] = stwo_metal_m31_sub(val0, temp);
}

// Fused-tail RFFT kernel: loads a tile of 2048 elements into threadgroup
// memory, performs the last N line_part stages + circle_part entirely on-chip,
// then stores back. Reduces global memory traffic from 2*(N+1) passes to 2
// passes for the fused stages.
//
// Tile = 2048 elements (8 KB threadgroup memory).
// Fusible stages: layers with butterfly distance <= 1024 (layers 1..10).
// Threads per threadgroup: 256 (8 elements / 2 uint4 loads per thread).
//
// Layers 10-5 (d=1024..32) use threadgroup memory + barriers.
// Layers 4-1 (d=16..2) + circle_part (d=1) use simd_shuffle_xor in
// registers — no barriers needed within a 32-wide SIMD-group.

#define RFFT_FUSED_TILE_LOG  11u
#define RFFT_FUSED_TILE_SIZE (1u << RFFT_FUSED_TILE_LOG)   // 2048
#define RFFT_FUSED_THREADS   256u
#define RFFT_FUSED_EPT       (RFFT_FUSED_TILE_SIZE / RFFT_FUSED_THREADS)  // 8

// Shuffle cutover: layers <= this use simd_shuffle_xor instead of TG memory.
// d=16 means 5 shuffle stages (layers 4,3,2,1 + circle).
#define RFFT_SHUFFLE_CUTOVER 4u

kernel void rfft_tail_fused_u32(
    device uint *values [[buffer(0)]],
    device const uint *twiddles [[buffer(1)]],
    constant uint &values_log_len [[buffer(2)]],
    constant uint &n_fused_layers [[buffer(3)]],
    uint tid [[thread_index_in_threadgroup]],
    uint tg  [[threadgroup_position_in_grid]]
) {
    threadgroup uint tile[RFFT_FUSED_TILE_SIZE];

    uint pair_count = 1u << (values_log_len - 1u);
    uint base = tg * RFFT_FUSED_TILE_SIZE;

    // --- vectorized global load (2 × uint4 per thread) ---
    uint load_off = base + tid * RFFT_FUSED_EPT;
    device const uint4 *src = (device const uint4 *)(values + load_off);
    threadgroup uint4 *dst = (threadgroup uint4 *)(tile + tid * RFFT_FUSED_EPT);
    dst[0] = src[0];
    dst[1] = src[1];
    threadgroup_barrier(mem_flags::mem_threadgroup);

    // --- threadgroup-memory stages (layers n_fused_layers down to SHUFFLE_CUTOVER+1) ---
    uint tile_pairs = RFFT_FUSED_TILE_SIZE >> 1u;  // 1024
    uint pairs_per_thread = tile_pairs / RFFT_FUSED_THREADS;  // 4
    uint tg_cutoff = min(n_fused_layers, RFFT_SHUFFLE_CUTOVER);

    for (uint layer = n_fused_layers; layer > tg_cutoff; --layer) {
        uint dist = 1u << layer;           // butterfly distance
        uint stride = dist << 1u;          // group stride
        uint twiddle_off = pair_count - (1u << (values_log_len - layer));
        uint h_base = base / stride;       // global group offset for this tile

        for (uint p = 0u; p < pairs_per_thread; p++) {
            uint lp = tid * pairs_per_thread + p;  // local pair index
            uint h_local = lp / dist;
            uint l = lp - h_local * dist;  // lp % dist (avoid division)
            uint li0 = h_local * stride + l;
            uint li1 = li0 + dist;

            uint v0 = tile[li0];
            uint v1 = tile[li1];
            uint tw = twiddles[twiddle_off + h_base + h_local];
            uint t = stwo_metal_m31_mul(v1, tw);

            tile[li0] = stwo_metal_m31_add(v0, t);
            tile[li1] = stwo_metal_m31_sub(v0, t);
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    // --- load registers from TG memory (lane-strided) ---
    // Each simdgroup (32 lanes) owns a 256-element slice of the tile.
    // Lane l loads 8 values at positions sg_base + r*32 + lane (stride-32).
    uint sg = tid >> 5u;       // simdgroup index (0..7)
    uint lane = tid & 31u;     // lane within simdgroup
    uint sg_base = sg << 8u;   // sg * 256

    uint v[8];
    for (uint r = 0u; r < 8u; r++) {
        v[r] = tile[sg_base + r * 32u + lane];
    }

    // --- simd shuffle stages: layers min(SHUFFLE_CUTOVER, n_fused_layers) down to 1 ---
    // Butterfly distance d=2^layer. Partner lane = lane ^ d.
    // Both lanes in a pair share the same twiddle (same h_global).
    uint shuffle_start = min(RFFT_SHUFFLE_CUTOVER, n_fused_layers);
    for (uint layer = shuffle_start; layer > 0u; --layer) {
        uint mask = 1u << layer;           // XOR mask = butterfly distance
        uint twiddle_off = pair_count - (1u << (values_log_len - layer));
        uint h_base = base >> (layer + 1u);

        for (uint r = 0u; r < 8u; r++) {
            uint tile_pos = sg_base + r * 32u + lane;
            uint h_local = tile_pos >> (layer + 1u);

            uint partner = simd_shuffle_xor(v[r], (ushort)mask);
            uint tw = twiddles[twiddle_off + h_base + h_local];

            if (lane & mask) {
                // Upper element: result = partner - tw * my_val
                uint t = stwo_metal_m31_mul(v[r], tw);
                v[r] = stwo_metal_m31_sub(partner, t);
            } else {
                // Lower element: result = my_val + tw * partner
                uint t = stwo_metal_m31_mul(partner, tw);
                v[r] = stwo_metal_m31_add(v[r], t);
            }
        }
    }

    // --- circle_part via simd shuffle (d=1, mask=1) ---
    for (uint r = 0u; r < 8u; r++) {
        uint tile_pos = sg_base + r * 32u + lane;
        uint global_pair = (base >> 1u) + (tile_pos >> 1u);

        uint partner = simd_shuffle_xor(v[r], 1);
        uint tw = stwo_metal_get_circle_twiddle(twiddles, global_pair);

        if (lane & 1u) {
            uint t = stwo_metal_m31_mul(v[r], tw);
            v[r] = stwo_metal_m31_sub(partner, t);
        } else {
            uint t = stwo_metal_m31_mul(partner, tw);
            v[r] = stwo_metal_m31_add(v[r], t);
        }
    }

    // --- store registers back to TG memory (lane-strided) ---
    for (uint r = 0u; r < 8u; r++) {
        tile[sg_base + r * 32u + lane] = v[r];
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    // --- vectorized global store (2 × uint4 per thread) ---
    device uint4 *out = (device uint4 *)(values + load_off);
    threadgroup const uint4 *src2 = (threadgroup const uint4 *)(tile + tid * RFFT_FUSED_EPT);
    out[0] = src2[0];
    out[1] = src2[1];
}
