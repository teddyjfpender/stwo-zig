#include "poly_support.h"

kernel void ifft_circle_part_u32(
    device uint *values [[buffer(0)]],
    device const uint *inverse_twiddles [[buffer(1)]],
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
    uint twiddle = stwo_metal_get_circle_twiddle(inverse_twiddles, index);

    values[idx0] = stwo_metal_m31_add(val0, val1);
    values[idx1] = stwo_metal_m31_mul(stwo_metal_m31_sub(val0, val1), twiddle);
}

kernel void ifft_line_part_u32(
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
    uint twiddle_index = index >> layer;
    uint l = index & (number_polynomials - 1u);
    uint idx0 = (twiddle_index << (layer + 1u)) + l;
    uint idx1 = idx0 + number_polynomials;

    uint val0 = values[idx0];
    uint val1 = values[idx1];
    uint twiddle = twiddles[layer_domain_offset + twiddle_index];

    values[idx0] = stwo_metal_m31_add(val0, val1);
    values[idx1] = stwo_metal_m31_mul(stwo_metal_m31_sub(val0, val1), twiddle);
}

kernel void ifft_line_stage_u32(
    device uint *values [[buffer(0)]],
    device const uint *twiddles [[buffer(1)]],
    constant uint &values_log_len [[buffer(2)]],
    constant uint &stage_domain_log_size [[buffer(3)]],
    uint index [[thread_position_in_grid]]
) {
    uint values_len = 1u << values_log_len;
    uint pair_count = values_len >> 1u;
    if (index >= pair_count) {
        return;
    }

    uint stage_domain_size = 1u << stage_domain_log_size;
    uint half_stage_size = stage_domain_size >> 1u;
    uint group = index / half_stage_size;
    uint inner = index % half_stage_size;
    uint base = group * stage_domain_size;
    uint idx0 = base + inner;
    uint idx1 = idx0 + half_stage_size;

    uint val0 = values[idx0];
    uint val1 = values[idx1];
    uint twiddle = twiddles[inner];

    values[idx0] = stwo_metal_m31_add(val0, val1);
    values[idx1] = stwo_metal_m31_mul(stwo_metal_m31_sub(val0, val1), twiddle);
}

// Fused-tail IFFT kernel: loads a tile of 2048 elements into threadgroup
// memory, performs the circle_part + first N line_part stages entirely on-chip,
// then stores back. Reduces global memory traffic from 2*(N+1) passes to 2
// passes for the fused stages.
//
// This is the inverse of rfft_tail_fused_u32: the IFFT processes layers in
// the opposite order (circle_part first, then line layers 1..N ascending),
// and uses the inverse butterfly: (a, b) -> (a + b, tw * (a - b)).
//
// Tile = 2048 elements (8 KB threadgroup memory).
// Fusible stages: circle_part (d=1) + layers 1..10 (d=2..1024).
// Threads per threadgroup: 256 (8 elements / 2 uint4 loads per thread).
//
// Circle_part + layers 1-4 (d=1..16) use simd_shuffle_xor in registers.
// Layers 5-10 (d=32..1024) use threadgroup memory + barriers.

#define IFFT_FUSED_TILE_LOG  11u
#define IFFT_FUSED_TILE_SIZE (1u << IFFT_FUSED_TILE_LOG)   // 2048
#define IFFT_FUSED_THREADS   256u
#define IFFT_FUSED_EPT       (IFFT_FUSED_TILE_SIZE / IFFT_FUSED_THREADS)  // 8

// Shuffle cutover: layers <= this use simd_shuffle_xor instead of TG memory.
#define IFFT_SHUFFLE_CUTOVER 4u

kernel void ifft_tail_fused_u32(
    device uint *values [[buffer(0)]],
    device const uint *inverse_twiddles [[buffer(1)]],
    constant uint &values_log_len [[buffer(2)]],
    constant uint &n_fused_layers [[buffer(3)]],
    uint tid [[thread_index_in_threadgroup]],
    uint tg  [[threadgroup_position_in_grid]]
) {
    threadgroup uint tile[IFFT_FUSED_TILE_SIZE];

    uint pair_count = 1u << (values_log_len - 1u);
    uint base = tg * IFFT_FUSED_TILE_SIZE;

    // --- vectorized global load (2 x uint4 per thread) ---
    uint load_off = base + tid * IFFT_FUSED_EPT;
    device const uint4 *src = (device const uint4 *)(values + load_off);
    threadgroup uint4 *dst = (threadgroup uint4 *)(tile + tid * IFFT_FUSED_EPT);
    dst[0] = src[0];
    dst[1] = src[1];
    threadgroup_barrier(mem_flags::mem_threadgroup);

    // --- load registers from TG memory (lane-strided) ---
    // Each simdgroup (32 lanes) owns a 256-element slice of the tile.
    uint sg = tid >> 5u;       // simdgroup index (0..7)
    uint lane = tid & 31u;     // lane within simdgroup
    uint sg_base = sg << 8u;   // sg * 256

    uint v[8];
    for (uint r = 0u; r < 8u; r++) {
        v[r] = tile[sg_base + r * 32u + lane];
    }

    // --- circle_part via simd shuffle (d=1, mask=1) ---
    // IFFT circle butterfly: (a, b) -> (a + b, tw * (a - b))
    // Even lanes hold 'a' (idx0), odd lanes hold 'b' (idx1).
    for (uint r = 0u; r < 8u; r++) {
        uint tile_pos = sg_base + r * 32u + lane;
        uint global_pair = (base >> 1u) + (tile_pos >> 1u);

        uint partner = simd_shuffle_xor(v[r], 1);
        uint tw = stwo_metal_get_circle_twiddle(inverse_twiddles, global_pair);

        if (lane & 1u) {
            // Odd lane (idx1): result = tw * (partner - my_val)
            // partner = val0, my_val = val1
            // result = tw * (val0 - val1)
            uint diff = stwo_metal_m31_sub(partner, v[r]);
            v[r] = stwo_metal_m31_mul(diff, tw);
        } else {
            // Even lane (idx0): result = my_val + partner
            // my_val = val0, partner = val1
            // result = val0 + val1
            v[r] = stwo_metal_m31_add(v[r], partner);
        }
    }

    // --- simd shuffle stages: layers 1 up to min(SHUFFLE_CUTOVER, n_fused_layers) ---
    // IFFT line butterfly: (a, b) -> (a + b, tw * (a - b))
    // Butterfly distance d = 2^layer. Partner lane = lane ^ d.
    // Lower lane holds 'a' (idx0), upper lane holds 'b' (idx1).
    uint shuffle_end = min(IFFT_SHUFFLE_CUTOVER, n_fused_layers);
    for (uint layer = 1u; layer <= shuffle_end; ++layer) {
        uint mask = 1u << layer;           // XOR mask = butterfly distance
        uint twiddle_off = pair_count - (1u << (values_log_len - layer));
        uint h_base = base >> (layer + 1u);

        for (uint r = 0u; r < 8u; r++) {
            uint tile_pos = sg_base + r * 32u + lane;
            uint h_local = tile_pos >> (layer + 1u);

            uint partner = simd_shuffle_xor(v[r], (ushort)mask);
            uint tw = inverse_twiddles[twiddle_off + h_base + h_local];

            if (lane & mask) {
                // Upper element (idx1): result = tw * (partner - my_val)
                uint diff = stwo_metal_m31_sub(partner, v[r]);
                v[r] = stwo_metal_m31_mul(diff, tw);
            } else {
                // Lower element (idx0): result = my_val + partner
                v[r] = stwo_metal_m31_add(v[r], partner);
            }
        }
    }

    // --- store registers back to TG memory (lane-strided) ---
    for (uint r = 0u; r < 8u; r++) {
        tile[sg_base + r * 32u + lane] = v[r];
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    // --- threadgroup-memory stages (layers shuffle_end+1 up to n_fused_layers) ---
    uint tile_pairs = IFFT_FUSED_TILE_SIZE >> 1u;  // 1024
    uint pairs_per_thread = tile_pairs / IFFT_FUSED_THREADS;  // 4

    for (uint layer = shuffle_end + 1u; layer <= n_fused_layers; ++layer) {
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
            uint tw = inverse_twiddles[twiddle_off + h_base + h_local];

            tile[li0] = stwo_metal_m31_add(v0, v1);
            tile[li1] = stwo_metal_m31_mul(stwo_metal_m31_sub(v0, v1), tw);
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    // --- vectorized global store (2 x uint4 per thread) ---
    device uint4 *out = (device uint4 *)(values + load_off);
    threadgroup const uint4 *src2 = (threadgroup const uint4 *)(tile + tid * IFFT_FUSED_EPT);
    out[0] = src2[0];
    out[1] = src2[1];
}
