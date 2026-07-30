#ifndef STWO_COMPOSITION_SPLIT_CUH
#define STWO_COMPOSITION_SPLIT_CUH

#include "fields.cuh"

// Final B2N interval for the exact four-coordinate Composition accumulator.
// The strong mode continues both coefficient halves through the first forward
// interval before its only global write. The fallback writes the exact
// duplicated stage-two image. Both modes preserve canonical left[0..4],
// right[4..8] output order.
template <unsigned LOG_VALUES_PER_THREAD, bool FUSE_FIRST_FORWARD>
__global__ void composition_split_boundary_batch(
    m31 **sources,
    m31 **retained_outputs,
    unsigned log_n,
    unsigned min_stage,
    m31 *inverse_twiddles,
    m31 *forward_twiddles,
    m31 rescale_factor
) {
    constexpr unsigned LOG_WARP = 5;
    constexpr unsigned WARP = 1u << LOG_WARP;
    constexpr unsigned VALUES_PER_THREAD = 1u << LOG_VALUES_PER_THREAD;
    constexpr unsigned HALF_VALUES_PER_THREAD = VALUES_PER_THREAD >> 1;
    constexpr unsigned INVERSE_STAGES = 2 * LOG_VALUES_PER_THREAD;
    constexpr unsigned FORWARD_WARPS_LOG = LOG_VALUES_PER_THREAD - 1;
    constexpr unsigned FORWARD_STAGES = 2 * LOG_VALUES_PER_THREAD - 1;
    constexpr unsigned FORWARD_TILE_WORDS =
        WARP << (LOG_VALUES_PER_THREAD + FORWARD_WARPS_LOG);
    constexpr unsigned SHARED_WORDS =
        (WARP << (2 * LOG_VALUES_PER_THREAD)) + WARP;
    static_assert(LOG_VALUES_PER_THREAD == 3 || LOG_VALUES_PER_THREAD == 4);
    static_assert(2 * FORWARD_TILE_WORDS <= SHARED_WORDS);

    const unsigned coordinate = blockIdx.z;
    const unsigned lane = threadIdx.x;
    const unsigned inverse_warp = threadIdx.y;
    const unsigned inverse_min_stride = 1u << (min_stage - 1);
    const unsigned block_start =
        (blockIdx.x << LOG_WARP) +
        (blockIdx.y << (min_stage + INVERSE_STAGES - 1));
    const m31 *source = sources[coordinate];

    m31 values[VALUES_PER_THREAD];
    unsigned offset =
        inverse_warp * (inverse_min_stride << LOG_VALUES_PER_THREAD) + lane;
#pragma unroll
    for (unsigned i = 0; i < VALUES_PER_THREAD; ++i) {
        values[i] = source[block_start + i * inverse_min_stride + offset];
    }

    unsigned inverse_layer_size = (1u << log_n) >> 1;
    unsigned inverse_layer_offset = 0;
    for (unsigned stage = 2; stage < min_stage; ++stage) {
        inverse_layer_size >>= 1;
        inverse_layer_offset += inverse_layer_size;
    }

    unsigned stage = min_stage;
#pragma unroll
    for (; stage < min_stage + LOG_VALUES_PER_THREAD; ++stage) {
        const unsigned log_inner_stride = stage - min_stage;
#pragma unroll
        for (unsigned gid = 0; gid < HALF_VALUES_PER_THREAD; ++gid) {
            const unsigned inner_group = gid & ((1u << log_inner_stride) - 1);
            const unsigned inner_pair = gid >> log_inner_stride;
            const unsigned left =
                inner_group + (inner_pair << (log_inner_stride + 1));
            const unsigned right = left + (1u << log_inner_stride);
            const unsigned outer_pair = (block_start + offset) >> stage;
            const m31 twiddle =
                inverse_twiddles[inverse_layer_offset + inner_pair + outer_pair];
            const m31 left_value = values[left];
            values[left] = add(left_value, values[right]);
            values[right] = mul(sub(left_value, values[right]), twiddle);
        }
        inverse_layer_size >>= 1;
        inverse_layer_offset += inverse_layer_size;
    }

    __shared__ m31 shared[SHARED_WORDS];
    const unsigned inverse_warp_store =
        inverse_warp * (inverse_min_stride << LOG_VALUES_PER_THREAD);
#pragma unroll
    for (unsigned i = 0; i < VALUES_PER_THREAD; ++i) {
        shared[(i * inverse_min_stride + inverse_warp_store) / gridDim.x + lane] =
            values[i];
    }
    __syncthreads();

    const unsigned second_min_stage = min_stage + LOG_VALUES_PER_THREAD;
    const unsigned second_min_stride = 1u << (second_min_stage - 1);
    const unsigned second_offset =
        inverse_warp * inverse_min_stride + lane;
#pragma unroll
    for (unsigned i = 0; i < VALUES_PER_THREAD; ++i) {
        values[i] = shared[
            (i * second_min_stride + inverse_warp * inverse_min_stride) /
                gridDim.x +
            lane];
    }

#pragma unroll
    for (; stage < second_min_stage + LOG_VALUES_PER_THREAD; ++stage) {
        const unsigned log_inner_stride = stage - second_min_stage;
#pragma unroll
        for (unsigned gid = 0; gid < HALF_VALUES_PER_THREAD; ++gid) {
            const unsigned inner_group = gid & ((1u << log_inner_stride) - 1);
            const unsigned inner_pair = gid >> log_inner_stride;
            const unsigned left =
                inner_group + (inner_pair << (log_inner_stride + 1));
            const unsigned right = left + (1u << log_inner_stride);
            const unsigned outer_pair = (block_start + second_offset) >> stage;
            const m31 twiddle =
                inverse_twiddles[inverse_layer_offset + inner_pair + outer_pair];
            const m31 left_value = values[left];
            values[left] = add(left_value, values[right]);
            values[right] = mul(sub(left_value, values[right]), twiddle);
            if (stage == log_n) {
                values[left] = mul(values[left], rescale_factor);
                values[right] = mul(values[right], rescale_factor);
            }
        }
        inverse_layer_size >>= 1;
        inverse_layer_offset += inverse_layer_size;
    }

    if constexpr (!FUSE_FIRST_FORWARD) {
        const unsigned half_rows = 1u << (log_n - 1);
#pragma unroll
        for (unsigned i = 0; i < VALUES_PER_THREAD; ++i) {
            const unsigned source_index =
                block_start + i * second_min_stride + second_offset;
            const unsigned side = source_index >= half_rows;
            const unsigned retained_index = source_index & (half_rows - 1);
            m31 *destination = retained_outputs[coordinate + 4 * side];
            destination[retained_index] = values[i];
            destination[retained_index + half_rows] = values[i];
        }
        return;
    }

    // One inverse CTA owns two smaller forward CTAs for each coefficient half.
    // Reuse its shared tile and execute left then right so no coefficient image
    // reaches global memory.
    const unsigned forward_group = inverse_warp >> FORWARD_WARPS_LOG;
    const unsigned forward_warp =
        inverse_warp & ((1u << FORWARD_WARPS_LOG) - 1);
    const unsigned forward_group_offset = forward_group * FORWARD_TILE_WORDS;
    const unsigned forward_end_stage = 2 * LOG_VALUES_PER_THREAD;
    const unsigned forward_min_stride = 1u << (log_n - forward_end_stage);
    const unsigned forward_block_start =
        (blockIdx.x << LOG_WARP) + (forward_group << (log_n - 1));

#pragma unroll 1
    for (unsigned side = 0; side < 2; ++side) {
        __syncthreads();
#pragma unroll
        for (unsigned i = 0; i < HALF_VALUES_PER_THREAD; ++i) {
            const unsigned coefficient =
                lane + WARP * (inverse_warp + i * (1u << LOG_VALUES_PER_THREAD));
            const m31 value = values[side * HALF_VALUES_PER_THREAD + i];
            shared[coefficient] = value;
            shared[FORWARD_TILE_WORDS + coefficient] = value;
        }
        __syncthreads();

        m31 forward_values[VALUES_PER_THREAD];
#pragma unroll
        for (unsigned i = 0; i < VALUES_PER_THREAD; ++i) {
            const unsigned coefficient =
                lane + WARP * (forward_warp + i * (1u << FORWARD_WARPS_LOG));
            forward_values[i] = shared[forward_group_offset + coefficient];
        }

        unsigned forward_layer_size = 2;
        unsigned forward_layer_offset = ((1u << log_n) >> 1) - 4;
        unsigned forward_stage = 2;
#pragma unroll
        for (; forward_stage < 2 + LOG_VALUES_PER_THREAD; ++forward_stage) {
            const unsigned log_inner_stride =
                LOG_VALUES_PER_THREAD - 1 - (forward_stage - 2);
#pragma unroll
            for (unsigned gid = 0; gid < HALF_VALUES_PER_THREAD; ++gid) {
                const unsigned inner_group =
                    gid & ((1u << log_inner_stride) - 1);
                const unsigned inner_pair = gid >> log_inner_stride;
                const unsigned left =
                    inner_group + (inner_pair << (log_inner_stride + 1));
                const unsigned right = left + (1u << log_inner_stride);
                const unsigned outer_pair =
                    (forward_block_start + forward_warp * forward_min_stride + lane) >>
                    (1 + log_n - forward_stage);
                const m31 product = mul(
                    forward_twiddles[
                        forward_layer_offset + inner_pair + outer_pair],
                    forward_values[right]);
                const m31 left_value = forward_values[left];
                forward_values[left] = add(left_value, product);
                forward_values[right] = sub(left_value, product);
            }
            forward_layer_size <<= 1;
            forward_layer_offset -= forward_layer_size;
        }

#pragma unroll
        for (unsigned i = 0; i < VALUES_PER_THREAD; ++i) {
            shared[forward_group_offset + lane +
                   (i << (LOG_WARP + FORWARD_WARPS_LOG)) +
                   (forward_warp << LOG_WARP)] = forward_values[i];
        }
        __syncthreads();
#pragma unroll
        for (unsigned i = 0; i < VALUES_PER_THREAD; ++i) {
            forward_values[i] = shared[
                forward_group_offset + lane + (i << LOG_WARP) +
                (forward_warp << (LOG_WARP + LOG_VALUES_PER_THREAD))];
        }

        const unsigned second_forward_stage = 2 + LOG_VALUES_PER_THREAD;
#pragma unroll
        for (; forward_stage <= forward_end_stage; ++forward_stage) {
            const unsigned log_inner_stride =
                FORWARD_WARPS_LOG - 1 -
                (forward_stage - second_forward_stage);
#pragma unroll
            for (unsigned gid = 0; gid < HALF_VALUES_PER_THREAD; ++gid) {
                const unsigned inner_group =
                    gid & ((1u << log_inner_stride) - 1);
                const unsigned inner_pair = gid >> log_inner_stride;
                const unsigned left =
                    inner_group + (inner_pair << (log_inner_stride + 1));
                const unsigned right = left + (1u << log_inner_stride);
                const unsigned transformed_offset =
                    forward_warp * (forward_min_stride << LOG_VALUES_PER_THREAD) +
                    lane;
                const unsigned outer_pair =
                    (forward_block_start + transformed_offset) >>
                    (1 + log_n - forward_stage);
                const m31 product = mul(
                    forward_twiddles[
                        forward_layer_offset + inner_pair + outer_pair],
                    forward_values[right]);
                const m31 left_value = forward_values[left];
                forward_values[left] = add(left_value, product);
                forward_values[right] = sub(left_value, product);
            }
            forward_layer_size <<= 1;
            forward_layer_offset -= forward_layer_size;
        }

        m31 *destination = retained_outputs[coordinate + 4 * side];
        const unsigned transformed_offset =
            forward_warp * (forward_min_stride << LOG_VALUES_PER_THREAD) + lane;
#pragma unroll
        for (unsigned i = 0; i < VALUES_PER_THREAD; ++i) {
            const unsigned address =
                forward_block_start + i * forward_min_stride + transformed_offset;
            destination[address] = forward_values[i];
        }
    }
}

#endif // STWO_COMPOSITION_SPLIT_CUH
