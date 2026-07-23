// Retained LDE final interval + Blake2s leaf fusion. The transform arithmetic,
// twiddle order, circle butterfly, canonical uint64 write mapping, and
// row-major 16-word message transpose match rfft.cu's unfused path. All loads
// for one column precede the warp/block barrier and its in-place write; blocks
// own disjoint rows. Evaluations stay byte-identical while the leaf consumes
// the resident result. Progressive and compact sinks differ only in how the
// canonical message advances their leaf state. Rust enforces their exact
// shape, ordering, retention, tail, and qualification contracts.
#include "ntt_leaf_fused.cuh"
#include "m31_fast32.cuh"
#include "ntt_compact_leaf.cuh"
#include "poly_utils.cuh"
#include "rfft.cuh"

#ifndef STWO_DIRECT_COMPACT_FAST32
#define STWO_DIRECT_COMPACT_FAST32 0
#endif

static_assert(STWO_DIRECT_COMPACT_FAST32 == 0 ||
                  STWO_DIRECT_COMPACT_FAST32 == 1,
              "STWO_DIRECT_COMPACT_FAST32 must be 0 or 1");

namespace {

enum class FusedLeafSink : uint32_t {
    Streaming,
    Progressive,
    DirectCompact,
};

static_assert(offsetof(ProgressiveBlake2sState, h) == 0,
              "progressive chaining value must prefix the state");
static_assert(sizeof(Blake2sHash) == sizeof(uint32_t) * 8,
              "progressive chaining value must match Blake2sHash");

// Duplicate of rfft.cu's file-local shfl_xor_bf (the butterfly operand
// exchange for the in-register final stages), under a unique name so the two
// translation units cannot collide at device link. Kept in LOCKSTEP with
// rfft.cu; the byte-identity gate catches any divergence.
template <unsigned LOG_VALS_PER_THREAD>
DEVICE_FORCEINLINE void shfl_xor_bf_fused(m31 *vals, const unsigned log_stride,
                                          const unsigned lane_id) {
  const unsigned mask = 1 << log_stride;
  const unsigned num_pair_per_thread = 1 << (LOG_VALS_PER_THREAD - 1);
  __syncwarp();
#pragma unroll
  for (unsigned i = 0; i < num_pair_per_thread; i++) {
    m31 *ptr = lane_id & mask ? vals + 2 * i : vals + 2 * i + 1;
    *ptr = __shfl_xor_sync(0xffffffff, *ptr, mask);
  }
}

// Both consumers see the same register-resident canonical row message. The
// streaming leaf consumes it immediately; the progressive leaf keeps the
// newest full block pending, exactly matching Blake2sHasher's lazy update
// rule. At an aligned boundary, a non-empty progressive state necessarily has
// one previous full block pending, so compress that block before replacing it.
template <FusedLeafSink SINK>
DEVICE_FORCEINLINE void consume_fused_leaf_message(
    void *raw_states,
    unsigned row,
    const uint32_t message[16],
    uint32_t cols_done,
    uint32_t is_final
) {
    if constexpr (SINK == FusedLeafSink::Progressive) {
        ProgressiveBlake2sState *state =
            &reinterpret_cast<ProgressiveBlake2sState *>(raw_states)[row];
        if (cols_done != 0) {
            stwo_blake2s_compress_leaf_block_device(
                reinterpret_cast<Blake2sHash *>(state), state->pending,
                4u * cols_done, 0u);
        }
        #pragma unroll
        for (unsigned word = 0; word < 16; ++word) {
            state->pending[word] = message[word];
        }
    } else if constexpr (SINK == FusedLeafSink::Streaming) {
        const uint32_t total_bytes = 4u * (cols_done + 16u);
        const uint32_t lastblock = is_final != 0 ? 0xffffffffu : 0u;
        stwo_blake2s_compress_leaf_block_device(
            &reinterpret_cast<Blake2sHash *>(raw_states)[row], message,
            total_bytes, lastblock);
    } else {
        static_assert(SINK != FusedLeafSink::DirectCompact,
                      "compact leaf messages require four-lane ownership");
    }
}

template <FusedLeafSink SINK>
DEVICE_FORCEINLINE bool writes_completed_evaluation(
    uint32_t retained_write_mask, unsigned column
) {
    if constexpr (SINK == FusedLeafSink::Progressive) {
        return (retained_write_mask & (1u << column)) != 0;
    }
    return true;
}

template <FusedLeafSink SINK>
DEVICE_FORCEINLINE m31 fused_mul(m31 a, m31 b) {
    if constexpr (SINK == FusedLeafSink::DirectCompact) {
#if STWO_DIRECT_COMPACT_FAST32
        return stwo_m31_mul_fast32(a, b);
#endif
    }
    return mul(a, b);
}

template <FusedLeafSink SINK>
DEVICE_FORCEINLINE m31 fused_add(m31 a, m31 b) {
    if constexpr (SINK == FusedLeafSink::DirectCompact) {
#if STWO_DIRECT_COMPACT_FAST32
        return stwo_m31_add_fast32(a, b);
#endif
    }
    return add(a, b);
}

template <FusedLeafSink SINK>
DEVICE_FORCEINLINE m31 fused_sub(m31 a, m31 b) {
    if constexpr (SINK == FusedLeafSink::DirectCompact) {
#if STWO_DIRECT_COMPACT_FAST32
        return stwo_m31_sub_fast32(a, b);
#endif
    }
    return sub(a, b);
}

#include "ntt_leaf_fused_col8.cuh"

// n2b_final_warp_hash16_batch (rfft.cu) + the evaluation writeback. Rows
// [global_warp_start, global_warp_start + VALUES_PER_WARP) are owned by one
// warp for both the store and the absorb.
template <unsigned LOG_VALS_PER_THREAD, FusedLeafSink SINK>
__global__ void n2b_final_warp_hash16_write_batch(
    m31 **values,   // in: prefinal state; out: completed evaluations
    const unsigned log_n,
    unsigned min_stage,
    m31 *g_twiddles,
    uint32_t cols_done,
    uint32_t is_final,
    uint32_t retained_write_mask,
    void *states,
    uint32_t tiles,
    CompactBlake2sTailDescriptor initial_tail
) {
    extern __shared__ uint32_t messages[];
    const unsigned lane = threadIdx.x;
    const unsigned local_warp = threadIdx.y;
    const unsigned global_warp = blockDim.y * blockIdx.x + local_warp;
    const unsigned log_values_per_warp = LOG_VALS_PER_THREAD + LOG_WARP;
    const unsigned global_warp_start = global_warp << log_values_per_warp;
    const unsigned local_warp_start = local_warp << log_values_per_warp;
    const unsigned rows_per_block = blockDim.y << log_values_per_warp;
    uint32_t *compact_scratch = messages + rows_per_block * 16;

    for (uint32_t tile = 0; tile < tiles; ++tile) {
    for (unsigned column = 0; column < 16; ++column) {
        m31 *column_values = values[16 * tile + column];
        unsigned warp_start = global_warp_start + lane;
        m31 vals[1 << LOG_VALS_PER_THREAD];
        #pragma unroll
        for (unsigned i = 0; i < (1 << LOG_VALS_PER_THREAD); ++i) {
            vals[i] = column_values[warp_start + (i << LOG_WARP)];
        }

        unsigned layer_domain_size = 1;
        unsigned layer_domain_offset = ((1 << log_n) >> 1) - 2;
        for (unsigned i = 1; i < min_stage; ++i) {
            layer_domain_size <<= 1;
            layer_domain_offset -= layer_domain_size;
        }
        unsigned stage = min_stage;
        #pragma unroll
        for (; stage < min_stage + LOG_VALS_PER_THREAD; ++stage) {
            const unsigned log_inner_stride =
                LOG_VALS_PER_THREAD - 1 - (stage - min_stage);
            #pragma unroll
            for (unsigned gid = 0; gid < (1 << (LOG_VALS_PER_THREAD - 1)); ++gid) {
                const unsigned inner_group = gid & ((1 << log_inner_stride) - 1);
                const unsigned inner_pair = gid >> log_inner_stride;
                const unsigned left_index =
                    inner_group + (inner_pair << (log_inner_stride + 1));
                const unsigned right_index = left_index + (1 << log_inner_stride);
                const unsigned outer_pair = warp_start >> (1 + log_n - stage);
                const m31 product = fused_mul<SINK>(
                    g_twiddles[layer_domain_offset + inner_pair + outer_pair],
                    vals[right_index]);
                const m31 left = vals[left_index];
                vals[left_index] = fused_add<SINK>(left, product);
                vals[right_index] = fused_sub<SINK>(left, product);
            }
            layer_domain_size <<= 1;
            layer_domain_offset -= layer_domain_size;
        }
        #pragma unroll
        for (; stage <= log_n; ++stage) {
            const unsigned log_stride = log_n - stage;
            shfl_xor_bf_fused<LOG_VALS_PER_THREAD>(vals, log_stride, lane);
            #pragma unroll
            for (unsigned i = 0; i < (1 << (LOG_VALS_PER_THREAD - 1)); ++i) {
                const unsigned inner_pair =
                    (lane >> log_stride) + (i << (LOG_WARP - log_stride));
                const unsigned outer_pair = global_warp
                    << (log_values_per_warp - 1 - log_stride);
                const m31 product = stage == log_n
                    ? fused_mul<SINK>(
                          get_circle_twiddle(g_twiddles, inner_pair + outer_pair),
                          vals[2 * i + 1])
                    : fused_mul<SINK>(
                          g_twiddles[layer_domain_offset + inner_pair + outer_pair],
                          vals[2 * i + 1]);
                const m31 left = vals[2 * i];
                vals[2 * i] = fused_add<SINK>(left, product);
                vals[2 * i + 1] = fused_sub<SINK>(left, product);
            }
            layer_domain_size <<= 1;
            layer_domain_offset -= layer_domain_size;
        }

        // Evaluation writeback — the identical uint64 store
        // n2b_final_warp_batch performs, so the retained buffer holds
        // exactly the unfused lane's bytes. Safe in place: all loads of
        // this column happened before the shfl __syncwarp barriers above.
        if (writes_completed_evaluation<SINK>(retained_write_mask, column)) {
            uint64_t *src = reinterpret_cast<uint64_t *>(vals);
            uint64_t *dst = reinterpret_cast<uint64_t *>(
                column_values + global_warp_start + 2 * lane);
            #pragma unroll
            for (unsigned i = 0; i < (1 << (LOG_VALS_PER_THREAD - 1)); ++i) {
                dst[i << LOG_WARP] = src[i];
            }
        }

        #pragma unroll
        for (unsigned i = 0; i < (1 << (LOG_VALS_PER_THREAD - 1)); ++i) {
            const unsigned row = local_warp_start + 2 * lane + (i << 6);
            messages[(row + 0) * 16 + column] = vals[2 * i];
            messages[(row + 1) * 16 + column] = vals[2 * i + 1];
        }
    }
    __syncthreads();

    if constexpr (SINK == FusedLeafSink::DirectCompact) {
        const unsigned linear_thread = threadIdx.y * blockDim.x + threadIdx.x;
        const unsigned quad = linear_thread / 4;
        const unsigned quads = blockDim.x * blockDim.y / 4;
        for (unsigned local_row = quad; local_row < rows_per_block;
             local_row += quads) {
            stwo_compact_consume_final16_quad(
                reinterpret_cast<Blake2sHash *>(states),
                blockIdx.x * rows_per_block + local_row,
                messages + local_row * 16, values, tile, cols_done,
                initial_tail, compact_scratch + quad * 16);
        }
    } else {
        #pragma unroll
        for (unsigned i = 0; i < (1 << (LOG_VALS_PER_THREAD - 1)); ++i) {
            #pragma unroll
            for (unsigned side = 0; side < 2; ++side) {
                const unsigned local_row =
                    local_warp_start + 2 * lane + (i << 6) + side;
                const unsigned global_row =
                    global_warp_start + 2 * lane + (i << 6) + side;
                uint32_t message[16];
                #pragma unroll
                for (unsigned k = 0; k < 16; ++k) {
                    message[k] = messages[local_row * 16 + k];
                }
                consume_fused_leaf_message<SINK>(
                    states, global_row, message, cols_done, is_final);
            }
        }
    }
    __syncthreads();
    // Next-tile tail visibility; blocks own stable, disjoint row ranges.
    }
}

// n2b_final_block_warp_hash16_batch (rfft.cu) + the evaluation writeback.
template <unsigned LOG_WARP_PER_BLOCK, FusedLeafSink SINK>
__global__ void n2b_final_block_warp_hash16_write_batch(
    m31 **values,   // in: prefinal state; out: completed evaluations
    const unsigned log_n,
    unsigned min_stage,
    m31 *g_twiddles,
    uint32_t cols_done,
    uint32_t is_final,
    uint32_t retained_write_mask,
    void *states,
    uint32_t tiles,
    CompactBlake2sTailDescriptor initial_tail
) {
    constexpr unsigned LOG_VALS_PER_THREAD = 3;
    constexpr unsigned VALUES_PER_WARP = 1 << (LOG_WARP + LOG_VALS_PER_THREAD);
    constexpr unsigned VALUES_PER_BLOCK = 32 << (LOG_WARP_PER_BLOCK + LOG_VALS_PER_THREAD);
    extern __shared__ uint32_t shared_words[];
    m31 *smem = reinterpret_cast<m31 *>(shared_words);
    uint32_t *messages = shared_words + VALUES_PER_BLOCK;
    uint32_t *compact_scratch = messages + VALUES_PER_BLOCK * 16;

    const unsigned local_warp = threadIdx.y;
    const unsigned lane = threadIdx.x;
    const unsigned block_start = blockIdx.x
        << (LOG_WARP + LOG_VALS_PER_THREAD + LOG_WARP_PER_BLOCK);
    const unsigned global_warp = blockDim.y * blockIdx.x + local_warp;
    const unsigned global_warp_start = global_warp << (LOG_WARP + LOG_VALS_PER_THREAD);
    const unsigned local_warp_start = local_warp * VALUES_PER_WARP;

    for (uint32_t tile = 0; tile < tiles; ++tile) {
    for (unsigned column = 0; column < 16; ++column) {
        m31 *column_values = values[16 * tile + column];
        m31 vals[1 << LOG_VALS_PER_THREAD];
        unsigned offset = (local_warp << LOG_WARP) + lane;
        #pragma unroll
        for (unsigned i = 0; i < (1 << LOG_VALS_PER_THREAD); ++i) {
            vals[i] = column_values[
                block_start + (i << (LOG_WARP + LOG_WARP_PER_BLOCK)) + offset];
        }

        unsigned layer_domain_size = 1;
        unsigned layer_domain_offset = ((1 << log_n) >> 1) - 2;
        for (unsigned stage = 1; stage < min_stage; ++stage) {
            layer_domain_size <<= 1;
            layer_domain_offset -= layer_domain_size;
        }
        unsigned stage = min_stage;
        #pragma unroll
        for (; stage < min_stage + LOG_WARP_PER_BLOCK; ++stage) {
            const unsigned log_inner_stride =
                LOG_VALS_PER_THREAD - 1 - (stage - min_stage);
            #pragma unroll
            for (unsigned gid = 0; gid < (1 << (LOG_VALS_PER_THREAD - 1)); ++gid) {
                const unsigned inner_group = gid & ((1 << log_inner_stride) - 1);
                const unsigned inner_pair = gid >> log_inner_stride;
                const unsigned left_index =
                    inner_group + (inner_pair << (log_inner_stride + 1));
                const unsigned right_index = left_index + (1 << log_inner_stride);
                const unsigned outer_pair = (block_start + offset) >> (1 + log_n - stage);
                const m31 product = fused_mul<SINK>(
                    g_twiddles[layer_domain_offset + inner_pair + outer_pair],
                    vals[right_index]);
                const m31 left = vals[left_index];
                vals[left_index] = fused_add<SINK>(left, product);
                vals[right_index] = fused_sub<SINK>(left, product);
            }
            layer_domain_size <<= 1;
            layer_domain_offset -= layer_domain_size;
        }

        #pragma unroll
        for (unsigned i = 0; i < (1 << LOG_VALS_PER_THREAD); ++i) {
            smem[lane + (i << (LOG_WARP + LOG_WARP_PER_BLOCK))
                + (local_warp << LOG_WARP)] = vals[i];
        }
        __syncthreads();
        #pragma unroll
        for (unsigned i = 0; i < (1 << LOG_VALS_PER_THREAD); ++i) {
            vals[i] = smem[lane + (i << LOG_WARP)
                + (local_warp << (LOG_WARP + LOG_VALS_PER_THREAD))];
        }
        offset = (local_warp << (LOG_WARP + LOG_VALS_PER_THREAD)) + lane;

        const unsigned new_min_stage = min_stage + LOG_WARP_PER_BLOCK;
        stage = new_min_stage;
        #pragma unroll
        for (; stage < new_min_stage + LOG_VALS_PER_THREAD; ++stage) {
            const unsigned log_inner_stride =
                LOG_VALS_PER_THREAD - 1 - (stage - new_min_stage);
            #pragma unroll
            for (unsigned gid = 0; gid < (1 << (LOG_VALS_PER_THREAD - 1)); ++gid) {
                const unsigned inner_group = gid & ((1 << log_inner_stride) - 1);
                const unsigned inner_pair = gid >> log_inner_stride;
                const unsigned left_index =
                    inner_group + (inner_pair << (log_inner_stride + 1));
                const unsigned right_index = left_index + (1 << log_inner_stride);
                const unsigned outer_pair =
                    (global_warp_start + lane) >> (1 + log_n - stage);
                const m31 product = fused_mul<SINK>(
                    g_twiddles[layer_domain_offset + inner_pair + outer_pair],
                    vals[right_index]);
                const m31 left = vals[left_index];
                vals[left_index] = fused_add<SINK>(left, product);
                vals[right_index] = fused_sub<SINK>(left, product);
            }
            layer_domain_size <<= 1;
            layer_domain_offset -= layer_domain_size;
        }
        #pragma unroll
        for (; stage <= log_n; ++stage) {
            const unsigned log_stride = log_n - stage;
            shfl_xor_bf_fused<LOG_VALS_PER_THREAD>(vals, log_stride, lane);
            #pragma unroll
            for (unsigned i = 0; i < (1 << (LOG_VALS_PER_THREAD - 1)); ++i) {
                const unsigned inner_pair =
                    (lane >> log_stride) + (i << (LOG_WARP - log_stride));
                const unsigned outer_pair = global_warp
                    << (LOG_WARP + LOG_VALS_PER_THREAD - 1 - log_stride);
                const m31 product = stage == log_n
                    ? fused_mul<SINK>(
                          get_circle_twiddle(g_twiddles, inner_pair + outer_pair),
                          vals[2 * i + 1])
                    : fused_mul<SINK>(
                          g_twiddles[layer_domain_offset + inner_pair + outer_pair],
                          vals[2 * i + 1]);
                const m31 left = vals[2 * i];
                vals[2 * i] = fused_add<SINK>(left, product);
                vals[2 * i + 1] = fused_sub<SINK>(left, product);
            }
            layer_domain_size <<= 1;
            layer_domain_offset -= layer_domain_size;
        }

        // Evaluation writeback — the identical uint64 store
        // n2b_final_block_warp_batch performs. Safe in place: every warp's
        // loads of this column precede the smem __syncthreads above, and the
        // written rows are disjoint per warp/block.
        if (writes_completed_evaluation<SINK>(retained_write_mask, column)) {
            uint64_t *src = reinterpret_cast<uint64_t *>(vals);
            uint64_t *dst = reinterpret_cast<uint64_t *>(
                column_values + global_warp_start + 2 * lane);
            #pragma unroll
            for (unsigned i = 0; i < (1 << (LOG_VALS_PER_THREAD - 1)); ++i) {
                dst[i << LOG_WARP] = src[i];
            }
        }

        #pragma unroll
        for (unsigned i = 0; i < (1 << (LOG_VALS_PER_THREAD - 1)); ++i) {
            const unsigned row = local_warp_start + 2 * lane + (i << 6);
            messages[(row + 0) * 16 + column] = vals[2 * i];
            messages[(row + 1) * 16 + column] = vals[2 * i + 1];
        }
        __syncthreads();
    }

    if constexpr (SINK == FusedLeafSink::DirectCompact) {
        const unsigned linear_thread = threadIdx.y * blockDim.x + threadIdx.x;
        const unsigned quad = linear_thread / 4;
        const unsigned quads = blockDim.x * blockDim.y / 4;
        for (unsigned local_row = quad; local_row < VALUES_PER_BLOCK;
             local_row += quads) {
            stwo_compact_consume_final16_quad(
                reinterpret_cast<Blake2sHash *>(states),
                block_start + local_row, messages + local_row * 16,
                values, tile, cols_done, initial_tail,
                compact_scratch + quad * 16);
        }
    } else {
        #pragma unroll
        for (unsigned i = 0; i < (1 << (LOG_VALS_PER_THREAD - 1)); ++i) {
            #pragma unroll
            for (unsigned side = 0; side < 2; ++side) {
                const unsigned local_row =
                    local_warp_start + 2 * lane + (i << 6) + side;
                const unsigned global_row =
                    global_warp_start + 2 * lane + (i << 6) + side;
                uint32_t message[16];
                #pragma unroll
                for (unsigned k = 0; k < 16; ++k) {
                    message[k] = messages[local_row * 16 + k];
                }
                consume_fused_leaf_message<SINK>(
                    states, global_row, message, cols_done, is_final);
            }
        }
    }
    __syncthreads();
    // Next-tile tail visibility; blocks own stable, disjoint row ranges.
    }
}

// Final-stage count for `log_n` — the last LAUNCH_N2B_CONFIG entry, i.e. the
// same row rfft.cu's dispatchers read. 0 marks an unsupported log size.
unsigned leaf_fused_final_stages(unsigned log_n) {
    if (log_n >= 13 && log_n <= 19) {
        return (unsigned)LAUNCH_N2B_CONFIG_13_19[log_n - 13][1];
    }
    if (log_n >= 20 && log_n <= 27) {
        return (unsigned)LAUNCH_N2B_CONFIG_20_27[log_n - 20][2];
    }
    if (log_n >= 28 && log_n <= 30) {
        return (unsigned)LAUNCH_N2B_CONFIG_28_30[log_n - 28][3];
    }
    return 0;
}

template <unsigned LOG_VALS_PER_THREAD, FusedLeafSink SINK>
cudaError_t leaf_fused_final_warp_on(
    m31 **values,
    unsigned log_n,
    unsigned start_stage,
    m31 *twiddles,
    unsigned twiddle_words,
    unsigned eval_domain_size,
    uint32_t cols_done,
    uint32_t is_final,
    uint32_t retained_write_mask,
    void *states,
    uint32_t tiles,
    CompactBlake2sTailDescriptor initial_tail,
    cudaStream_t stream
) {
    if (log_n + 1 - (LOG_VALS_PER_THREAD + LOG_WARP) != start_stage) {
        return cudaErrorInvalidValue;
    }
    twiddles += twiddle_words - eval_domain_size;
    const unsigned num_warps = 1 << (log_n - LOG_WARP - LOG_VALS_PER_THREAD);
    dim3 block_dim{32, min(num_warps, 4u), 1};
    dim3 grid_dim{num_warps / block_dim.y, 1, 1};
    const size_t message_bytes = size_t(block_dim.y)
        * (1u << (LOG_WARP + LOG_VALS_PER_THREAD)) * 16u * sizeof(uint32_t);
    const size_t compact_bytes = SINK == FusedLeafSink::DirectCompact
        ? size_t(block_dim.x) * block_dim.y / 4u * 16u * sizeof(uint32_t)
        : 0;
    const size_t shared_bytes = message_bytes + compact_bytes;
    n2b_final_warp_hash16_write_batch<LOG_VALS_PER_THREAD, SINK>
        <<<grid_dim, block_dim, shared_bytes, stream>>>(
            values, log_n, start_stage, twiddles, cols_done, is_final,
            retained_write_mask, states, tiles, initial_tail);
    return cudaGetLastError();
}

template <unsigned LOG_VALS_PER_THREAD>
cudaError_t leaf_fused_final_col8_compact_on(
    m31 **values,
    unsigned log_n,
    unsigned start_stage,
    m31 *twiddles,
    unsigned twiddle_words,
    unsigned eval_domain_size,
    uint32_t cols_done,
    Blake2sHash *states,
    uint32_t tiles,
    CompactBlake2sTailDescriptor initial_tail,
    cudaStream_t stream
) {
    constexpr unsigned WARPS = 8;
    constexpr unsigned MESSAGE_STRIDE = 17;
    constexpr unsigned ROWS = 1u << (LOG_WARP + LOG_VALS_PER_THREAD);
    constexpr unsigned QUADS = 32u * WARPS / 4u;
    if (log_n + 1 - (LOG_VALS_PER_THREAD + LOG_WARP) != start_stage) {
        return cudaErrorInvalidValue;
    }
    twiddles += twiddle_words - eval_domain_size;
    dim3 block_dim{32, WARPS, 1};
    dim3 grid_dim{
        1u << (log_n - LOG_WARP - LOG_VALS_PER_THREAD), 1, 1};
    constexpr size_t shared_bytes =
        size_t(ROWS + QUADS) * MESSAGE_STRIDE * sizeof(uint32_t);
    n2b_final_warp_col8_compact16_write_batch<LOG_VALS_PER_THREAD>
        <<<grid_dim, block_dim, shared_bytes, stream>>>(
            values, log_n, start_stage, twiddles, cols_done, states, tiles,
            initial_tail);
    return cudaGetLastError();
}

template <unsigned LOG_WARP_PER_BLOCK, FusedLeafSink SINK>
cudaError_t leaf_fused_final_block_on(
    m31 **values,
    unsigned log_n,
    unsigned start_stage,
    m31 *twiddles,
    unsigned twiddle_words,
    unsigned eval_domain_size,
    uint32_t cols_done,
    uint32_t is_final,
    uint32_t retained_write_mask,
    void *states,
    uint32_t tiles,
    CompactBlake2sTailDescriptor initial_tail,
    cudaStream_t stream
) {
    constexpr unsigned LOG_VALS_PER_THREAD = 3;
    if (log_n + 1 - start_stage !=
        LOG_VALS_PER_THREAD + LOG_WARP + LOG_WARP_PER_BLOCK) {
        return cudaErrorInvalidValue;
    }
    twiddles += twiddle_words - eval_domain_size;
    dim3 block_dim{32, 1u << LOG_WARP_PER_BLOCK, 1};
    dim3 grid_dim{1u << (log_n - LOG_WARP - LOG_VALS_PER_THREAD
        - LOG_WARP_PER_BLOCK), 1, 1};
    constexpr size_t values_per_block =
        32u << (LOG_WARP_PER_BLOCK + LOG_VALS_PER_THREAD);
    constexpr size_t block_threads = 32u << LOG_WARP_PER_BLOCK;
    constexpr size_t compact_words = SINK == FusedLeafSink::DirectCompact
        ? block_threads / 4u * 16u : 0;
    constexpr size_t shared_bytes =
        (values_per_block * 17u + compact_words) * sizeof(uint32_t);
    n2b_final_block_warp_hash16_write_batch<LOG_WARP_PER_BLOCK, SINK>
        <<<grid_dim, block_dim, shared_bytes, stream>>>(
            values, log_n, start_stage, twiddles, cols_done, is_final,
            retained_write_mask, states, tiles, initial_tail);
    return cudaGetLastError();
}

template <FusedLeafSink SINK>
cudaError_t configure_leaf_fused(unsigned log_n) {
    constexpr unsigned compact_kib =
        SINK == FusedLeafSink::DirectCompact ? 2 : 0;
    switch (leaf_fused_final_stages(log_n)) {
        case 7:
            return cudaFuncSetAttribute(
                n2b_final_warp_hash16_write_batch<2, SINK>,
                cudaFuncAttributeMaxDynamicSharedMemorySize,
                (32 + compact_kib) * 1024);
        case 8:
            return cudaFuncSetAttribute(
                n2b_final_warp_hash16_write_batch<3, SINK>,
                cudaFuncAttributeMaxDynamicSharedMemorySize,
                (64 + compact_kib) * 1024);
        case 10:
            return cudaFuncSetAttribute(
                n2b_final_block_warp_hash16_write_batch<2, SINK>,
                cudaFuncAttributeMaxDynamicSharedMemorySize,
                (68 + compact_kib) * 1024);
        case 11:
            return cudaFuncSetAttribute(
                n2b_final_block_warp_hash16_write_batch<3, SINK>,
                cudaFuncAttributeMaxDynamicSharedMemorySize,
                (136 + 2 * compact_kib) * 1024);
        default:
            return cudaErrorInvalidValue;
    }
}

template <FusedLeafSink SINK>
int launch_leaf_fused_final(
    uint32_t **device_values,
    unsigned log_n,
    uint32_t *twiddles,
    unsigned twiddle_words,
    unsigned eval_domain_size,
    uint32_t cols_done,
    uint32_t is_final,
    uint32_t retained_write_mask,
    void *states,
    uint32_t tiles,
    CompactBlake2sTailDescriptor initial_tail,
    void *stream
) {
    const unsigned final_stages = leaf_fused_final_stages(log_n);
    const unsigned final_start = log_n + 1 - final_stages;
    m31 **values = reinterpret_cast<m31 **>(device_values);
    cudaStream_t cuda_stream = reinterpret_cast<cudaStream_t>(stream);
    switch (final_stages) {
        case 7:
            return leaf_fused_final_warp_on<2, SINK>(
                values, log_n, final_start, twiddles, twiddle_words,
                eval_domain_size, cols_done, is_final, retained_write_mask,
                states, tiles, initial_tail, cuda_stream);
        case 8:
            return leaf_fused_final_warp_on<3, SINK>(
                values, log_n, final_start, twiddles, twiddle_words,
                eval_domain_size, cols_done, is_final, retained_write_mask,
                states, tiles, initial_tail, cuda_stream);
        case 10:
            return leaf_fused_final_block_on<2, SINK>(
                values, log_n, final_start, twiddles, twiddle_words,
                eval_domain_size, cols_done, is_final, retained_write_mask,
                states, tiles, initial_tail, cuda_stream);
        case 11:
            return leaf_fused_final_block_on<3, SINK>(
                values, log_n, final_start, twiddles, twiddle_words,
                eval_domain_size, cols_done, is_final, retained_write_mask,
                states, tiles, initial_tail, cuda_stream);
        default:
            return cudaErrorInvalidConfiguration;
    }
}

int launch_leaf_fused_final_col8_compact(
    uint32_t **device_values,
    unsigned log_n,
    uint32_t *twiddles,
    unsigned twiddle_words,
    unsigned eval_domain_size,
    uint32_t cols_done,
    Blake2sHash *states,
    uint32_t tiles,
    CompactBlake2sTailDescriptor initial_tail,
    void *stream
) {
    const unsigned final_stages = leaf_fused_final_stages(log_n);
    const unsigned final_start = log_n + 1 - final_stages;
    m31 **values = reinterpret_cast<m31 **>(device_values);
    cudaStream_t cuda_stream = reinterpret_cast<cudaStream_t>(stream);
    switch (final_stages) {
        case 7:
            return leaf_fused_final_col8_compact_on<2>(
                values, log_n, final_start, twiddles, twiddle_words,
                eval_domain_size, cols_done, states, tiles, initial_tail,
                cuda_stream);
        case 8:
            return leaf_fused_final_col8_compact_on<3>(
                values, log_n, final_start, twiddles, twiddle_words,
                eval_domain_size, cols_done, states, tiles, initial_tail,
                cuda_stream);
        default:
            return cudaErrorNotSupported;
    }
}

template <unsigned LOG_VALS_PER_THREAD>
cudaError_t configure_leaf_fused_final_col8_compact() {
    cudaFuncAttributes attributes{};
    cudaError_t status = cudaFuncGetAttributes(
        &attributes,
        n2b_final_warp_col8_compact16_write_batch<LOG_VALS_PER_THREAD>);
    if (status != cudaSuccess) {
        return status;
    }
    // `localSizeBytes` includes compiler-managed ABI state and does not match
    // ptxas/cubin spill accounting. The artifact gate separately requires
    // STACK=LOCAL=0; runtime admission can soundly enforce the architectural
    // register ceiling exposed by cudaFuncGetAttributes.
    return attributes.numRegs <= 64
        ? cudaSuccess : cudaErrorInvalidConfiguration;
}

template <FusedLeafSink SINK>
int launch_leaf_fused(
    const uint32_t *const *coefficient_values,
    const uint32_t *coefficient_sizes,
    uint32_t **device_values,
    unsigned log_n,
    uint32_t *twiddles,
    unsigned twiddle_words,
    unsigned eval_domain_size,
    uint32_t cols_done,
    uint32_t is_final,
    uint32_t retained_write_mask,
    void *states,
    void *stream
) {
    int err = stwo_lde_n2b_prefinal16_on(
        coefficient_values, coefficient_sizes, device_values, log_n, twiddles,
        twiddle_words, eval_domain_size, stream);
    if (err != (int)cudaSuccess) {
        return err;
    }
    const CompactBlake2sTailDescriptor empty_tail{};
    return launch_leaf_fused_final<SINK>(
        device_values, log_n, twiddles, twiddle_words, eval_domain_size,
        cols_done, is_final, retained_write_mask, states, 1, empty_tail,
        stream);
}

} // namespace

// Same dynamic shared-memory ceilings as rfft.cu's
// configure_n2b_hash16_kernel, applied to the write+hash twins.
extern "C" int stwo_ntt_leaf_fused_configure(unsigned log_n) {
    return configure_leaf_fused<FusedLeafSink::Streaming>(log_n);
}

extern "C" int stwo_ntt_leaf_fused_on(
    const uint32_t *const *coefficient_values,
    const uint32_t *coefficient_sizes,
    uint32_t **device_values,
    unsigned log_n,
    uint32_t *twiddles,
    unsigned twiddle_words,
    unsigned eval_domain_size,
    uint32_t cols_done,
    uint32_t is_final,
    Blake2sHash *states,
    void *stream
) {
    // Same admission contract as stwo_lde_n2b_hash16_on.
    if (coefficient_values == nullptr || coefficient_sizes == nullptr ||
        device_values == nullptr || log_n < 13 || log_n > 30 ||
        twiddles == nullptr || eval_domain_size != (1u << (log_n - 1)) ||
        eval_domain_size > twiddle_words || (cols_done % 16) != 0 ||
        is_final > 1 || states == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }

    return launch_leaf_fused<FusedLeafSink::Streaming>(
        coefficient_values, coefficient_sizes, device_values, log_n, twiddles,
        twiddle_words, eval_domain_size, cols_done, is_final, 0xffffu, states,
        stream);
}

extern "C" int stwo_ntt_progressive_leaf_fused_configure(unsigned log_n) {
    return configure_leaf_fused<FusedLeafSink::Progressive>(log_n);
}

extern "C" int stwo_ntt_progressive_leaf_fused_on(
    const uint32_t *const *coefficient_values,
    const uint32_t *coefficient_sizes,
    uint32_t **device_values,
    unsigned log_n,
    uint32_t *twiddles,
    unsigned twiddle_words,
    unsigned eval_domain_size,
    uint32_t cols_done,
    uint32_t retained_write_mask,
    ProgressiveBlake2sState *states,
    void *stream
) {
    if (coefficient_values == nullptr || coefficient_sizes == nullptr ||
        device_values == nullptr || log_n < 13 || log_n > 30 ||
        twiddles == nullptr || eval_domain_size != (1u << (log_n - 1)) ||
        eval_domain_size > twiddle_words || (cols_done % 16) != 0 ||
        (retained_write_mask & ~0xffffu) != 0 || states == nullptr ||
        stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    return launch_leaf_fused<FusedLeafSink::Progressive>(
        coefficient_values, coefficient_sizes, device_values, log_n, twiddles,
        twiddle_words, eval_domain_size, cols_done, 0u, retained_write_mask,
        states, stream);
}

extern "C" int stwo_ntt_direct_compact_final16_configure(unsigned log_n) {
    return configure_leaf_fused<FusedLeafSink::DirectCompact>(log_n);
}

extern "C" int stwo_ntt_direct_compact_final16_on(
    uint32_t **device_values,
    unsigned log_n,
    uint32_t tiles,
    uint32_t *twiddles,
    unsigned twiddle_words,
    unsigned eval_domain_size,
    uint32_t cols_done,
    const CompactBlake2sTailDescriptor *initial_tail,
    Blake2sHash *states,
    void *stream
) {
    constexpr uint32_t kMaxFixed16Tiles = 4095;
    if (device_values == nullptr || log_n < 13 || log_n > 30 || tiles == 0 ||
        tiles > kMaxFixed16Tiles || twiddles == nullptr ||
        eval_domain_size != (1u << (log_n - 1)) ||
        eval_domain_size > twiddle_words ||
        cols_done > 65535u - 16u * tiles || initial_tail == nullptr ||
        states == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    const CompactBlake2sTailDescriptor tail = *initial_tail;
    if (!stwo_compact_tail_descriptor_valid(
            1u << log_n, cols_done, tail)) {
        return cudaErrorInvalidValue;
    }
    return launch_leaf_fused_final<FusedLeafSink::DirectCompact>(
        device_values, log_n, twiddles, twiddle_words, eval_domain_size,
        cols_done, 0u, 0xffffu, states, tiles, tail, stream);
}

extern "C" int stwo_ntt_direct_compact_final16_col8_configure(
    unsigned log_n
) {
    switch (leaf_fused_final_stages(log_n)) {
        case 7:
            return configure_leaf_fused_final_col8_compact<2>();
        case 8:
            return configure_leaf_fused_final_col8_compact<3>();
        default:
            return cudaErrorNotSupported;
    }
}

extern "C" int stwo_ntt_direct_compact_final16_col8_on(
    uint32_t **device_values,
    unsigned log_n,
    uint32_t tiles,
    uint32_t *twiddles,
    unsigned twiddle_words,
    unsigned eval_domain_size,
    uint32_t cols_done,
    const CompactBlake2sTailDescriptor *initial_tail,
    Blake2sHash *states,
    void *stream
) {
    constexpr uint32_t kMaxFixed16Tiles = 4095;
    if (device_values == nullptr || log_n < 13 || log_n > 30 || tiles == 0 ||
        tiles > kMaxFixed16Tiles || twiddles == nullptr ||
        eval_domain_size != (1u << (log_n - 1)) ||
        eval_domain_size > twiddle_words ||
        cols_done > 65535u - 16u * tiles || initial_tail == nullptr ||
        states == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    const CompactBlake2sTailDescriptor tail = *initial_tail;
    if (!stwo_compact_tail_descriptor_valid(1u << log_n, cols_done, tail)) {
        return cudaErrorInvalidValue;
    }
    return launch_leaf_fused_final_col8_compact(
        device_values, log_n, twiddles, twiddle_words, eval_domain_size,
        cols_done, states, tiles, tail, stream);
}
